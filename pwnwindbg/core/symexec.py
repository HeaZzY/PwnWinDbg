"""Bridge to the isolated angr venv for symbolic-execution payload solving.

angr pins an old capstone that conflicts with the debugger's, so it lives in a
dedicated venv (see the README / `angr setup`). This module locates that venv's
python and runs ``core/angr_solver.py`` in it as a subprocess, returning the
parsed JSON result. Nothing here imports angr into the debugger process.
"""

import json
import os
import subprocess


# Candidate locations for the angr venv python (env override wins).
def _candidate_pythons():
    cands = []
    env = os.environ.get("PWNWINDBG_ANGR_PYTHON")
    if env:
        cands.append(env)
    home = os.path.expanduser("~")
    cands.append(os.path.join(home, "pwnwindbg-angr", "venv", "Scripts", "python.exe"))
    cands.append(os.path.join(home, "pwnwindbg-angr", "venv", "bin", "python"))
    la = os.environ.get("LOCALAPPDATA", "")
    if la:
        cands.append(os.path.join(la, "pwnWinDbg", "angr-venv", "Scripts", "python.exe"))
    return cands


_cached_python = None


def find_angr_python(verify=False):
    """Return the path to the angr venv python, or None.

    With ``verify=True`` also confirms ``import angr`` works in it (slower).
    """
    global _cached_python
    if _cached_python:
        return _cached_python
    for p in _candidate_pythons():
        if p and os.path.exists(p):
            if verify:
                try:
                    r = subprocess.run([p, "-c", "import angr"],
                                       capture_output=True, timeout=60)
                    if r.returncode != 0:
                        continue
                except Exception:
                    continue
            _cached_python = p
            return p
    return None


def _solver_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "angr_solver.py")


def solve_payload(exe_path, target, avoid=None, start=None, base=None,
                  stdin_len=200, symargv=0, timeout=120):
    """Run the angr solver in the venv. Returns the result dict.

    Result keys: ``found`` (bool), ``stdin_hex``/``stdin_len``/``stdin_repr``
    when found (plus ``argv1_hex``/``argv1_repr`` when ``symargv`` > 0), or
    ``reason`` when not, or ``error`` on failure (incl. a missing angr venv).
    ``symargv`` > 0 makes ``argv[1]`` a symbolic key of that many bytes.
    """
    vpy = find_angr_python()
    if not vpy:
        return {"error": (
            "angr venv not found. Create it with:\n"
            "  python -m venv %USERPROFILE%\\pwnwindbg-angr\\venv\n"
            "  %USERPROFILE%\\pwnwindbg-angr\\venv\\Scripts\\python -m pip install angr\n"
            "or set PWNWINDBG_ANGR_PYTHON to a python that has angr."
        )}

    argv = [vpy, _solver_path(), str(exe_path), hex(int(target))]
    if avoid:
        argv += ["--avoid", ",".join(hex(int(a)) for a in avoid)]
    if start is not None:
        argv += ["--start", hex(int(start))]
    if base is not None:
        argv += ["--base", hex(int(base))]
    if symargv:
        argv += ["--symargv", str(int(symargv))]
    argv += ["--stdin-len", str(int(stdin_len)), "--timeout", str(int(timeout))]

    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            timeout=timeout + 30,
        )
    except subprocess.TimeoutExpired:
        return {"error": "angr solver hard-timeout"}
    except Exception as e:
        return {"error": "failed to launch angr solver: %s" % e}

    out = (proc.stdout or "").strip()
    # The solver prints exactly one JSON line last; be tolerant of banner noise.
    for line in reversed(out.splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                return json.loads(line)
            except Exception:
                break
    return {"error": "no JSON from angr solver",
            "stderr": (proc.stderr or "")[:500],
            "stdout": out[:500]}
