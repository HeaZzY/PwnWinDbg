"""`angr` command — symbolic-execution payload solving.

Finds the stdin input that drives execution to a target address (optionally
avoiding others), via the isolated angr venv. Great for "what input reaches this
branch / this win function". Usage:

    angr <target> [from <addr>] [avoid <a1>,<a2>] [send] [timeout <sec>]
    angr status          # is the angr venv available?
    angr setup           # print venv setup instructions
"""

import os

from ..display.formatters import console, error, info, success, warn
from ..core import symexec
from ..utils.addr_expr import eval_expr


_SETUP = (
    "angr runs in an isolated venv (it pins an old capstone). Create it once:\n"
    "  python -m venv %USERPROFILE%\\pwnwindbg-angr\\venv\n"
    "  %USERPROFILE%\\pwnwindbg-angr\\venv\\Scripts\\python -m pip install angr\n"
    "(or set PWNWINDBG_ANGR_PYTHON to a python that already has angr)."
)


def _usage():
    info("angr — symbolic payload solver")
    console.print(
        "  angr <target> [from <addr>] [avoid <a1>,<a2>] [key <N>] [send] [timeout <sec>]\n"
        "  angr status | setup\n"
        "  Finds the stdin bytes that reach <target>. `key <N>` instead solves\n"
        "  for an N-byte argv[1] (serial/key crackmes). `send` pipes the stdin\n"
        "  payload to the running debuggee (needs `run -i`)."
    )


def _exe_base(debugger):
    try:
        for mod in debugger.symbols.modules:
            if mod.path and os.path.normcase(mod.path) == \
                    os.path.normcase(debugger.exe_path or ""):
                return mod.base_address
    except Exception:
        pass
    return getattr(debugger, "image_base", None)


def cmd_angr(debugger, args):
    args = (args or "").strip()
    if not args or args.lower() in ("help", "-h", "?"):
        _usage()
        return None

    toks = args.split()
    sub = toks[0].lower()

    if sub == "setup":
        info("angr venv setup")
        console.print(_SETUP)
        return None
    if sub == "status":
        vpy = symexec.find_angr_python(verify=True)
        if vpy:
            success(f"angr venv: {vpy}")
        else:
            warn("angr venv NOT found — run `angr setup`")
        return None

    if not debugger.exe_path or not os.path.exists(debugger.exe_path):
        error("angr: no target loaded (run/attach a program first)")
        return None

    # Parse: <target> [from <addr>] [avoid <csv>] [send] [timeout <sec>]
    target = eval_expr(debugger, toks[0])
    if target is None:
        error(f"angr: cannot resolve target {toks[0]!r}")
        return None
    start = None
    avoid = []
    send = False
    timeout = 120
    symargv = 0
    i = 1
    while i < len(toks):
        t = toks[i].lower()
        if t == "from" and i + 1 < len(toks):
            start = eval_expr(debugger, toks[i + 1]); i += 2; continue
        if t == "avoid" and i + 1 < len(toks):
            for a in toks[i + 1].split(","):
                v = eval_expr(debugger, a.strip())
                if v is not None:
                    avoid.append(v)
            i += 2; continue
        if t == "key" and i + 1 < len(toks):
            try:
                symargv = int(toks[i + 1], 0)
            except ValueError:
                pass
            i += 2; continue
        if t == "send":
            send = True; i += 1; continue
        if t == "timeout" and i + 1 < len(toks):
            try:
                timeout = int(toks[i + 1], 0)
            except ValueError:
                pass
            i += 2; continue
        i += 1

    base = _exe_base(debugger)
    what = f"a {symargv}-byte argv[1] key" if symargv else "stdin"
    info(f"angr: solving {what} to reach {target:#x} "
         f"(timeout {timeout}s){' from ' + hex(start) if start else ''}… "
         "this can take a while")

    res = symexec.solve_payload(
        debugger.exe_path, target, avoid=avoid, start=start,
        base=base, symargv=symargv, timeout=timeout,
    )

    if res.get("error"):
        error("angr: " + str(res["error"]))
        return None
    if not res.get("found"):
        warn("angr: no input found — " + str(res.get("reason", "unknown")))
        return None

    if symargv and res.get("argv1_hex"):
        argb = bytes.fromhex(res["argv1_hex"])
        success(f"angr: found a {len(argb)}-byte argv[1] key reaching {target:#x}")
        console.print(f"  key repr : {res.get('argv1_repr', repr(argb))}")
        console.print(f"  key hex  : {argb.hex()}")
        return None

    hexs = res.get("stdin_hex", "")
    n = res.get("stdin_len", len(hexs) // 2)
    payload = bytes.fromhex(hexs) if hexs else b""
    success(f"angr: found a {n}-byte stdin payload reaching {target:#x}")
    console.print(f"  repr : {res.get('stdin_repr', repr(payload))}")
    console.print(f"  hex  : {payload.hex()}")

    if send:
        tube = getattr(debugger, "tube", None)
        if tube is None:
            warn("angr: no tube — spawn with `run -i` to use `send`")
        else:
            try:
                tube.write(payload)
                success(f"angr: sent {len(payload)} bytes to the debuggee stdin")
            except Exception as e:
                error(f"angr: send failed: {e}")

    return None
