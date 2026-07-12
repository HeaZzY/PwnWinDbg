#!/usr/bin/env python3
"""Standalone angr solver — runs INSIDE the dedicated angr venv.

This module has NO pwnwindbg imports (the venv does not have the package). The
debugger (see ``core/symexec.py``) invokes it as::

    <angr-venv-python> -m ... OR path\\to\\angr_solver.py <exe> <find> [opts]

It symbolically explores the target binary to find a path from the start to the
``find`` address (optionally ``--avoid`` some addresses), then dumps the stdin
bytes (and argv) that drive execution there. Output is a single JSON line on
stdout so the caller can parse it. Everything is wrapped so it always prints
valid JSON, even on error.
"""
import argparse
import json
import sys
import time


def _hexint(x):
    return int(x, 0)


def solve(exe, find, avoid=None, start=None, stdin_len=200, base=None,
          argv=None, timeout=120):
    """Return a result dict: {found, stdin_hex, stdin_len, ...} or {error}."""
    avoid = avoid or []
    try:
        import logging
        for n in ("angr", "cle", "pyvex", "claripy", "angr.engines"):
            logging.getLogger(n).setLevel(logging.CRITICAL)
        import angr
        import claripy
    except Exception as e:  # angr not importable
        return {"error": "angr import failed: %s: %s" % (type(e).__name__, e)}

    try:
        load_opts = {}
        if base is not None:
            load_opts["main_opts"] = {"base_addr": base}
        proj = angr.Project(exe, auto_load_libs=False, **load_opts)

        # A bounded, symbolic stdin so the solver can choose the input bytes.
        stdin = angr.SimFileStream(name="stdin", has_end=False)

        state_args = None
        if argv:
            state_args = [exe] + list(argv)

        common_opts = {
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        }

        if start is not None:
            # call_state sets up a proper frame + return address (blank_state
            # leaves esp/ebp garbage, which deadends real functions immediately).
            state = proj.factory.call_state(
                start, stdin=stdin, add_options=common_opts
            )
        else:
            state = proj.factory.full_init_state(
                args=state_args, stdin=stdin, add_options=common_opts
            )

        simgr = proj.factory.simulation_manager(state, save_unconstrained=True)

        deadline = time.time() + timeout
        counter = {"n": 0}

        def _stepper(sm):
            counter["n"] += 1
            if time.time() > deadline:
                sm.stashes["active"] = []  # stop exploring on timeout
            # Constrain a smashed/symbolic return (ret2win) to the target so
            # overflow-style paths are discovered too.
            for st in list(sm.stashes.get("unconstrained", [])):
                try:
                    ip = st.regs.pc
                    if st.solver.satisfiable(extra_constraints=[ip == find]):
                        st.add_constraints(ip == find)
                        sm.stashes.setdefault("found", []).append(st)
                    sm.stashes["unconstrained"].remove(st)
                except Exception:
                    pass
            return sm

        simgr.explore(find=find, avoid=avoid, step_func=_stepper)
        steps = counter["n"]

        found = simgr.stashes.get("found")
        if found:
            s = found[0]
            try:
                stdin_bytes = s.posix.dumps(0)
            except Exception:
                stdin_bytes = b""
            res = {
                "found": True,
                "stdin_hex": stdin_bytes.hex(),
                "stdin_len": len(stdin_bytes),
                "steps": steps,
            }
            # printable preview
            try:
                res["stdin_repr"] = repr(stdin_bytes)
            except Exception:
                pass
            return res
        info = {"found": False, "reason": "no path (explored %d steps)" % steps}
        try:
            info["stashes"] = {k: len(v) for k, v in simgr.stashes.items() if v}
            errs = simgr.stashes.get("errored") or []
            if errs:
                info["first_error"] = str(errs[0].error)[:220]
        except Exception:
            pass
        return info
    except Exception as e:
        return {"error": "%s: %s" % (type(e).__name__, e)}


def main(argv=None):
    ap = argparse.ArgumentParser(description="angr payload solver")
    ap.add_argument("exe")
    ap.add_argument("find", type=_hexint, help="target address to reach")
    ap.add_argument("--avoid", default="", help="comma-separated addrs to avoid")
    ap.add_argument("--start", type=_hexint, default=None,
                    help="start address (blank state) instead of full init")
    ap.add_argument("--stdin-len", type=int, default=200)
    ap.add_argument("--base", type=_hexint, default=None,
                    help="force image base (match the live load base)")
    ap.add_argument("--argv", default="", help="comma-separated argv (after exe)")
    ap.add_argument("--timeout", type=int, default=120)
    args = ap.parse_args(argv)

    avoid = [int(a, 0) for a in args.avoid.split(",") if a.strip()]
    argv_extra = [a for a in args.argv.split(",") if a] or None
    res = solve(
        args.exe, args.find, avoid=avoid, start=args.start,
        stdin_len=args.stdin_len, base=args.base, argv=argv_extra,
        timeout=args.timeout,
    )
    sys.stdout.write(json.dumps(res))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
