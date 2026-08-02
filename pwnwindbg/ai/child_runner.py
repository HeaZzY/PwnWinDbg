"""Code-exec child entrypoint.

Run as::

    <python> -m pwnwindbg.ai.child_runner <script_path>

Connects back to the parent debugger's RPC server (host/port/token come from
``PWNWINDBG_RPC_HOST`` / ``PWNWINDBG_RPC_PORT`` / ``PWNWINDBG_RPC_TOKEN``),
builds the runtime namespace (``agent_runtime.build_namespace``), publishes it
as a synthetic ``pwnwindbg_agent`` module, then executes the AI-authored
script with that namespace as its globals.

Hermes rule: ONLY the script's own ``print()`` / traceback output (real
stdout) becomes the observation returned to the model. ``dbg()`` and tube
traffic print live on the PARENT via RPC, not here. Stdout is unbuffered so the
parent can stream it live over its subprocess PIPE. An uncaught script
exception prints a traceback to stdout and exits non-zero.
"""

import os
import sys
import types
import traceback


def _make_unbuffered():
    """Force line-buffered / flushing stdout+stderr for live streaming."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(line_buffering=True, write_through=True)
        except Exception:
            pass


def main(argv=None):
    argv = list(sys.argv if argv is None else argv)
    if len(argv) < 2:
        print("usage: python -m pwnwindbg.ai.child_runner <script_path>")
        return 2

    _make_unbuffered()

    script_path = argv[1]
    try:
        with open(script_path, "r", encoding="utf-8", errors="replace") as fh:
            source = fh.read()
    except OSError as exc:
        print(f"[child_runner] cannot read script: {exc}")
        return 2

    # Connect to the parent RPC server.
    from .rpc import RpcClient
    try:
        rpc_client = RpcClient.from_env()
    except Exception as exc:
        print(f"[child_runner] RPC connect failed: {exc}")
        return 2

    # Build the runtime namespace and expose it as `pwnwindbg_agent`.
    from . import agent_runtime
    ns = agent_runtime.build_namespace(rpc_client)

    agent_mod = types.ModuleType("pwnwindbg_agent")
    agent_mod.__dict__.update(ns)
    # `__all__` so `from pwnwindbg_agent import *` picks up our public names.
    agent_mod.__all__ = [k for k in ns if not k.startswith("_")]
    sys.modules["pwnwindbg_agent"] = agent_mod

    # Script globals: our namespace plus a proper __name__/__file__ so the
    # script can use `if __name__ == "__main__"` and tracebacks show a path.
    script_globals = dict(ns)
    script_globals["__name__"] = "__main__"
    script_globals["__file__"] = script_path
    script_globals["__builtins__"] = __builtins__

    exit_code = 0
    try:
        code = compile(source, script_path, "exec")
        exec(code, script_globals)
    except SystemExit as exc:
        exit_code = exc.code if isinstance(exc.code, int) else (0 if not exc.code else 1)
    except BaseException:
        # Contract: uncaught script exceptions go to STDOUT (that is the
        # observation the parent captures and hands back to the model).
        traceback.print_exc(file=sys.stdout)
        exit_code = 1
    finally:
        try:
            sys.stdout.flush()
        except Exception:
            pass
        try:
            rpc_client.close()
        except Exception:
            pass

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
