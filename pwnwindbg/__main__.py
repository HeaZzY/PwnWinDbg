"""pwnWinDbg - Main entry point and REPL."""

import sys
import os
import signal
import threading
import argparse

from rich.console import Console

from .core.debugger import Debugger, DebuggerState
from .commands.dispatcher import dispatch
from .commands.display_cmds import display_context
from .display.formatters import (
    console, info, error, success, warn, banner, separator,
)


LOGO = r"""
[bold bright_red]                  __        ___       ____  _
 _ ____      ___ _\ \      / (_)_ __ |  _ \| |__   __ _
| '_ \ \ /\ / / '_ \ \ /\ / /| | '_ \| | | | '_ \ / _` |
| |_) \ V  V /| | | \ V  V / | | | | | |_| | |_) | (_| |
| .__/ \_/\_/ |_| |_|\_/\_/  |_|_| |_|____/|_.__/ \__, |
|_|                                                |___/[/]
[bright_black]  Windows userland debugger — pwndbg style[/]
[bright_black]  Type 'help' for commands — Ctrl+C to interrupt[/]
"""


def handle_stop(debugger, stop_info):
    """Handle a stop event: print reason and show context."""
    if stop_info is None:
        return

    reason = stop_info.get("reason", "unknown")

    if reason == "initial_breakpoint":
        addr = stop_info.get("address", 0)
        info(f"Initial breakpoint hit at {addr:#x}")
        debugger.symbols.refresh_modules(debugger.process_id)
        display_context(debugger)

    elif reason == "interrupt":
        addr = stop_info.get("address", 0)
        warn(f"Interrupted at {addr:#x}")
        debugger.symbols.refresh_modules(debugger.process_id)
        display_context(debugger)

    elif reason == "breakpoint":
        bp = stop_info.get("bp")
        addr = stop_info.get("address", 0)
        if bp:
            info(f"Breakpoint #{bp.id} hit at {addr:#x} (hits={bp.hit_count})")
        else:
            info(f"Breakpoint at {addr:#x}")
        # Show return address when stopped
        _show_ret_info(debugger)
        display_context(debugger)

    elif reason == "single_step":
        display_context(debugger)

    elif reason == "access_violation":
        addr = stop_info.get("address", 0)
        access = stop_info.get("access_type", "unknown")
        fault = stop_info.get("fault_address", 0)
        first = stop_info.get("first_chance", True)
        chance_str = "first" if first else "second"
        error(f"Access violation ({chance_str} chance) at {addr:#x}")
        error(f"  {access} access to {fault:#x}")
        display_context(debugger)

    elif reason == "exception":
        code = stop_info.get("code", 0)
        addr = stop_info.get("address", 0)
        error(f"Exception {code:#x} at {addr:#x}")
        display_context(debugger)

    elif reason == "exit":
        exit_code = stop_info.get("exit_code", 0)
        warn(f"Process exited with code {exit_code}")

    elif reason == "quit":
        pass

    elif reason == "kd_handled":
        pass  # KD commands display context themselves

    elif reason == "timeout":
        warn("Timeout waiting for debug event")


def _show_ret_info(debugger):
    """Show return address info when on a ret instruction."""
    ret_addr = debugger.get_return_address()
    if ret_addr and ret_addr > 0x1000:
        sym = debugger.symbols.resolve_address(ret_addr) or ""
        sym_str = f"  ({sym})" if sym else ""
        info(f"Return address: {ret_addr:#x}{sym_str}")


def get_prompt(debugger):
    """Generate the REPL prompt."""
    if debugger.state == DebuggerState.STOPPED:
        return "[bold bright_red]pwnWinDbg>[/] "
    elif debugger.state == DebuggerState.RUNNING:
        return "[bold bright_yellow]pwnWinDbg>[/] "
    elif debugger.state == DebuggerState.TERMINATED:
        return "[bold bright_black]pwnWinDbg>[/] "
    return "[bold bright_blue]pwnWinDbg>[/] "


# Global reference so the signal handler can reach it
_active_debugger = None


def _sigint_handler(signum, frame):
    """Handle Ctrl+C: interrupt the debuggee if running, or KD target."""
    if _active_debugger and _active_debugger.state == DebuggerState.RUNNING:
        _active_debugger.interrupt()
        return
    # Check for active KD session
    try:
        from .commands.kd_cmds import _kd_session
        if _kd_session and _kd_session.connected and not _kd_session.stopped:
            _kd_session.do_break()
            return
    except Exception:
        pass
    # Not running — raise normally so the REPL input is cancelled
    raise KeyboardInterrupt


def main():
    """Main entry point."""
    global _active_debugger

    parser = argparse.ArgumentParser(
        description="pwnWinDbg - Windows userland debugger",
    )
    parser.add_argument("executable", nargs="?", help="PE executable to debug")
    parser.add_argument("-a", "--attach", type=int, metavar="PID", help="Attach to a running process")
    parser.add_argument("--args", default="", help="Arguments to pass to the executable")
    parser.add_argument("--stdin", default="", metavar="FILE", help="Redirect file to process stdin")
    args = parser.parse_args()

    console.print(LOGO)

    debugger = Debugger()
    _active_debugger = debugger

    # Install Ctrl+C handler
    signal.signal(signal.SIGINT, _sigint_handler)

    # Auto-launch if executable provided
    if args.attach:
        from .commands.execution import cmd_attach
        stop_info = cmd_attach(debugger, str(args.attach))
        handle_stop(debugger, stop_info)
    elif args.executable:
        from .commands.execution import cmd_run
        run_args = args.executable
        if args.args:
            run_args += " " + args.args
        if args.stdin:
            run_args += f" < {args.stdin}"
        stop_info = cmd_run(debugger, run_args)
        handle_stop(debugger, stop_info)

    # REPL
    last_cmd = ""
    while True:
        try:
            prompt = get_prompt(debugger)
            user_input = console.input(prompt)

            # Repeat last command on empty input
            if not user_input.strip():
                user_input = last_cmd
            else:
                last_cmd = user_input

            stop_info = dispatch(debugger, user_input)

            if stop_info:
                if stop_info.get("reason") == "quit":
                    if debugger.state in (DebuggerState.STOPPED, DebuggerState.RUNNING):
                        debugger.terminate()
                    info("Goodbye!")
                    break
                handle_stop(debugger, stop_info)

        except KeyboardInterrupt:
            console.print()
            if debugger.state == DebuggerState.RUNNING:
                debugger.interrupt()
            else:
                # Check KD session
                from .commands.kd_cmds import _kd_session
                if _kd_session and _kd_session.connected and not _kd_session.stopped:
                    _kd_session.do_break()
            continue
        except EOFError:
            console.print()
            if debugger.state in (DebuggerState.STOPPED, DebuggerState.RUNNING):
                debugger.terminate()
            break
        except Exception as e:
            error(f"Error: {e}")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main()
