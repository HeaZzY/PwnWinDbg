"""Execution commands: run, attach, continue, step, breakpoints."""

import os
import shlex

from ..display.formatters import error, info, success, warn, console


def cmd_run(debugger, args):
    """Spawn a process: run <exe> [args] [< stdin_file]

    With no arguments, re-spawns the most recently launched executable
    using the same args and stdin redirection. To re-launch with new
    args without retyping the path, see `rerun`.
    """
    raw = args.strip()

    # Parse stdin redirection: run exe args < file
    stdin_file = None
    if "<" in raw:
        left, right = raw.rsplit("<", 1)
        stdin_file = right.strip()
        if stdin_file.startswith('"') and stdin_file.endswith('"'):
            stdin_file = stdin_file[1:-1]
        raw = left.strip()
        if not os.path.exists(stdin_file):
            error(f"Stdin file not found: {stdin_file}")
            return None

    if not raw:
        if debugger.exe_path:
            exe = debugger.exe_path
            extra_args = debugger.exe_args or ""
            # Re-use last stdin redirection unless the user explicitly
            # passed `< file` on this invocation.
            if stdin_file is None:
                stdin_file = debugger.exe_stdin_file
        else:
            error("Usage: run <exe_path> [args] [< stdin_file]")
            return None
    else:
        # Use shlex with posix=False so Windows-style quoted paths
        # ("C:\Program Files\..." …) survive intact.
        try:
            tokens = shlex.split(raw, posix=False)
        except ValueError as e:
            error(f"Failed to parse command line: {e}")
            return None
        if not tokens:
            error("Usage: run <exe_path> [args] [< stdin_file]")
            return None
        exe = tokens[0]
        # Strip surrounding quotes shlex left in place (posix=False keeps them).
        if len(exe) >= 2 and exe[0] == exe[-1] and exe[0] in ('"', "'"):
            exe = exe[1:-1]
        extra_args = " ".join(tokens[1:]) if len(tokens) > 1 else ""

    if not os.path.exists(exe):
        error(f"File not found: {exe}")
        return None

    return _spawn_and_run(debugger, exe, extra_args, stdin_file)


def cmd_rerun(debugger, args):
    """Re-run the last executable with optional new args.

    Usage:
        rerun                 — same exe + same args as last run
        rerun <new args...>   — same exe but with new args
        rerun < new_stdin     — same exe + args, but new stdin file

    Auto-terminates the previous process if it's still alive.
    """
    if not debugger.exe_path:
        error("Nothing to rerun — no exe has been launched yet")
        return None

    raw = args.strip()
    stdin_file = debugger.exe_stdin_file

    # Same `< file` parsing as cmd_run, but everything else is just
    # the new arg list (no exe token).
    if "<" in raw:
        left, right = raw.rsplit("<", 1)
        stdin_file = right.strip() or None
        if stdin_file and stdin_file.startswith('"') and stdin_file.endswith('"'):
            stdin_file = stdin_file[1:-1]
        raw = left.strip()
        if stdin_file and not os.path.exists(stdin_file):
            error(f"Stdin file not found: {stdin_file}")
            return None

    new_args = raw if raw else (debugger.exe_args or "")
    return _spawn_and_run(debugger, debugger.exe_path, new_args, stdin_file)


def _spawn_and_run(debugger, exe, extra_args, stdin_file):
    """Shared spawn helper used by both `run` and `rerun`.

    If a previous process is still alive, terminate it first so we
    don't leak handles or end up debugging two children at once.
    """
    from ..core.debugger import DebuggerState
    if debugger.state not in (DebuggerState.IDLE, DebuggerState.TERMINATED):
        try:
            debugger.terminate()
            info("Terminated previous process")
        except Exception:
            pass

    try:
        debugger.spawn(exe, extra_args, stdin_file=stdin_file)
        cmdline = exe + (f" {extra_args}" if extra_args else "")
        info(f"Spawned process PID={debugger.process_id} ({cmdline})")
        info(f"Architecture: {'x86 (WoW64)' if debugger.is_wow64 else 'x64'}")
        if stdin_file:
            info(f"Stdin: {stdin_file}")

        # Run until first stop
        result = debugger.run_until_stop()

        # Re-apply saved breakpoints from previous session
        reapplied = debugger.bp_manager.reapply_saved(debugger.process_handle)
        if reapplied:
            info(f"Re-applied {reapplied} saved breakpoint(s)")

        return result
    except Exception as e:
        error(f"Failed to spawn: {e}")
        return None


def cmd_attach(debugger, args):
    """Attach to a process: attach <pid>"""
    args = args.strip()
    if not args:
        error("Usage: attach <pid>")
        return None

    try:
        pid = int(args, 0)
    except ValueError:
        error(f"Invalid PID: {args}")
        return None

    try:
        debugger.attach(pid)
        info(f"Attached to PID={pid}")
        info(f"Architecture: {'x86 (WoW64)' if debugger.is_wow64 else 'x64'}")

        result = debugger.run_until_stop()

        # Re-apply saved breakpoints from previous session
        reapplied = debugger.bp_manager.reapply_saved(debugger.process_handle)
        if reapplied:
            info(f"Re-applied {reapplied} saved breakpoint(s)")

        return result
    except Exception as e:
        error(f"Failed to attach: {e}")
        return None


def cmd_continue(debugger, args):
    """Continue execution: c / continue"""
    from .kd_cmds import _kd_session
    if _kd_session and _kd_session.connected:
        from .kd_cmds import cmd_kdcontinue
        return cmd_kdcontinue(debugger, args)
    from ..core.debugger import DebuggerState
    if debugger.state != DebuggerState.STOPPED:
        error("Process is not stopped")
        return None
    return debugger.do_continue()


def cmd_step_into(debugger, args):
    """Step into: si"""
    from .kd_cmds import _kd_session
    if _kd_session and _kd_session.connected:
        from .kd_cmds import cmd_kdstep
        return cmd_kdstep(debugger, args)
    from ..core.debugger import DebuggerState
    if debugger.state != DebuggerState.STOPPED:
        error("Process is not stopped")
        return None
    return debugger.do_step_into()


def cmd_step_over(debugger, args):
    """Step over: ni"""
    from .kd_cmds import _kd_session
    if _kd_session and _kd_session.connected:
        from .kd_cmds import cmd_kdstep
        return cmd_kdstep(debugger, args)
    from ..core.debugger import DebuggerState
    if debugger.state != DebuggerState.STOPPED:
        error("Process is not stopped")
        return None
    return debugger.do_step_over()


def cmd_finish(debugger, args):
    """Run until return: finish"""
    from ..core.debugger import DebuggerState
    if debugger.state != DebuggerState.STOPPED:
        error("Process is not stopped")
        return None
    return debugger.do_finish()


def cmd_stepuntil(debugger, args):
    """Run until <addr>: stepuntil <addr|symbol|expression>

    Sets a one-shot breakpoint at the resolved address and continues.
    Useful for skipping ahead to a known location without single-stepping.
    """
    from ..core.debugger import DebuggerState
    if debugger.state != DebuggerState.STOPPED:
        error("Process is not stopped")
        return None
    if not args.strip():
        error("Usage: stepuntil <address|symbol|expression>")
        return None
    from ..utils.addr_expr import eval_expr
    addr = eval_expr(debugger, args.strip())
    if addr is None:
        error(f"Cannot resolve: {args.strip()}")
        return None
    return debugger.do_stepuntil(addr)


def cmd_bp(debugger, args):
    """Set breakpoint: bp <address> [thread <tid>] [if <condition>]

    `thread <tid>` and `if <expr>` may appear in either order. The BP
    only stops when both filters match — wrong thread silently steps
    past, same as a falsy condition.

    Examples:
        bp 0x401000
        bp WinExec
        bp *0x401000+0x10
        bp 0x401000 if rax == 0x42
        bp WinExec thread 0x1234
        bp WinExec thread 0x1234 if qword(rsp+8) == 0x4141414141414141
    """
    from .kd_cmds import _kd_session
    if _kd_session and _kd_session.connected:
        from .kd_cmds import cmd_kdbp
        return cmd_kdbp(debugger, args)
    args = args.strip()
    if not args:
        error("Usage: bp <address|symbol> [thread <tid>] [if <condition>]")
        return None

    # Pull out optional `thread <tid>` and `if <expr>` clauses. Either
    # order is accepted; whichever appears first ends the address.
    # `if` consumes the rest of the line up to a trailing `thread` clause
    # (or end), so conditions can contain spaces and operators freely.
    tokens = args.split()
    condition = None
    thread_id = None
    head_end = len(tokens)
    i = 0
    while i < len(tokens):
        t = tokens[i].lower()
        if i > 0 and t == "thread":
            head_end = min(head_end, i)
            if i + 1 >= len(tokens):
                error("`thread` requires a TID value")
                return None
            try:
                thread_id = int(tokens[i + 1], 0)
            except ValueError:
                error(f"Invalid TID: {tokens[i + 1]}")
                return None
            # Drop these two tokens and keep scanning for `if`
            tokens = tokens[:i] + tokens[i + 2:]
            continue
        if i > 0 and t == "if":
            head_end = min(head_end, i)
            # `if` consumes everything until end or a `thread` keyword
            j = i + 1
            end = len(tokens)
            while j < len(tokens):
                if tokens[j].lower() == "thread":
                    end = j
                    break
                j += 1
            condition = " ".join(tokens[i + 1:end]).strip()
            if not condition:
                error("Empty condition after `if`")
                return None
            tokens = tokens[:i] + tokens[end:]
            continue
        i += 1

    if not tokens[:head_end]:
        error("Missing address")
        return None
    addr_part = " ".join(tokens[:head_end])

    # Strip GDB-style '*' prefix
    if addr_part.startswith("*"):
        addr_part = addr_part[1:].strip()

    # Try to resolve address (supports expressions like addr+0x10)
    from ..utils.addr_expr import eval_expr
    addr = eval_expr(debugger, addr_part)
    if addr is None:
        error(f"Cannot resolve: {addr_part}")
        return None

    bp = debugger.bp_manager.add(debugger.process_handle, addr)
    debugger.bp_manager.save_address(addr)
    if condition is not None:
        bp.condition = condition
    if thread_id is not None:
        bp.thread_id = thread_id
    parts = [f"Breakpoint #{bp.id} set at {addr:#x}"]
    if thread_id is not None:
        parts.append(f"thread {thread_id}")
    if condition is not None:
        parts.append(f"if {condition}")
    success(" ".join(parts))
    return None


def cmd_bpcond(debugger, args):
    """Set or clear a condition on an existing breakpoint.

    Usage: cond <id> [<expression>]
           cond <id>            — clear the condition
           cond <id> rax == 0x42 — set condition
    """
    args = args.strip()
    parts = args.split(None, 1)
    if not parts:
        error("Usage: cond <bp_id> [<expression>]")
        return None
    try:
        bp_id = int(parts[0], 0)
    except ValueError:
        error(f"Invalid breakpoint id: {parts[0]}")
        return None
    bp = debugger.bp_manager.bp_by_id.get(bp_id)
    if bp is None:
        error(f"No breakpoint with id {bp_id}")
        return None
    expr = parts[1].strip() if len(parts) > 1 else ""
    if not expr:
        bp.condition = None
        success(f"Breakpoint #{bp_id}: condition cleared")
    else:
        bp.condition = expr
        success(f"Breakpoint #{bp_id}: condition set to `{expr}`")
    return None


def cmd_bl(debugger, args):
    """List breakpoints: bl"""
    from ..display.formatters import display_breakpoints
    bps = debugger.bp_manager.list_all()
    display_breakpoints(bps)
    return None


def cmd_bd(debugger, args):
    """Delete breakpoint: bd <id>"""
    args = args.strip()
    if not args:
        error("Usage: bd <breakpoint_id>")
        return None

    try:
        bp_id = int(args)
    except ValueError:
        error(f"Invalid breakpoint ID: {args}")
        return None

    if debugger.bp_manager.remove(debugger.process_handle, bp_id):
        success(f"Breakpoint #{bp_id} deleted")
    else:
        error(f"Breakpoint #{bp_id} not found")
    return None


def cmd_detach(debugger, args):
    """Detach from process: detach"""
    debugger.detach()
    info("Detached from process")
    return None


def cmd_kill(debugger, args):
    """Kill the process: kill"""
    debugger.terminate()
    info("Process terminated")
    return {"reason": "exit", "exit_code": -1}


def cmd_retbreak(debugger, args):
    """Set breakpoints on all ret in current function, then continue: retbreak"""
    from ..core.debugger import DebuggerState
    if debugger.state != DebuggerState.STOPPED:
        error("Process is not stopped")
        return None

    ret_addrs = debugger.do_retbreak(run_after=True)
    if not ret_addrs:
        error("No ret instructions found in current function")
        return None

    for addr in ret_addrs:
        sym = debugger.symbols.resolve_address(addr) or ""
        info(f"Temp BP on ret at {addr:#x}  {sym}")

    info(f"Set {len(ret_addrs)} ret breakpoint(s), continuing...")
    return debugger.do_continue()
