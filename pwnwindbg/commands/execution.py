"""Execution commands: run, attach, continue, step, breakpoints."""

import os
from ..display.formatters import error, info, success, warn, console


def cmd_run(debugger, args):
    """Spawn a process: run <exe> [args] [< stdin_file]"""
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

    parts = raw.split(None, 1) if raw else []
    if not parts:
        if debugger.exe_path:
            exe = debugger.exe_path
            extra_args = ""
        else:
            error("Usage: run <exe_path> [args] [< stdin_file]")
            return None
    else:
        exe = parts[0]
        extra_args = parts[1] if len(parts) > 1 else ""

    if not os.path.exists(exe):
        error(f"File not found: {exe}")
        return None

    try:
        debugger.spawn(exe, extra_args, stdin_file=stdin_file)
        info(f"Spawned process PID={debugger.process_id} ({exe})")
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


def cmd_bp(debugger, args):
    """Set breakpoint: bp <address>"""
    from .kd_cmds import _kd_session
    if _kd_session and _kd_session.connected:
        from .kd_cmds import cmd_kdbp
        return cmd_kdbp(debugger, args)
    args = args.strip()
    if not args:
        error("Usage: bp <address|symbol>")
        return None

    # Strip GDB-style '*' prefix
    if args.startswith("*"):
        args = args[1:].strip()

    # Try to resolve address (supports expressions like addr+0x10)
    from ..utils.addr_expr import eval_expr
    addr = eval_expr(debugger, args)
    if addr is None:
        error(f"Cannot resolve: {args}")
        return None

    bp = debugger.bp_manager.add(debugger.process_handle, addr)
    debugger.bp_manager.save_address(addr)
    success(f"Breakpoint #{bp.id} set at {addr:#x}")
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
