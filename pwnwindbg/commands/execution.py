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
    """Set breakpoint: bp <address> [if <condition>]

    Examples:
        bp 0x401000
        bp WinExec
        bp *0x401000+0x10
        bp 0x401000 if rax == 0x42
        bp WinExec if qword(rsp+8) == 0x4141414141414141
    """
    from .kd_cmds import _kd_session
    if _kd_session and _kd_session.connected:
        from .kd_cmds import cmd_kdbp
        return cmd_kdbp(debugger, args)
    args = args.strip()
    if not args:
        error("Usage: bp <address|symbol> [if <condition>]")
        return None

    # Split off "if <condition>" tail
    condition = None
    addr_part = args
    # Use a token-aware split: look for the keyword `if` surrounded by spaces
    tokens = args.split()
    for i, tok in enumerate(tokens):
        if tok.lower() == "if" and i > 0:
            addr_part = " ".join(tokens[:i])
            condition = " ".join(tokens[i + 1:])
            if not condition:
                error("Empty condition after `if`")
                return None
            break

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
        success(f"Breakpoint #{bp.id} set at {addr:#x} if {condition}")
    else:
        success(f"Breakpoint #{bp.id} set at {addr:#x}")
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
