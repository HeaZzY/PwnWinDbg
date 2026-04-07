"""dprintf — printf-style tracing breakpoint.

Sets an INT3 at <addr> that, instead of stopping the debugger, evaluates
a format string and prints it to the REPL, then transparently continues
execution. Modeled on GDB's `dprintf`.

Format string supports `{expr}` placeholders evaluated against the same
namespace as conditional breakpoints (registers + memory readers). An
optional `:spec` selects rendering (`x`/`hex`, `d`, `s`):

    dprintf ntdll!NtCreateFile "open: handle={rcx} attrs={qword(r8+0x10):hex}"
    dprintf kernel32!CreateFileW "name={wstr(rcx)} access={rdx:hex}"
    dprintf 0x401234 "rax={rax} *[rsp]={qword(rsp):hex}"

Underneath, this is a regular software breakpoint with `bp.action` set;
the BP-hit handler in core/debugger.py renders the message and resumes.
"""

import shlex

from ..display.formatters import banner, console, error, info, success
from ..utils.addr_expr import eval_expr


def cmd_dprintf(debugger, args):
    """Set a tracing breakpoint that prints a message and continues.

    Usage:
        dprintf <addr> "<format>"
        dprintf list                — show every dprintf currently set
        dprintf del <id>            — remove a tracing BP by id
    """
    if not debugger.process_handle:
        error("No process attached")
        return None

    raw = args.strip()
    if not raw:
        error('Usage: dprintf <addr> "<format>"   |   dprintf list   |   dprintf del <id>')
        return None

    # `list` / `del` subcommands
    parts0 = raw.split()
    if parts0[0] in ("list", "ls"):
        rows = [bp for bp in debugger.bp_manager.list_all() if bp.action]
        if not rows:
            info("No dprintf breakpoints set")
            return None
        banner(f"dprintf — {len(rows)} entries")
        for bp in rows:
            console.print(
                f"  [bright_yellow]BP#{bp.id}[/]  "
                f"[bright_blue]{bp.address:#x}[/]  "
                f"hits={bp.hit_count}  "
                f'[bright_white]"{bp.action}"[/]'
            )
        return None
    if parts0[0] in ("del", "delete", "rm") and len(parts0) >= 2:
        try:
            bp_id = int(parts0[1])
        except ValueError:
            error(f"Invalid id: {parts0[1]}")
            return None
        if debugger.bp_manager.remove(debugger.process_handle, bp_id):
            success(f"Removed BP#{bp_id}")
        else:
            error(f"No BP with id {bp_id}")
        return None

    # Parse "<addr> <format>"  — format may be quoted
    try:
        toks = shlex.split(raw, posix=True)
    except ValueError as e:
        error(f"Parse error: {e}")
        return None
    if len(toks) < 2:
        error('Usage: dprintf <addr> "<format>"')
        return None

    addr_str = toks[0]
    fmt = " ".join(toks[1:])

    addr = eval_expr(debugger, addr_str)
    if addr is None:
        error(f"Cannot resolve: {addr_str}")
        return None

    try:
        bp = debugger.bp_manager.add(debugger.process_handle, addr)
    except Exception as e:
        error(f"Failed to set breakpoint: {e}")
        return None

    bp.action = fmt
    debugger.bp_manager.save_address(addr)
    success(f'BP#{bp.id} @ {addr:#x}  dprintf "{fmt}"')
    return None
