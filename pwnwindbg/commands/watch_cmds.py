"""Hardware watchpoint commands.

Usage
-----
    watch -w <addr>           write watch (default length 8)
    watch -r <addr>           read+write watch
    watch -x <addr>           execute watch (length forced to 1)
    watch [...] -l <bytes>    set length (1, 2, 4, 8)
    watch                     list active watchpoints
    watch del <id>            remove a watchpoint
    watch clear               remove all watchpoints

`-w/--write`, `-r/--read`, and `-x/--exec` are also accepted as
`watch w <addr>` / `watch r <addr>` / `watch x <addr>`.

The address may be any expression accepted by `eval_expr`, including
register references like `$rsp+0x18` or `ntdll!DbgUiRemoteBreakin`.
"""

from rich.table import Table
from rich.text import Text

from ..display.formatters import error, info, success, warn, console, banner
from ..utils.addr_expr import eval_expr
from ..core.watchpoints import (
    WATCH_WRITE, WATCH_READ_WRITE, WATCH_EXEC,
)


def cmd_watch(debugger, args):
    """Add / list / remove hardware watchpoints (DR0-DR3)."""
    if not debugger.process_handle:
        error("No process attached")
        return None

    parts = args.strip().split()
    if not parts:
        return _list(debugger)

    sub = parts[0].lower()
    if sub in ("list", "l"):
        return _list(debugger)
    if sub in ("clear", "clr", "cls"):
        return _clear(debugger)
    if sub in ("del", "delete", "rm", "d"):
        if len(parts) < 2:
            error("Usage: watch del <id>")
            return None
        try:
            wp_id = int(parts[1], 0)
        except ValueError:
            error(f"Invalid id: {parts[1]}")
            return None
        if debugger.remove_watchpoint(wp_id):
            success(f"Watchpoint #{wp_id} removed")
        else:
            error(f"No watchpoint with id {wp_id}")
        return None

    # Parse access flag + address + optional length
    access = None
    length = 8  # default for read/write watches
    addr_tokens = []

    i = 0
    while i < len(parts):
        a = parts[i]
        if a in ("-w", "--write", "w", "write"):
            access = WATCH_WRITE
            i += 1
        elif a in ("-r", "--read", "r", "rw", "read"):
            access = WATCH_READ_WRITE
            i += 1
        elif a in ("-x", "--exec", "x", "exec"):
            access = WATCH_EXEC
            length = 1
            i += 1
        elif a in ("-l", "--len", "--length"):
            if i + 1 >= len(parts):
                error(f"{a} requires a value (1, 2, 4, or 8)")
                return None
            try:
                length = int(parts[i + 1], 0)
            except ValueError:
                error(f"Invalid length: {parts[i + 1]}")
                return None
            i += 2
        else:
            addr_tokens.append(a)
            i += 1

    if access is None:
        error("Specify -w (write), -r (read+write), or -x (exec)")
        return None
    if not addr_tokens:
        error("Missing address")
        return None

    addr_expr = " ".join(addr_tokens)
    addr = eval_expr(debugger, addr_expr)
    if addr is None:
        error(f"Cannot resolve address: {addr_expr}")
        return None

    try:
        wp = debugger.add_watchpoint(addr, access, length)
    except ValueError as e:
        error(str(e))
        return None

    label = {WATCH_WRITE: "write", WATCH_READ_WRITE: "read+write",
             WATCH_EXEC: "exec"}[access]
    success(
        f"Watchpoint #{wp.id} armed: {label} @ {addr:#x} "
        f"(len={length}, slot DR{wp.slot})"
    )
    return None


def _list(debugger):
    wps = debugger.wp_manager.list_all()
    if not wps:
        info("No active watchpoints")
        return None

    banner(f"WATCHPOINTS ({len(wps)}/4 slots used)")
    table = Table(show_header=True, border_style="cyan", header_style="bold bright_white")
    table.add_column("Id", justify="right", style="bright_yellow")
    table.add_column("Slot", justify="center", style="bright_white")
    table.add_column("Address", style="bright_cyan")
    table.add_column("Type", style="bold bright_green")
    table.add_column("Len", justify="right", style="bright_white")
    table.add_column("Hits", justify="right", style="bright_magenta")
    table.add_column("State", style="bright_white")

    type_label = {WATCH_WRITE: "write", WATCH_READ_WRITE: "read+write",
                  WATCH_EXEC: "exec"}
    for wp in wps:
        sym = ""
        if hasattr(debugger.symbols, "resolve_address"):
            sym = debugger.symbols.resolve_address(wp.address) or ""
        addr_text = Text(f"{wp.address:#x}")
        if sym:
            addr_text.append(f"  ({sym})", style="bright_black")
        table.add_row(
            str(wp.id),
            f"DR{wp.slot}",
            addr_text,
            type_label[wp.access],
            str(wp.length),
            str(wp.hit_count),
            "enabled" if wp.enabled else "disabled",
        )

    console.print(table)
    return None


def _clear(debugger):
    wps = debugger.wp_manager.list_all()
    if not wps:
        info("No watchpoints to clear")
        return None
    for wp in list(wps):
        debugger.remove_watchpoint(wp.id)
    success(f"Cleared {len(wps)} watchpoint(s)")
    return None
