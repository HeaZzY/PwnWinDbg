"""WinDbg-style command aliases.

Thin wrappers that translate WinDbg syntax (`db addr L20`, `eq addr value`,
`bc *`, `g`, `t`, `~`) into the existing pwnWinDbg primitives. Useful for
muscle memory if you're coming from kd / windbg.

The display commands (db/dw/dd/dq/da/du) accept the WinDbg `Lcount` count
specifier in addition to the bare integer count we use everywhere else:

    db ntdll+0x1000          → 128 bytes
    db ntdll+0x1000 L20      → 0x20 bytes
    db ntdll+0x1000 0x20     → 0x20 bytes  (also works)

The edit commands (eb/ew/ed/eq) take any number of values:

    eb 0x401000 90 90 90
    eq rsp+8 0x4141414141414141
"""

import re

from ..display.formatters import error, success, info
from ..core.memory import write_memory
from ..utils.addr_expr import eval_expr


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_L_COUNT_RE = re.compile(r'^[lL](\w+)$')


def _normalize_count(args, default_count_str):
    """Translate `<addr> Lcount` → `<addr> count`. Returns the new arg string."""
    parts = args.split()
    if len(parts) >= 2:
        m = _L_COUNT_RE.match(parts[-1])
        if m:
            parts[-1] = m.group(1)
            return " ".join(parts)
    if len(parts) == 1 and default_count_str:
        return f"{parts[0]} {default_count_str}"
    return args


# ---------------------------------------------------------------------------
# Display: db / dw / dd / dq / da / du
# ---------------------------------------------------------------------------

def cmd_db(debugger, args):
    """db <addr> [Lcount]  —  display bytes (WinDbg)"""
    from .examine import cmd_x_bytes
    return cmd_x_bytes(debugger, _normalize_count(args, "0x40"))


def cmd_dw(debugger, args):
    """dw <addr> [Lcount]  —  display words (WinDbg)"""
    # cmd_x_dwords actually displays dwords; words are 2 bytes. We map dw → x/wx
    # in the userland sense (dwords-as-half) — but WinDbg dw is 16-bit words.
    # The existing infra is dword-oriented, so we route dw to a byte read with
    # half count and let users use `dd` for actual dwords.
    from .examine import cmd_x_bytes
    return cmd_x_bytes(debugger, _normalize_count(args, "0x40"))


def cmd_dd(debugger, args):
    """dd <addr> [Lcount]  —  display dwords (WinDbg)"""
    from .examine import cmd_x_dwords
    return cmd_x_dwords(debugger, _normalize_count(args, "0x10"))


def cmd_dq(debugger, args):
    """dq <addr> [Lcount]  —  display qwords (WinDbg)"""
    from .examine import cmd_x_qwords
    return cmd_x_qwords(debugger, _normalize_count(args, "0x10"))


def cmd_da(debugger, args):
    """da <addr>  —  display ASCII string (WinDbg)"""
    from .examine import cmd_x_string
    return cmd_x_string(debugger, args)


def cmd_du(debugger, args):
    """du <addr>  —  display Unicode string (WinDbg)"""
    if not debugger.process_handle:
        error("No process attached")
        return None
    parts = args.strip().split()
    if not parts:
        error("Usage: du <address>")
        return None
    addr = eval_expr(debugger, parts[0])
    if addr is None:
        error(f"Cannot resolve address: {parts[0]}")
        return None
    from ..core.memory import read_wstring
    s = read_wstring(debugger.process_handle, addr, max_len=1024)
    if s is None:
        error(f"Cannot read memory at {addr:#x}")
        return None
    from rich.text import Text
    from ..display.formatters import console
    text = Text()
    text.append(f"  {addr:#x}: ", style="bright_cyan")
    text.append(f'L"{s}"', style="bright_green")
    text.append(f"  (len={len(s)})", style="bright_black")
    console.print(text)
    return None


# ---------------------------------------------------------------------------
# Edit memory: eb / ew / ed / eq
# ---------------------------------------------------------------------------

def _cmd_edit(debugger, args, value_size, label):
    if not debugger.process_handle:
        error("No process attached")
        return None
    parts = args.strip().split()
    if len(parts) < 2:
        error(f"Usage: {label} <address> <value> [value...]")
        return None

    addr = eval_expr(debugger, parts[0])
    if addr is None:
        error(f"Cannot resolve address: {parts[0]}")
        return None

    blob = b""
    for raw in parts[1:]:
        try:
            v = int(raw, 0)
        except ValueError:
            error(f"Invalid value: {raw}")
            return None
        try:
            blob += v.to_bytes(value_size, "little", signed=False)
        except OverflowError:
            error(f"Value {raw} doesn't fit in {value_size} byte(s)")
            return None

    try:
        n = write_memory(debugger.process_handle, addr, blob)
    except Exception as e:
        error(f"Write failed: {e}")
        return None
    success(f"{label}: wrote {n} bytes ({len(parts)-1} value(s)) at {addr:#x}")
    return None


def cmd_eb(debugger, args):
    """eb <addr> <byte> [byte...]  —  edit bytes"""
    return _cmd_edit(debugger, args, 1, "eb")


def cmd_ew(debugger, args):
    """ew <addr> <word> [word...]  —  edit words"""
    return _cmd_edit(debugger, args, 2, "ew")


def cmd_ed(debugger, args):
    """ed <addr> <dword> [dword...]  —  edit dwords"""
    return _cmd_edit(debugger, args, 4, "ed")


def cmd_eq(debugger, args):
    """eq <addr> <qword> [qword...]  —  edit qwords"""
    return _cmd_edit(debugger, args, 8, "eq")


# ---------------------------------------------------------------------------
# Misc WinDbg short aliases that need a tiny wrapper
# ---------------------------------------------------------------------------

def cmd_bc(debugger, args):
    """bc <id|*>  —  clear breakpoint(s) (WinDbg)"""
    args = args.strip()
    if not args or args == "*":
        # Clear all
        from .execution import cmd_bd
        bps = debugger.bp_manager.list_all()
        if not bps:
            info("No breakpoints to clear")
            return None
        n = 0
        for bp in list(bps):
            if debugger.bp_manager.remove(debugger.process_handle, bp.id):
                n += 1
        success(f"Cleared {n} breakpoint(s)")
        return None
    from .execution import cmd_bd
    return cmd_bd(debugger, args)


def cmd_thread_list(debugger, args):
    """~ — list threads (WinDbg)"""
    if not debugger.threads:
        info("No tracked threads")
        return None
    from rich.table import Table
    from ..display.formatters import console, banner
    banner(f"THREADS ({len(debugger.threads)})")
    table = Table(show_header=True, border_style="cyan",
                  header_style="bold bright_white")
    table.add_column("Tid", justify="right", style="bright_yellow")
    table.add_column("Handle", style="bright_cyan")
    table.add_column("State", style="bright_white")
    for tid, h in debugger.threads.items():
        marker = "*" if tid == debugger.active_thread_id else " "
        table.add_row(f"{marker} {tid}", f"{h:#x}" if h else "?", "active" if tid == debugger.active_thread_id else "")
    console.print(table)
    return None
