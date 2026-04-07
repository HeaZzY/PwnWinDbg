"""dt — userland struct viewer (WinDbg `dt` clone).

Reuses the field tables defined in `core/peb_teb.py` so that PEB / TEB / etc.
field offsets stay in one place. Generic primitives (`_LIST_ENTRY`,
`_UNICODE_STRING`) are added here for convenience.

Usage:
    dt                              — list available structures
    dt <_STRUCT>                    — show field layout
    dt <_STRUCT> <addr>             — read fields from the debuggee
    dt _PEB                         — auto-resolves to the current PEB
    dt _TEB                         — auto-resolves to the active TEB
"""

from rich.text import Text

from ..display.formatters import banner, console, error, info, warn
from ..core.peb_teb import (
    PEB_X64, TEB_X64, RTL_USER_PROCESS_PARAMS_X64, PEB_LDR_DATA_X64,
    LDR_DATA_TABLE_ENTRY_X64, LIST_ENTRY_X64, UNICODE_STRING_X64,
    read_struct, get_peb_address, get_teb_address,
)


# Map struct name -> (layout, default_addr_resolver) ; resolver may be None.
def _peb_addr(debugger):
    return get_peb_address(debugger.process_handle)


def _teb_addr(debugger):
    th = debugger.get_active_thread_handle()
    return get_teb_address(th) if th else None


_STRUCTS = {
    "_PEB":                       (PEB_X64,                    _peb_addr),
    "_TEB":                       (TEB_X64,                    _teb_addr),
    "_RTL_USER_PROCESS_PARAMETERS": (RTL_USER_PROCESS_PARAMS_X64, None),
    "_PEB_LDR_DATA":              (PEB_LDR_DATA_X64,           None),
    "_LDR_DATA_TABLE_ENTRY":      (LDR_DATA_TABLE_ENTRY_X64,   None),
    "_LIST_ENTRY":                (LIST_ENTRY_X64,             None),
    "_UNICODE_STRING":            (UNICODE_STRING_X64,         None),
}


def _kind_width(kind):
    """Pretty kind label for the layout column."""
    if kind == "ptr":
        return "Ptr64"
    if kind == "u8":
        return "UChar"
    if kind == "u16":
        return "Uint2B"
    if kind == "u32":
        return "Uint4B"
    if kind == "u64":
        return "Uint8B"
    if kind == "unicode_string":
        return "_UNICODE_STRING"
    return kind


def _fmt_value(val, kind):
    if val is None:
        return "<unreadable>"
    if kind == "unicode_string":
        # _read_unicode_string returns the decoded string already
        return f'"{val}"' if val else '""'
    if kind in ("ptr", "u64"):
        return f"0x{val:016x}"
    if kind == "u32":
        return f"0x{val:08x}"
    if kind == "u16":
        return f"0x{val:04x}"
    if kind == "u8":
        return f"0x{val:02x}"
    return str(val)


def cmd_dt(debugger, args):
    """Display a struct's layout or read it from the debuggee.

    Usage:
        dt                          — list available structures
        dt <_STRUCT>                — show fields (auto-reads PEB/TEB if known)
        dt <_STRUCT> <addr|expr>    — read fields at <addr>
    """
    parts = args.strip().split(None, 1)

    if not parts:
        banner("Available structures (userland)")
        for name in sorted(_STRUCTS.keys()):
            console.print(Text(f"  {name}", style="bright_green"))
        info("Usage: dt <_STRUCT> [address]")
        return None

    sname = parts[0]
    if not sname.startswith("_"):
        sname = "_" + sname
    sname_upper = sname.upper()

    matched = None
    for k in _STRUCTS:
        if k.upper() == sname_upper:
            matched = k
            break
    if matched is None:
        error(f"Unknown struct: {sname}  (use `dt` to list)")
        return None

    layout, auto_resolver = _STRUCTS[matched]

    # Resolve address
    addr = None
    if len(parts) >= 2:
        from ..utils.addr_expr import eval_expr
        addr = eval_expr(debugger, parts[1])
        if addr is None:
            error(f"Cannot resolve: {parts[1]}")
            return None
    elif auto_resolver is not None and debugger.process_handle:
        try:
            addr = auto_resolver(debugger)
        except Exception:
            addr = None

    # Layout-only mode
    if addr is None:
        banner(f"struct {matched}")
        for name, (off, kind) in layout.items():
            text = Text()
            text.append(f"  +{off:#06x}  ", style="bright_yellow")
            text.append(f"{name:38s}  ", style="bold bright_white")
            text.append(_kind_width(kind), style="bright_black")
            console.print(text)
        return None

    if not debugger.process_handle:
        error("No process attached — cannot read memory")
        return None

    if debugger.is_wow64 and matched in ("_PEB", "_TEB"):
        warn("WoW64: showing the 64-bit struct (32-bit not implemented)")

    fields = read_struct(debugger.process_handle, addr, layout)

    banner(f"struct {matched} at {addr:#x}")
    for name, (off, kind) in layout.items():
        val = fields.get(name)
        text = Text()
        text.append(f"  +{off:#06x}  ", style="bright_yellow")
        text.append(f"{name:38s}  ", style="bold bright_white")
        text.append(_fmt_value(val, kind), style="bright_cyan")
        # Append a symbol annotation for resolvable pointers
        if kind == "ptr" and val and debugger.symbols:
            sym = debugger.symbols.resolve_address(val)
            if sym:
                text.append(f"  ({sym})", style="green")
            else:
                mod = debugger.symbols.get_module_at(val)
                if mod:
                    text.append(f"  ({mod.name}+{mod.offset_of(val):#x})", style="green")
        console.print(text)
    return None
