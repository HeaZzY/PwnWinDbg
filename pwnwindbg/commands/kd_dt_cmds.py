"""kddt — display struct types at a kernel address (WinDbg `dt` clone).

Hardcodes a few common Win10/11 x64 structs (_EPROCESS, _ETHREAD, _KPCR,
_KPRCB, _KTHREAD). For each struct we list field offsets, sizes, and a
display kind (ptr / int / ascii / unicode / list_entry).
"""

import struct

from ..core.kd.win_structs import EPROCESS
from ..display.formatters import (
    info, error, warn, console, banner,
)

from rich.text import Text


def _eprocess_layout():
    """Build the _EPROCESS field list from the (build-aware) EPROCESS class."""
    return [
        (0x000,                                  8,  "Pcb.Header",                  "u64"),
        (0x028,                                  8,  "Pcb.DirectoryTableBase",      "u64"),
        (0x030,                                  16, "Pcb.ThreadListHead",          "list_entry"),
        (EPROCESS.UniqueProcessId,               8,  "UniqueProcessId",             "u64"),
        (EPROCESS.ActiveProcessLinks,            16, "ActiveProcessLinks",          "list_entry"),
        (EPROCESS.Token,                         8,  "Token (EX_FAST_REF)",         "u64"),
        (EPROCESS.InheritedFromUniqueProcessId,  8,  "InheritedFromUniqueProcessId","u64"),
        (EPROCESS.ImageFileName,                 15, "ImageFileName",               "ascii15"),
        (EPROCESS.ThreadListHead,                16, "ThreadListHead",              "list_entry"),
    ]


# ---------------------------------------------------------------------------
# Struct definitions: list of (offset, size, name, kind)
# kind: u8/u16/u32/u64/ptr/ascii<N>/unicode_string/list_entry
# ---------------------------------------------------------------------------

_STRUCTS = {
    # _EPROCESS is rebuilt dynamically (see _resolve_struct below)
    "_EPROCESS": None,
    "_KPROCESS": [
        (0x000, 16, "Header",                       "u64"),
        (0x028, 8,  "DirectoryTableBase",           "u64"),
        (0x030, 16, "ThreadListHead",               "list_entry"),
    ],
    "_ETHREAD": [
        (0x000, 8,  "Tcb.Header",                   "u64"),
        (0x220, 8,  "Tcb.Process",                  "ptr"),
        (0x4e8, 16, "ThreadListEntry",              "list_entry"),
        (0x650, 16, "Cid (ProcessId, ThreadId)",    "u64"),
    ],
    "_KTHREAD": [
        (0x000, 8,  "Header",                       "u64"),
        (0x030, 8,  "StackLimit",                   "ptr"),
        (0x038, 8,  "StackBase",                    "ptr"),
        (0x058, 8,  "KernelStack",                  "ptr"),
        (0x220, 8,  "Process",                      "ptr"),
    ],
    "_KPCR": [
        (0x018, 8,  "Self",                         "ptr"),
        (0x020, 8,  "CurrentPrcb",                  "ptr"),
        (0x038, 8,  "IdtBase",                      "ptr"),
        (0x180, 0,  "Prcb (embedded KPRCB)",        "u64"),
    ],
    "_KPRCB": [
        (0x008, 8,  "CurrentThread",                "ptr"),
        (0x010, 8,  "NextThread",                   "ptr"),
        (0x018, 8,  "IdleThread",                   "ptr"),
    ],
    "_LIST_ENTRY": [
        (0x000, 8,  "Flink",                        "ptr"),
        (0x008, 8,  "Blink",                        "ptr"),
    ],
    "_UNICODE_STRING": [
        (0x000, 2,  "Length",                       "u16"),
        (0x002, 2,  "MaximumLength",                "u16"),
        (0x008, 8,  "Buffer",                       "ptr"),
    ],
}


def _format_field(session, base, off, size, kind):
    """Read a field from the target and return a string value."""
    if kind == "list_entry":
        data = session.read_virtual(base + off, 16)
        if not data or len(data) < 16:
            return "<unreadable>"
        flink, blink = struct.unpack_from("<QQ", data, 0)
        return f"Flink={flink:#x} Blink={blink:#x}"

    if kind.startswith("ascii"):
        n = int(kind[5:]) if kind != "ascii" else size
        data = session.read_virtual(base + off, n)
        if not data:
            return "<unreadable>"
        return data.split(b"\x00")[0].decode("latin-1", errors="replace")

    if kind == "u8":
        d = session.read_virtual(base + off, 1)
        return f"{d[0]:#x}" if d else "<unreadable>"
    if kind == "u16":
        d = session.read_virtual(base + off, 2)
        return f"{struct.unpack_from('<H', d, 0)[0]:#x}" if d and len(d) >= 2 else "<unreadable>"
    if kind == "u32":
        d = session.read_virtual(base + off, 4)
        return f"{struct.unpack_from('<I', d, 0)[0]:#x}" if d and len(d) >= 4 else "<unreadable>"
    if kind in ("u64", "ptr"):
        d = session.read_virtual(base + off, 8)
        return f"{struct.unpack_from('<Q', d, 0)[0]:#x}" if d and len(d) >= 8 else "<unreadable>"

    return "?"


def cmd_kddt(debugger, args):
    """Display a struct at a kernel address (WinDbg `dt` style).

    Usage:
        kddt                              — list available structs
        kddt <_STRUCT>                    — list fields of struct
        kddt <_STRUCT> <addr>             — read fields from target memory

    Examples:
        kddt _EPROCESS
        kddt _EPROCESS 0xffffaa00`12345000
        kddt _KPCR @gs_base
    """
    from .kd_cmds import _get_session, _kd_eval_expr

    parts = args.strip().split(None, 1)
    if not parts:
        banner("Available structures")
        for name in sorted(_STRUCTS.keys()):
            console.print(Text(f"  {name}", style="bright_green"))
        info("Usage: kddt <_STRUCT> [address]")
        return None

    sname = parts[0]
    if not sname.startswith("_"):
        sname = "_" + sname
    sname_upper = sname.upper()

    # Case-insensitive lookup
    matched = None
    for k in _STRUCTS:
        if k.upper() == sname_upper:
            matched = k
            break
    if matched is None:
        error(f"Unknown struct: {sname}  (use `kddt` to list)")
        return None

    # _EPROCESS layout depends on the Windows build — rebuild dynamically
    if matched == "_EPROCESS":
        fields = _eprocess_layout()
    else:
        fields = _STRUCTS[matched]

    # No address: just show layout
    if len(parts) < 2:
        banner(f"struct {matched}")
        for off, size, name, kind in fields:
            text = Text()
            text.append(f"  +{off:#06x}  ", style="bright_yellow")
            text.append(f"{name:32s}  ", style="bold bright_white")
            text.append(f"({kind})", style="bright_black")
            console.print(text)
        return None

    # With address: read from target
    session = _get_session()
    if session is None:
        return None
    if not session.stopped:
        error("Target is running. Break first.")
        return None

    addr = _kd_eval_expr(parts[1], session)
    if addr is None:
        error(f"Cannot resolve: {parts[1]}")
        return None

    banner(f"struct {matched} at {addr:#x}")
    for off, size, name, kind in fields:
        value = _format_field(session, addr, off, size, kind)
        text = Text()
        text.append(f"  +{off:#06x}  ", style="bright_yellow")
        text.append(f"{name:32s}  ", style="bold bright_white")
        text.append(value, style="bright_cyan")
        console.print(text)
    return None
