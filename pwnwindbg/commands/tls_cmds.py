"""tls — show TLS slots for the active thread.

x64 TEB layout (Win10+):

    TlsSlots[64]              @ +0x1480   (64 ULONG_PTR)
    TlsExpansionSlots*        @ +0x1780   (pointer to ULONG_PTR[1024],
                                            allocated by RtlAllocateHeap on
                                            first TlsAlloc beyond slot 63)

x86 TEB:

    TlsSlots[64]              @ +0x0e10
    TlsExpansionSlots*        @ +0x0f94

We display non-zero slots only by default; pass `--all` to dump every
slot. Each value is annotated via the symbol resolver / module index so
TLS pointers to runtime data become readable.
"""

import struct

from rich.table import Table
from rich.text import Text

from ..display.formatters import banner, console, error, info, warn
from ..core.peb_teb import get_teb_address
from ..core.memory import read_memory_safe, read_qword, read_dword


# Per-arch offsets
TEB_TLS_SLOTS_X64           = 0x1480
TEB_TLS_EXPANSION_SLOTS_X64 = 0x1780
TEB_TLS_SLOTS_X86           = 0x0E10
TEB_TLS_EXPANSION_SLOTS_X86 = 0x0F94

NUM_STATIC_SLOTS    = 64
NUM_EXPANSION_SLOTS = 1024


def _annotate(debugger, val):
    """Return a short rich-Text annotation for a TLS pointer value."""
    if not val:
        return Text("", style="bright_black")
    out = Text()
    syms = debugger.symbols
    if syms:
        sym = syms.resolve_address(val)
        if sym:
            out.append(sym, style="bright_white")
            return out
    # Try a string read
    try:
        raw = read_memory_safe(debugger.process_handle, val, 32)
        if raw:
            printable = "".join(
                chr(b) if 32 <= b < 127 else "."
                for b in raw[:24]
            )
            stripped = printable.strip(".").strip()
            if len(stripped) >= 4:
                out.append(f'"{printable}"', style="bright_yellow")
                return out
    except Exception:
        pass
    out.append("(data)", style="bright_black")
    return out


def cmd_tls(debugger, args):
    """Display TLS slot values for the active thread.

    Usage:
        tls               — show non-zero static + expansion slots
        tls --all         — show every slot, including zeros
        tls <tid>         — switch to a specific thread first
    """
    if not debugger.process_handle:
        error("No process attached")
        return None

    show_all = False
    target_tid = None
    for p in args.strip().split():
        if p in ("--all", "-a"):
            show_all = True
        elif p.isdigit():
            target_tid = int(p)
        else:
            warn(f"Unknown arg: {p}")

    tid = target_tid if target_tid is not None else debugger.active_thread_id
    if tid not in debugger.threads:
        error(f"Unknown TID {tid}")
        return None
    h = debugger.threads[tid]

    teb = get_teb_address(h)
    if not teb:
        error("Could not query TEB address")
        return None

    is_wow = debugger.is_wow64
    ptr_size = 4 if is_wow else 8
    if is_wow:
        slots_off = TEB_TLS_SLOTS_X86
        exp_off   = TEB_TLS_EXPANSION_SLOTS_X86
        unpack    = "<I"
    else:
        slots_off = TEB_TLS_SLOTS_X64
        exp_off   = TEB_TLS_EXPANSION_SLOTS_X64
        unpack    = "<Q"

    # Read static slots in one shot
    raw = read_memory_safe(
        debugger.process_handle, teb + slots_off, NUM_STATIC_SLOTS * ptr_size,
    )
    static = []
    if raw:
        for i in range(NUM_STATIC_SLOTS):
            v = struct.unpack(unpack, raw[i * ptr_size:(i + 1) * ptr_size])[0]
            static.append(v)
    else:
        warn("Failed to read TEB.TlsSlots")

    # Expansion slots
    if is_wow:
        exp_ptr = read_dword(debugger.process_handle, teb + exp_off)
    else:
        exp_ptr = read_qword(debugger.process_handle, teb + exp_off)

    expansion = []
    if exp_ptr:
        raw_exp = read_memory_safe(
            debugger.process_handle, exp_ptr, NUM_EXPANSION_SLOTS * ptr_size,
        )
        if raw_exp:
            for i in range(NUM_EXPANSION_SLOTS):
                v = struct.unpack(
                    unpack, raw_exp[i * ptr_size:(i + 1) * ptr_size],
                )[0]
                expansion.append(v)

    banner(f"TLS — TID {tid}, TEB @ {teb:#x}")

    nonzero_static = [(i, v) for i, v in enumerate(static) if v]
    nonzero_exp    = [(i, v) for i, v in enumerate(expansion) if v]

    if not nonzero_static and not nonzero_exp and not show_all:
        info("No non-zero TLS slots — try `tls --all`")
        return None

    tbl = Table(show_header=True, border_style="cyan",
                header_style="bold bright_white")
    tbl.add_column("Slot",  style="bright_yellow", justify="right")
    tbl.add_column("Addr",  style="bright_blue")
    tbl.add_column("Value", style="bright_magenta")
    tbl.add_column("Info",  style="bright_white", overflow="fold")

    src = enumerate(static) if show_all else nonzero_static
    for i, v in src:
        slot_addr = teb + slots_off + i * ptr_size
        val_str = f"{v:#018x}" if not is_wow else f"{v:#010x}"
        tbl.add_row(str(i), f"{slot_addr:#x}", val_str, _annotate(debugger, v))

    if expansion:
        tbl.add_section()
        src = enumerate(expansion) if show_all else nonzero_exp
        for i, v in src:
            slot_addr = exp_ptr + i * ptr_size
            val_str = f"{v:#018x}" if not is_wow else f"{v:#010x}"
            tbl.add_row(
                f"e{i}", f"{slot_addr:#x}", val_str, _annotate(debugger, v),
            )

    console.print(tbl)
    return None
