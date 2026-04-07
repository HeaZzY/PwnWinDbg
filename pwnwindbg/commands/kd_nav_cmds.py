"""Navigation commands for kernel debug sessions: kdbt, kdxinfo, kdtel."""

import struct

from ..core.kd.stack_walker import scan_backtrace
from ..core.kd.kernel_regions import classify
from ..display.formatters import (
    info, error, warn, console, banner,
)

from rich.text import Text
from rich.table import Table


# ---------------------------------------------------------------------------
# kdbt — kernel backtrace
# ---------------------------------------------------------------------------

def cmd_kdbt(debugger, args):
    """Show kernel call stack (heuristic scan-based).

    Walks the stack from RSP looking for return addresses pointing into
    loaded kernel modules. Validates by checking the preceding bytes form
    a `call` instruction.

    Usage: kdbt [max_frames] [scan_bytes]
    """
    from .kd_cmds import _get_session, _walk_module_list

    session = _get_session()
    if session is None:
        return None
    if not session.stopped:
        error("Target is running. Break first.")
        return None

    parts = args.strip().split()
    max_frames = 20
    scan_bytes = 0x800
    if parts:
        try:
            max_frames = int(parts[0], 0)
        except ValueError:
            pass
    if len(parts) > 1:
        try:
            scan_bytes = int(parts[1], 0)
        except ValueError:
            pass

    regs = session.get_context()
    rip = session.current_pc
    rsp = regs.get("Rsp", 0)
    if not rsp:
        error("Cannot read RSP")
        return None

    modules = _walk_module_list(session)
    if not modules:
        error("Module list unavailable — try `lm` first")
        return None

    frames = scan_backtrace(session, rsp, modules, max_frames, scan_bytes)

    banner(f"BACKTRACE  RIP={rip:#x}  RSP={rsp:#x}")

    # Frame 0: current PC
    rip_label = ""
    for dll_base, size, ep, bname, _ in modules:
        if dll_base <= rip < dll_base + size:
            rip_label = f"{bname}+{rip - dll_base:#x}"
            break
    if not rip_label:
        rip_label = "<unknown>"

    text = Text()
    text.append(" #0 ", style="bold bright_yellow")
    text.append(f"{rip:#018x}", style="bright_cyan")
    text.append(f"  {rip_label}", style="bold bright_green")
    text.append("    (current)", style="bright_black")
    console.print(text)

    if not frames:
        warn("No return addresses found on stack — try increasing scan_bytes")
        return None

    for idx, f in enumerate(frames, start=1):
        text = Text()
        text.append(f" #{idx:<2d} ", style="bold bright_yellow")
        text.append(f"{f['value']:#018x}", style="bright_cyan")
        text.append(f"  {f['module']}+{f['mod_offset']:#x}", style="bright_green")
        text.append(f"    [rsp+{f['offset']:#x}]", style="bright_black")
        console.print(text)
    return None


# ---------------------------------------------------------------------------
# kdxinfo — classify a kernel address
# ---------------------------------------------------------------------------

def cmd_kdxinfo(debugger, args):
    """Show what region of kernel address space an address lives in.

    Usage: kdxinfo <addr|module+offset|reg+offset>
    """
    from .kd_cmds import _get_session, _kd_eval_expr, _cached_modules, _walk_module_list

    session = _get_session()
    if session is None:
        return None

    expr = args.strip()
    if not expr:
        error("Usage: kdxinfo <address>")
        return None

    addr = _kd_eval_expr(expr, session)
    if addr is None:
        error(f"Cannot resolve: {expr}")
        return None

    # Make sure modules are loaded for classification
    modules = _cached_modules
    if modules is None and session.stopped:
        modules = _walk_module_list(session)

    region, detail = classify(addr, modules)

    banner(f"Address info: {addr:#x}")
    text = Text()
    text.append("  Region : ", style="bold")
    text.append(region, style="bold bright_yellow")
    console.print(text)

    text = Text()
    text.append("  Detail : ", style="bold")
    text.append(detail, style="white")
    console.print(text)

    # If it's in a module, also show that module's range
    if modules:
        for dll_base, size, ep, bname, fpath in modules:
            if dll_base <= addr < dll_base + size:
                text = Text()
                text.append("  Module : ", style="bold")
                text.append(f"{bname}", style="bold bright_green")
                text.append(f"  [{dll_base:#x} – {dll_base + size:#x})", style="bright_cyan")
                console.print(text)
                if fpath and fpath.lower() != bname.lower():
                    console.print(Text(f"  Path   : {fpath}", style="bright_black"))
                break

    # Try to read a few bytes there
    if session.stopped:
        sample = session.read_virtual(addr, 16)
        if sample:
            hex_str = " ".join(f"{b:02x}" for b in sample)
            ascii_str = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in sample)
            text = Text()
            text.append("  Bytes  : ", style="bold")
            text.append(hex_str, style="white")
            text.append(f"  |{ascii_str}|", style="bright_green")
            console.print(text)

            # If it dereferences to a pointer, show what it points to
            if len(sample) >= 8:
                ptr_val = struct.unpack_from("<Q", sample, 0)[0]
                if ptr_val >= 0xFFFF800000000000:
                    sub_region, sub_detail = classify(ptr_val, modules)
                    text = Text()
                    text.append("  As ptr : ", style="bold")
                    text.append(f"{ptr_val:#x}", style="bright_cyan")
                    text.append(f"  → {sub_region}", style="bright_yellow")
                    console.print(text)
        else:
            warn("Cannot read memory at this address (unmapped or paged out)")

    return None
