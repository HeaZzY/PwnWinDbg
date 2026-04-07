"""kdsearch — search for patterns in kernel memory.

Search is restricted to loaded kernel module ranges by default to avoid
scanning the entire 128 TB kernel address space (most of which is unmapped).
"""

import re

from ..display.formatters import (
    info, error, warn, success, console, banner,
)

from rich.text import Text


def _parse_search_args(args):
    """Parse: kdsearch [-s str | -x hex | -p ptr] [--module name]"""
    parts = args.split()
    mode = None
    pattern = None
    module_filter = None
    i = 0
    while i < len(parts):
        a = parts[i]
        if a == "-s" and i + 1 < len(parts):
            mode = "string"
            pattern = " ".join(parts[i + 1:])  # consume rest as the string
            return mode, pattern, module_filter
        if a == "-x" and i + 1 < len(parts):
            mode = "hex"
            pattern = parts[i + 1]
            i += 2
            continue
        if a == "-p" and i + 1 < len(parts):
            mode = "ptr"
            pattern = parts[i + 1]
            i += 2
            continue
        if a in ("-m", "--module") and i + 1 < len(parts):
            module_filter = parts[i + 1].lower()
            i += 2
            continue
        i += 1
    return mode, pattern, module_filter


def cmd_kdsearch(debugger, args):
    """Search for a pattern in kernel module memory.

    Usage:
        kdsearch -s <string>             — ASCII string
        kdsearch -x <hex>                — hex bytes (e.g. 4889e5)
        kdsearch -p <ptr>                — 8-byte little-endian pointer
        kdsearch -s foo --module ntoskrnl
        kdsearch -m hidclass -x cccccc

    Searches across all loaded kernel modules unless --module narrows it.
    """
    from .kd_cmds import _get_session, _walk_module_list

    session = _get_session()
    if session is None:
        return None
    if not session.stopped:
        error("Target is running. Break first.")
        return None

    mode, pattern, mod_filter = _parse_search_args(args.strip())
    if not mode or not pattern:
        error("Usage: kdsearch -s <str> | -x <hex> | -p <ptr> [--module name]")
        return None

    # Build the byte pattern
    if mode == "string":
        needle = pattern.encode("latin-1")
    elif mode == "hex":
        try:
            needle = bytes.fromhex(pattern.replace(" ", ""))
        except ValueError:
            error(f"Invalid hex: {pattern}")
            return None
    elif mode == "ptr":
        try:
            val = int(pattern, 0)
        except ValueError:
            error(f"Invalid pointer: {pattern}")
            return None
        needle = val.to_bytes(8, "little")
    else:
        return None

    if not needle:
        error("Empty pattern")
        return None

    modules = _walk_module_list(session)
    if not modules:
        error("Module list unavailable — try `lm` first")
        return None

    if mod_filter:
        modules = [m for m in modules if mod_filter in m[3].lower()]
        if not modules:
            warn(f"No module matching '{mod_filter}'")
            return None

    banner(f"kdsearch: {len(needle)}-byte pattern across {len(modules)} module(s)")

    use_pipelined = hasattr(session, "read_virtual_pipelined")
    total_hits = 0

    for dll_base, size, ep, bname, _ in modules:
        # Cap per-module size to avoid runaway reads
        max_size = min(size, 0x800000)  # 8 MB max per module
        info(f"  scanning {bname}  ({dll_base:#x} – {dll_base + max_size:#x})")
        if use_pipelined:
            data = session.read_virtual_pipelined(dll_base, max_size)
        else:
            data = session.read_virtual(dll_base, max_size)
        if not data:
            warn(f"    cannot read {bname}")
            continue

        hits = []
        start = 0
        while True:
            idx = data.find(needle, start)
            if idx < 0:
                break
            hits.append(idx)
            start = idx + 1
            if len(hits) > 64:
                break

        for idx in hits:
            addr = dll_base + idx
            text = Text()
            text.append(f"  {addr:#018x}  ", style="bright_cyan")
            text.append(f"{bname}+{idx:#x}", style="bold bright_green")
            # Show context
            ctx_start = max(0, idx - 4)
            ctx_end = min(len(data), idx + len(needle) + 4)
            ctx = data[ctx_start:ctx_end]
            hex_str = " ".join(f"{b:02x}" for b in ctx)
            text.append(f"  {hex_str}", style="bright_black")
            console.print(text)
            total_hits += 1

        if len(hits) > 64:
            warn(f"    …truncated, {len(hits)} hits in {bname}")

    success(f"Total: {total_hits} hits")
    return None
