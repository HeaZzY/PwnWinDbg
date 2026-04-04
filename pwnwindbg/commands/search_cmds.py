"""
Memory search commands — search for patterns/bytes/strings across readable memory regions.
"""

import argparse
import struct
import re

from rich.text import Text

from ..core.memory import read_memory_safe, enumerate_memory_regions
from ..display.formatters import info, error, success, console, banner


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MEM_COMMIT = 0x1000

# PAGE_NOACCESS / PAGE_GUARD — regions we should skip outright
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100

# Chunk size when reading large regions (4 MB)
READ_CHUNK_SIZE = 4 * 1024 * 1024

# How many context bytes to show around a match
CONTEXT_BYTES = 8


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _protection_string(protect: int) -> str:
    """Return a short rwx-style protection string."""
    r = w = x = "-"

    # Readable pages
    readable = (
        0x02,  # PAGE_READONLY
        0x04,  # PAGE_READWRITE
        0x08,  # PAGE_WRITECOPY
        0x10,  # PAGE_EXECUTE
        0x20,  # PAGE_EXECUTE_READ
        0x40,  # PAGE_EXECUTE_READWRITE
        0x80,  # PAGE_EXECUTE_WRITECOPY
    )

    base = protect & 0xFF
    if base in readable:
        r = "r"

    # Writable pages
    writable = (0x04, 0x08, 0x40, 0x80)
    if base in writable:
        w = "w"

    # Executable pages
    executable = (0x10, 0x20, 0x40, 0x80)
    if base in executable:
        x = "x"

    return f"{r}{w}{x}"


def _is_readable(protect: int) -> bool:
    """Return True if the protection flags indicate the page is readable."""
    base = protect & 0xFF
    # Skip PAGE_NOACCESS (0x01) and unmapped (0x00)
    if base in (0x00, PAGE_NOACCESS):
        return False
    # Skip guarded pages
    if protect & PAGE_GUARD:
        return False
    return True


def _hex_dump_line(data: bytes, max_bytes: int = CONTEXT_BYTES) -> str:
    """Return a short hex dump of *data* (up to *max_bytes*)."""
    snippet = data[:max_bytes]
    return " ".join(f"{b:02x}" for b in snippet)


def _build_pattern(args) -> bytes | None:
    """Parse the user arguments and return the raw byte pattern to search for."""

    if args.string is not None:
        return args.string.encode("utf-8")

    if args.hex is not None:
        hex_str = args.hex.replace(" ", "").replace("\\x", "")
        if len(hex_str) % 2 != 0:
            error("Hex string must have an even number of characters")
            return None
        try:
            return bytes.fromhex(hex_str)
        except ValueError:
            error(f"Invalid hex string: {args.hex}")
            return None

    if args.pointer is not None:
        try:
            val = int(args.pointer, 0)
        except ValueError:
            error(f"Invalid pointer value: {args.pointer}")
            return None
        # Will be packed later with the correct pointer size
        return val  # special-cased in cmd_search

    if args.raw_bytes is not None:
        # Interpret Python-style escape sequences
        try:
            return args.raw_bytes.encode("utf-8").decode("unicode_escape").encode("latin-1")
        except Exception:
            error(f"Invalid byte string: {args.raw_bytes}")
            return None

    error("No search pattern specified. Use -s, -x, -p, or -b.")
    return None


def _format_match(addr: int, context_data: bytes, debugger, protect: int) -> Text:
    """Format a single search result line."""
    ptr_width = debugger.ptr_size * 2  # hex chars for an address

    # Resolve symbol / module info
    sym = debugger.symbols.resolve_address(addr)
    mod = debugger.symbols.get_module_at(addr)
    prot_str = _protection_string(protect)

    if sym:
        location = f"{sym} {prot_str}"
    elif mod:
        offset = addr - mod.base_address if hasattr(mod, "base_address") else 0
        name = mod.name if hasattr(mod, "name") else str(mod)
        location = f"{name}+{offset:#x} {prot_str}"
    else:
        location = prot_str

    hex_context = _hex_dump_line(context_data)

    line = Text()
    line.append(f"  0x{addr:0{ptr_width}x}", style="bold green")
    line.append(f"  ({location})", style="cyan")
    line.append(f"      {hex_context}", style="white")
    return line


# ---------------------------------------------------------------------------
# Region searching
# ---------------------------------------------------------------------------

def _search_region(process_handle, base: int, size: int, pattern: bytes):
    """
    Search a single memory region for *pattern*.

    Yields absolute addresses of every occurrence found.
    Reads in chunks to avoid huge single allocations.
    """
    offset = 0
    overlap = len(pattern) - 1  # overlap between chunks so we don't miss cross-boundary matches

    while offset < size:
        chunk_size = min(READ_CHUNK_SIZE, size - offset)
        data = read_memory_safe(process_handle, base + offset, chunk_size)
        if data is None:
            offset += chunk_size
            continue

        # Find all occurrences in this chunk
        start = 0
        while True:
            idx = data.find(pattern, start)
            if idx == -1:
                break
            yield base + offset + idx
            start = idx + 1  # move past this match

        # Advance, keeping an overlap so patterns spanning chunk boundaries are found
        if chunk_size < READ_CHUNK_SIZE:
            break  # last chunk
        offset += chunk_size - overlap


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="search",
        description="Search for a pattern in process memory",
        add_help=False,
    )
    # Optional address range
    parser.add_argument("start_addr", nargs="?", default=None,
                        help="Start address of region to search")
    parser.add_argument("end_addr", nargs="?", default=None,
                        help="End address of region to search")

    # Pattern type (mutually exclusive)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-s", "--string", dest="string", default=None,
                       help="ASCII string to search for")
    group.add_argument("-x", "--hex", dest="hex", default=None,
                       help="Hex byte sequence (e.g. 41414141)")
    group.add_argument("-p", "--pointer", dest="pointer", default=None,
                       help="Pointer value to search for (packed to 4/8 bytes)")
    group.add_argument("-b", "--bytes", dest="raw_bytes", default=None,
                       help="Raw byte string with escapes (e.g. \\x90\\x90)")

    parser.add_argument("-m", "--max", dest="max_results", type=int, default=256,
                        help="Maximum number of results to display (default: 256)")

    return parser


def _parse_address(value: str, debugger) -> int | None:
    """Parse an address from a string — accepts hex literals or symbol names."""
    if value is None:
        return None
    # Try as integer literal first
    try:
        return int(value, 0)
    except ValueError:
        pass
    # Try as symbol name
    resolved = debugger.symbols.resolve_name_to_address(value)
    if resolved is not None:
        return resolved
    error(f"Cannot resolve address: {value}")
    return None


# ---------------------------------------------------------------------------
# Main command handler
# ---------------------------------------------------------------------------

def cmd_search(debugger, args):
    """
    Search for a byte pattern across all readable memory regions
    (or a user-specified address range).
    """
    import shlex
    try:
        arg_list = shlex.split(args) if isinstance(args, str) else args
    except ValueError:
        arg_list = args.split() if isinstance(args, str) else args

    parser = _build_parser()
    try:
        parsed = parser.parse_args(arg_list)
    except SystemExit:
        return

    # ------------------------------------------------------------------
    # Build the search pattern
    # ------------------------------------------------------------------
    if parsed.pointer is not None:
        try:
            ptr_val = int(parsed.pointer, 0)
        except ValueError:
            error(f"Invalid pointer value: {parsed.pointer}")
            return
        fmt = "<Q" if debugger.ptr_size == 8 else "<I"
        pattern = struct.pack(fmt, ptr_val)
    else:
        pattern = _build_pattern(parsed)
        if pattern is None:
            return

    if len(pattern) == 0:
        error("Search pattern is empty")
        return

    # Friendly description of the pattern for output
    if parsed.string is not None:
        pat_desc = f'"{parsed.string}"'
    elif parsed.hex is not None:
        pat_desc = f"0x{parsed.hex}"
    elif parsed.pointer is not None:
        pat_desc = f"ptr {parsed.pointer}"
    elif parsed.raw_bytes is not None:
        pat_desc = f"bytes {parsed.raw_bytes}"
    else:
        pat_desc = pattern.hex()

    # ------------------------------------------------------------------
    # Determine which regions to search
    # ------------------------------------------------------------------
    process_handle = debugger.process_handle
    max_results = parsed.max_results
    results: list[tuple[int, bytes, int]] = []  # (address, context_bytes, protect)

    start_addr = _parse_address(parsed.start_addr, debugger)
    end_addr = _parse_address(parsed.end_addr, debugger)

    # Validate range if both provided
    if start_addr is not None and end_addr is not None and end_addr <= start_addr:
        error("End address must be greater than start address")
        return

    banner(f"Searching for {pat_desc} ({len(pattern)} bytes)")

    if start_addr is not None and end_addr is not None:
        # ----------------------------------------------------------
        # Search a specific address range
        # ----------------------------------------------------------
        region_size = end_addr - start_addr
        for match_addr in _search_region(process_handle, start_addr, region_size, pattern):
            # Read context bytes around match
            ctx = read_memory_safe(process_handle, match_addr, CONTEXT_BYTES)
            if ctx is None:
                ctx = pattern
            results.append((match_addr, ctx, 0))
            if len(results) >= max_results:
                break
    else:
        # ----------------------------------------------------------
        # Search all committed, readable regions
        # ----------------------------------------------------------
        for base_addr, mbi in enumerate_memory_regions(process_handle):
            if len(results) >= max_results:
                break

            # Only search committed pages
            if mbi.State != MEM_COMMIT:
                continue

            # Quick readability check
            if not _is_readable(mbi.Protect):
                continue

            region_base = base_addr
            region_size = mbi.RegionSize
            protect = mbi.Protect

            for match_addr in _search_region(process_handle, region_base, region_size, pattern):
                ctx = read_memory_safe(process_handle, match_addr, CONTEXT_BYTES)
                if ctx is None:
                    ctx = pattern
                results.append((match_addr, ctx, protect))
                if len(results) >= max_results:
                    break

    # ------------------------------------------------------------------
    # Display results
    # ------------------------------------------------------------------
    if not results:
        error(f"No matches found for {pat_desc}")
        return

    count_str = f"{len(results)}" if len(results) < max_results else f"{len(results)}+"
    success(f"Found {count_str} results for {pat_desc}")
    console.print()

    for addr, ctx_data, protect in results:
        line = _format_match(addr, ctx_data, debugger, protect)
        console.print(line)

    if len(results) >= max_results:
        info(f"Results limited to {max_results} — use -m to increase")
