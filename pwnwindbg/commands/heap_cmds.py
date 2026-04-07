"""Windows heap analysis commands.

Commands:
    heap                    — list all heaps in process
    chunks [heap_addr]      — list chunks in heap
    bins [heap_addr]        — show free bins/buckets
    vis [heap_addr]         — visual heap layout (like pwndbg)
    find-chunks <criteria>  — search for specific chunks
    segheap [heap_addr]     — inspect a Win10/11 _SEGMENT_HEAP
"""

import struct

from ..core.heap import (
    WindowsHeapAnalyzer, HeapType, ChunkState, HEAP_ENTRY_SIZE,
    SEGMENT_HEAP_SIGNATURE,
)
from ..core.memory import read_memory_safe
from ..display.formatters import (
    error, info, success, warn, console, banner,
)
from rich.table import Table
from rich.text import Text


def cmd_heap(debugger, args):
    """List all heaps in the current process.

    Usage: heap

    Shows detected heaps with type, address, size, and flags.
    """
    if not debugger.process_id:
        error("No process attached")
        return None

    analyzer = WindowsHeapAnalyzer(debugger)
    heaps = analyzer.detect_heaps()

    if not heaps:
        warn("No heaps detected in process")
        return None

    banner(f"PROCESS HEAPS ({len(heaps)})")

    table = Table(show_header=True, border_style="cyan", header_style="bold bright_white")
    table.add_column("Index", style="bright_yellow", justify="right")
    table.add_column("Address", style="bright_cyan")
    table.add_column("Type", style="bold bright_green")
    table.add_column("Size", style="bright_white")
    table.add_column("Flags", style="bright_magenta")

    for i, heap in enumerate(heaps):
        flags_str = []
        if heap.heap_type == HeapType.NT_HEAP:
            if heap.lfh_enabled:
                flags_str.append("LFH")

        flags_display = " | ".join(flags_str) if flags_str else "-"

        # Size display
        if heap.size > 0x100000:
            size_str = f"{heap.size // 0x100000}MB"
        elif heap.size > 0x1000:
            size_str = f"{heap.size // 0x1000}KB"
        else:
            size_str = f"{heap.size}B"

        table.add_row(
            str(i),
            f"{heap.address:#x}",
            heap.heap_type.name,
            size_str,
            flags_display
        )

    console.print(table)
    console.print()

    # Show heap summary
    info("Use 'chunks <heap_addr>' to inspect individual heap chunks")
    info("Use 'vis <heap_addr>' for visual heap layout")

    return None


def cmd_chunks(debugger, args):
    """List chunks in a specific heap.

    Usage:
        chunks              — show chunks in default heap
        chunks <heap_addr>  — show chunks in specific heap
        chunks --all        — show chunks in all heaps
    """
    if not debugger.process_id:
        error("No process attached")
        return None

    analyzer = WindowsHeapAnalyzer(debugger)

    # Parse arguments
    parts = args.strip().split()

    if not parts:
        # Use default heap
        heaps = analyzer.detect_heaps()
        if not heaps:
            error("No heaps detected")
            return None
        target_heap = heaps[0].address
        heap_name = "default heap"
    elif parts[0] == "--all":
        # Show chunks from all heaps
        return _show_all_chunks(analyzer)
    else:
        # Specific heap address
        try:
            target_heap = int(parts[0], 0)
            heap_name = f"heap {target_heap:#x}"
        except ValueError:
            error(f"Invalid heap address: {parts[0]}")
            return None

    chunks = analyzer.get_chunks(target_heap)
    if not chunks:
        warn(f"No chunks found in {heap_name}")
        return None

    _display_chunks(chunks, heap_name)
    return None


def cmd_bins(debugger, args):
    """Show free bins/buckets in heap.

    Usage:
        bins              — show bins in default heap
        bins <heap_addr>  — show bins in specific heap
    """
    if not debugger.process_id:
        error("No process attached")
        return None

    analyzer = WindowsHeapAnalyzer(debugger)

    # Get target heap
    if args.strip():
        try:
            target_heap = int(args.strip(), 0)
        except ValueError:
            error(f"Invalid heap address: {args.strip()}")
            return None
    else:
        heaps = analyzer.detect_heaps()
        if not heaps:
            error("No heaps detected")
            return None
        target_heap = heaps[0].address

    # Get free chunks
    chunks = analyzer.get_chunks(target_heap)
    free_chunks = [c for c in chunks if c.state == ChunkState.FREE]

    if not free_chunks:
        warn(f"No free chunks in heap {target_heap:#x}")
        return None

    _display_bins(free_chunks, target_heap)
    return None


DEFAULT_VIS_BYTES = 0x400  # default window size (1KB) for `vis`


def cmd_vis(debugger, args):
    """pwndbg-style visual heap dump.

    Usage:
        vis                       — first 0x400 bytes of default heap chunks
        vis <heap_addr>           — first 0x400 bytes of given heap
        vis -n <bytes>            — first <bytes> bytes (hex/dec)
        vis --from <addr>         — start the window at <addr>
        vis --from <addr> -n <n>  — <n> bytes starting at <addr>
        vis --all                 — every chunk (verbose)
    """
    if not debugger.process_id:
        error("No process attached")
        return None

    analyzer = WindowsHeapAnalyzer(debugger)

    show_all = False
    size_limit = DEFAULT_VIS_BYTES
    start_addr = None
    target_heap = None

    from ..utils.addr_expr import eval_expr

    parts = args.strip().split()
    i = 0
    while i < len(parts):
        a = parts[i]
        if a == "--all":
            show_all = True
            i += 1
        elif a in ("-n", "--bytes"):
            if i + 1 >= len(parts):
                error(f"{a} requires a value")
                return None
            try:
                size_limit = int(parts[i + 1], 0)
            except ValueError:
                error(f"Invalid size: {parts[i + 1]}")
                return None
            i += 2
        elif a == "--from":
            if i + 1 >= len(parts):
                error("--from requires an address")
                return None
            start_addr = eval_expr(debugger, parts[i + 1])
            if start_addr is None:
                error(f"Cannot resolve address: {parts[i + 1]}")
                return None
            i += 2
        else:
            target_heap = eval_expr(debugger, a)
            if target_heap is None:
                error(f"Cannot resolve heap address: {a}")
                return None
            i += 1

    heaps = analyzer.detect_heaps()
    if not heaps:
        error("No heaps detected")
        return None

    if target_heap is None:
        heap_info = heaps[0]
        target_heap = heap_info.address
    else:
        heap_info = next((h for h in heaps if h.address == target_heap), None)
        if not heap_info:
            error(f"Heap {target_heap:#x} not found")
            return None

    chunks = analyzer.get_chunks(target_heap)
    if not chunks:
        warn(f"No chunks found in heap {target_heap:#x}")
        return None

    sorted_chunks = sorted(chunks, key=lambda c: c.address)

    # Filter by --from / window size
    if not show_all:
        # Each chunk's header begins HEAP_ENTRY_SIZE before chunk.address
        if start_addr is None:
            start_addr = sorted_chunks[0].address - HEAP_ENTRY_SIZE
        end_addr = start_addr + size_limit

        windowed = []
        for c in sorted_chunks:
            chunk_start = c.address - HEAP_ENTRY_SIZE
            if chunk_start >= end_addr:
                break
            if chunk_start < start_addr:
                continue
            windowed.append(c)
        sorted_chunks = windowed

        if not sorted_chunks:
            warn(f"No chunks in window {start_addr:#x}..{end_addr:#x}")
            return None

    _display_visual_heap(debugger, sorted_chunks, heap_info, len(chunks))
    return None


def cmd_find_chunks(debugger, args):
    """Find chunks matching specific criteria.

    Usage:
        find-chunks --size <size>           — find chunks of exact size
        find-chunks --min-size <size>       — find chunks at least this size
        find-chunks --max-size <size>       — find chunks at most this size
        find-chunks --free                  — find free chunks only
        find-chunks --busy                  — find allocated chunks only
        find-chunks --contains <string>     — find chunks containing string
        find-chunks --type <heap_type>      — filter by heap type (CRT, NT_HEAP, LFH)
        find-chunks --corrupted             — find potentially corrupted chunks

    Examples:
        find-chunks --size 64
        find-chunks --contains "password"
        find-chunks --free --min-size 100
    """
    if not debugger.process_id:
        error("No process attached")
        return None

    # Parse filters from arguments
    filters = {}
    parts = args.strip().split()
    i = 0

    while i < len(parts):
        arg = parts[i]

        if arg in ("--size", "--min-size", "--max-size"):
            if i + 1 >= len(parts):
                error(f"{arg} requires a value")
                return None
            try:
                value = int(parts[i + 1], 0)
                filters[arg[2:].replace("-", "_")] = value
                i += 2
            except ValueError:
                error(f"Invalid size: {parts[i + 1]}")
                return None

        elif arg == "--contains":
            if i + 1 >= len(parts):
                error("--contains requires a string")
                return None
            filters["contains"] = parts[i + 1]
            i += 2

        elif arg == "--free":
            filters["state"] = ChunkState.FREE
            i += 1

        elif arg == "--busy":
            filters["state"] = ChunkState.BUSY
            i += 1

        elif arg == "--corrupted":
            filters["state"] = ChunkState.CORRUPTED
            i += 1

        elif arg == "--type":
            if i + 1 >= len(parts):
                error("--type requires a heap type (CRT, NT_HEAP, LFH, SEGMENT)")
                return None
            type_name = parts[i + 1].upper()
            try:
                filters["heap_type"] = HeapType[type_name]
                i += 2
            except KeyError:
                error(f"Unknown heap type: {type_name}")
                return None
        else:
            error(f"Unknown filter: {arg}")
            return None

    if not filters:
        error("No search criteria specified. Use --help for options.")
        return None

    analyzer = WindowsHeapAnalyzer(debugger)
    matches = analyzer.find_chunks(**filters)

    if not matches:
        warn("No chunks found matching criteria")
        return None

    banner(f"MATCHING CHUNKS ({len(matches)})")
    _display_chunks(matches, "search results")
    return None


# ---- Helper functions ----

def _display_chunks(chunks, heap_name):
    """Display chunks in a table format."""
    banner(f"CHUNKS in {heap_name} ({len(chunks)})")

    table = Table(show_header=True, border_style="cyan", header_style="bold bright_white")
    table.add_column("Address", style="bright_cyan")
    table.add_column("Size", style="bright_yellow", justify="right")
    table.add_column("State", style="bold")
    table.add_column("Type", style="bright_green")
    table.add_column("Data Preview", style="bright_white")

    for chunk in chunks:
        # State coloring
        if chunk.state == ChunkState.BUSY:
            state_style = "green"
            state_text = "BUSY"
        elif chunk.state == ChunkState.FREE:
            state_style = "red"
            state_text = "FREE"
        else:
            state_style = "yellow"
            state_text = "CORRUPT"

        table.add_row(
            f"{chunk.address:#x}",
            f"{chunk.size}",
            Text(state_text, style=state_style),
            chunk.heap_type.name,
            chunk.data_preview
        )

    console.print(table)
    console.print()


def _display_bins(free_chunks, heap_addr):
    """Display free bins analysis (like pwndbg bins)."""
    banner(f"FREE BINS in heap {heap_addr:#x}")

    # Group by size for bin analysis
    bins = {}
    for chunk in free_chunks:
        size = chunk.size
        if size not in bins:
            bins[size] = []
        bins[size].append(chunk)

    if not bins:
        warn("No free chunks found")
        return

    table = Table(show_header=True, border_style="cyan", header_style="bold bright_white")
    table.add_column("Size", style="bright_yellow", justify="right")
    table.add_column("Count", style="bright_cyan", justify="right")
    table.add_column("Addresses", style="bright_white")

    for size in sorted(bins.keys()):
        chunks_list = bins[size]
        addresses = " → ".join(f"{c.address:#x}" for c in chunks_list[:5])
        if len(chunks_list) > 5:
            addresses += f" ... (+{len(chunks_list) - 5} more)"

        table.add_row(
            str(size),
            str(len(chunks_list)),
            addresses
        )

    console.print(table)
    console.print()


_VIS_COLORS = ["yellow", "cyan", "green", "magenta", "blue", "bright_yellow", "bright_cyan", "bright_green"]


def _display_visual_heap(debugger, chunks, heap_info, total_chunks):
    """pwndbg-style hexdump: per-chunk 16-byte rows, colored by chunk index.

    Each row: <addr>  <qword1>  <qword2>  <ascii>
    Free chunks are bright_red, busy chunks cycle through a color palette.
    Within a single chunk, runs of 3+ identical 16-byte rows are collapsed
    into a single "* (N identical rows)" line, GDB-style.
    """
    console.print(
        f"[bright_black]vis: {heap_info.name} @ {heap_info.address:#x} "
        f"({len(chunks)}/{total_chunks} chunks)[/]"
    )

    color_idx = 0
    for chunk in chunks:
        # Read the full chunk including its 16-byte _HEAP_ENTRY header
        header_addr = chunk.address - HEAP_ENTRY_SIZE
        raw = read_memory_safe(debugger.process_handle, header_addr, chunk.size)
        if not raw:
            continue

        if chunk.state == ChunkState.FREE:
            color = "bright_red"
        else:
            color = _VIS_COLORS[color_idx % len(_VIS_COLORS)]
            color_idx += 1

        # Group consecutive identical 16-byte rows
        rows = []
        for off in range(0, len(raw), 16):
            line = raw[off:off + 16]
            if len(line) < 16:
                line = line + b"\x00" * (16 - len(line))
            rows.append((header_addr + off, line))

        n = len(rows)
        i = 0
        while i < n:
            line_addr, line = rows[i]
            # Look ahead for identical rows
            j = i + 1
            while j < n and rows[j][1] == line:
                j += 1
            run_len = j - i

            # Always print the first row of the run
            q1 = struct.unpack("<Q", line[:8])[0]
            q2 = struct.unpack("<Q", line[8:16])[0]
            ascii_repr = "".join(chr(b) if 32 <= b < 127 else "." for b in line)
            console.print(
                f"[{color}]{line_addr:#018x}  {q1:#018x}  {q2:#018x}  {ascii_repr}[/]"
            )

            if run_len >= 3:
                # Skip the middle, print the marker, then the last row of the run
                # so the user still sees where the pattern ends.
                console.print(
                    f"[bright_black]* {run_len - 2} identical row(s) "
                    f"({(run_len - 2) * 16:#x} bytes)[/]"
                )
                last_addr, last_line = rows[j - 1]
                lq1 = struct.unpack("<Q", last_line[:8])[0]
                lq2 = struct.unpack("<Q", last_line[8:16])[0]
                lascii = "".join(chr(b) if 32 <= b < 127 else "." for b in last_line)
                console.print(
                    f"[{color}]{last_addr:#018x}  {lq1:#018x}  {lq2:#018x}  {lascii}[/]"
                )
                i = j
            elif run_len == 2:
                # Print the second one too — collapsing 2 saves nothing
                second_addr, second_line = rows[i + 1]
                sq1 = struct.unpack("<Q", second_line[:8])[0]
                sq2 = struct.unpack("<Q", second_line[8:16])[0]
                sascii = "".join(chr(b) if 32 <= b < 127 else "." for b in second_line)
                console.print(
                    f"[{color}]{second_addr:#018x}  {sq1:#018x}  {sq2:#018x}  {sascii}[/]"
                )
                i = j
            else:
                i = j


def _show_all_chunks(analyzer):
    """Show chunks from all heaps."""
    heaps = analyzer.detect_heaps()

    for heap in heaps:
        chunks = analyzer.get_chunks(heap.address)
        if chunks:
            _display_chunks(chunks, f"{heap.name} @ {heap.address:#x}")
        else:
            console.print(f"[bright_black]No chunks in {heap.name}[/]")
            console.print()

    return None


# ---------------------------------------------------------------------------
# segheap — Win10/11 _SEGMENT_HEAP inspection
# ---------------------------------------------------------------------------

def cmd_segheap(debugger, args):
    """Inspect a _SEGMENT_HEAP (Win10+ default for some processes).

    Usage:
        segheap                 — show all detected segment heaps
        segheap <addr>          — show one specific heap address
        segheap <addr> --large  — also walk LargeAllocMetadata RB tree
    """
    if not debugger.process_id:
        error("No process attached")
        return None

    parts = args.strip().split()
    target = None
    show_large = False
    for p in parts:
        if p == "--large":
            show_large = True
            continue
        try:
            target = int(p, 0)
        except ValueError:
            from ..utils.addr_expr import eval_expr
            target = eval_expr(debugger, p)
            if target is None:
                error(f"Invalid heap address: {p}")
                return None

    analyzer = WindowsHeapAnalyzer(debugger)

    targets = []
    if target is not None:
        targets = [target]
    else:
        for h in analyzer.detect_heaps():
            if h.heap_type == HeapType.SEGMENT:
                targets.append(h.address)
        if not targets:
            warn("No segment heaps detected in process")
            info("Win11's default heap is segment-heap-only for processes "
                 "with the appropriate manifest. test_heap.exe uses NT heap.")
            return None

    for addr in targets:
        info_obj = analyzer.read_segment_heap(addr)
        if info_obj is None:
            error(f"No _SEGMENT_HEAP at {addr:#x} "
                  f"(signature mismatch — expected {SEGMENT_HEAP_SIGNATURE:#x})")
            continue
        _display_segment_heap(info_obj)
        if show_large:
            allocs = analyzer.walk_segment_large_allocs(addr)
            _display_large_allocs(allocs, addr)
    return None


def _display_segment_heap(info_obj):
    """Print _SEGMENT_HEAP header fields."""
    banner(f"SEGMENT HEAP @ {info_obj.address:#x}")
    table = Table(show_header=True, border_style="cyan",
                  header_style="bold bright_white")
    table.add_column("Field", style="bold bright_white")
    table.add_column("Value", style="bright_cyan")
    table.add_column("Note", style="bright_black")

    table.add_row("Signature", f"{info_obj.signature:#x}",
                  "OK" if info_obj.signature == SEGMENT_HEAP_SIGNATURE else "MISMATCH")
    table.add_row("GlobalFlags", f"{info_obj.global_flags:#x}", "")
    table.add_row("Interceptor", f"{info_obj.interceptor:#x}",
                  "non-zero = page heap or hooked" if info_obj.interceptor else "")
    table.add_row("ProcessHeapListIndex",
                  f"{info_obj.process_heap_list_index}", "")
    table.add_row("LargeReservedPages",
                  f"{info_obj.large_reserved_pages:#x}",
                  f"= {info_obj.large_reserved_pages * 0x1000} bytes")
    table.add_row("LargeCommittedPages",
                  f"{info_obj.large_committed_pages:#x}",
                  f"= {info_obj.large_committed_pages * 0x1000} bytes")
    console.print(table)
    info("Backend / VS / LFH chunk walking is not supported (per-context "
         "encoded headers vary across builds). Use `segheap <addr> --large` "
         "to walk the LargeAllocMetadata RB tree.")


def _display_large_allocs(allocs, heap_addr):
    """Print large allocations from a segment heap."""
    if not allocs:
        warn(f"No large allocations in segment heap {heap_addr:#x}")
        return

    banner(f"LARGE ALLOCATIONS in segment heap {heap_addr:#x} ({len(allocs)})")
    table = Table(show_header=True, border_style="cyan",
                  header_style="bold bright_white")
    table.add_column("#", justify="right", style="bright_yellow")
    table.add_column("Address", style="bright_cyan")
    table.add_column("Size", justify="right", style="bright_white")
    table.add_column("UserSize", justify="right", style="bright_green")
    table.add_column("Metadata", style="bright_black")

    for i, a in enumerate(allocs):
        table.add_row(
            str(i),
            f"{a['address']:#x}",
            f"{a['size']:#x}",
            f"{a['user_size']:#x}",
            f"{a['metadata_addr']:#x}",
        )
    console.print(table)