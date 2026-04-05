"""
ROP gadget finder for Windows exploit development.

Scans executable memory regions for ROP gadgets by locating ret instructions
and disassembling backwards to find valid instruction chains.
"""

import argparse

from ..core.memory import read_memory_safe, enumerate_memory_regions
from ..core.disasm import create_disassembler, disassemble_at, is_ret_instruction
from ..display.formatters import info, error, success, console, banner
from ..utils.constants import MEM_COMMIT
from rich.text import Text


# Page protection flags with execute permission
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

EXECUTABLE_PROTECTIONS = (
    PAGE_EXECUTE,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY,
)

# Instructions that break a ROP chain — gadgets containing these are unusable
BAD_MNEMONICS = {"int3", "call", "jmp", "jne", "je", "jb", "ja", "jl", "jg",
                 "jbe", "jae", "jle", "jge", "js", "jns", "jo", "jno", "jp",
                 "jnp", "jcxz", "jecxz", "jrcxz", "loop", "loope", "loopne",
                 "syscall", "sysenter", "int", "into", "ud2"}

# Maximum single x86 instruction size
MAX_INSN_SIZE = 15

# Default display limit
DEFAULT_MAX_DISPLAY = 500


def _is_executable(protect):
    """Check if a memory protection flag includes execute permission."""
    return (protect & 0xF0) in EXECUTABLE_PROTECTIONS


def _get_executable_regions(debugger, module_name=None):
    """
    Get executable memory regions, optionally filtered to a specific module.

    Returns list of (base_address, size) tuples.
    """
    regions = []

    if module_name:
        # Find the specific module
        target_module = None
        for mod in debugger.symbols.modules:
            if mod.name.lower() == module_name.lower():
                target_module = mod
                break

        if target_module is None:
            error(f"Module '{module_name}' not found")
            return regions

        # Enumerate memory regions within the module's address range
        for base, mbi in enumerate_memory_regions(debugger.process_handle):
            if mbi.State != MEM_COMMIT:
                continue
            if not _is_executable(mbi.Protect):
                continue
            region_base = base
            region_end = base + mbi.RegionSize
            mod_end = target_module.end_address

            # Check if this region overlaps with the module
            if region_base < mod_end and region_end > target_module.base_address:
                # Clamp to module boundaries
                start = max(region_base, target_module.base_address)
                end = min(region_end, mod_end)
                if end > start:
                    regions.append((start, end - start))

        if not regions:
            error(f"No executable regions found in module '{module_name}'")

    else:
        # All executable committed regions
        for base, mbi in enumerate_memory_regions(debugger.process_handle):
            if mbi.State != MEM_COMMIT:
                continue
            if not _is_executable(mbi.Protect):
                continue
            regions.append((base, mbi.RegionSize))

    return regions


def _find_gadgets(debugger, regions, depth=3):
    """
    Scan executable regions for ROP gadgets.

    For each ret instruction found, disassemble backwards up to `depth`
    instructions to find valid gadget chains.

    Returns dict mapping gadget_string -> list of addresses.
    """
    disassembler = debugger.disassembler
    max_back = depth * MAX_INSN_SIZE
    gadgets = {}  # gadget_str -> [addresses]

    for base, size in regions:
        data = read_memory_safe(debugger.process_handle, base, size)
        if data is None:
            continue

        # Find all ret positions: 0xC3 (ret) and 0xC2 (ret imm16)
        ret_positions = []
        for i in range(len(data)):
            if data[i] == 0xC3:
                ret_positions.append((i, 1))   # (offset, ret_size)
            elif data[i] == 0xC2 and i + 2 < len(data):
                ret_positions.append((i, 3))   # ret imm16 = 3 bytes

        for ret_offset, ret_size in ret_positions:
            ret_end = ret_offset + ret_size  # one past the last byte of ret

            for back in range(1, max_back + 1):
                start = ret_offset - back
                if start < 0:
                    continue

                chunk = data[start:ret_end]
                chunk_addr = base + start

                insns = disassemble_at(disassembler, bytes(chunk), chunk_addr, 20)
                if not insns:
                    continue

                # Verify the disassembled instructions exactly cover the chunk
                total_size = sum(sz for _, sz, _, _ in insns)
                if total_size != len(chunk):
                    continue

                # Last instruction must be a ret variant
                last_mnemonic = insns[-1][2].lower()
                if last_mnemonic not in ("ret", "retn", "retf"):
                    continue

                # Too many instructions for the requested depth
                # (depth is the max number of instructions *before* the ret)
                if len(insns) - 1 > depth:
                    continue

                # Filter out gadgets containing bad instructions (except the ret itself)
                has_bad = False
                for _, _, mnemonic, _ in insns[:-1]:
                    if mnemonic.lower() in BAD_MNEMONICS:
                        has_bad = True
                        break
                if has_bad:
                    continue

                # Build the gadget string
                parts = []
                for _, _, mnemonic, operands in insns:
                    if operands:
                        parts.append(f"{mnemonic} {operands}")
                    else:
                        parts.append(mnemonic)
                gadget_str = " ; ".join(parts)

                gadget_addr = base + start

                if gadget_str not in gadgets:
                    gadgets[gadget_str] = []
                gadgets[gadget_str].append(gadget_addr)

    return gadgets


def cmd_rop(debugger, args):
    """Find ROP gadgets in executable memory regions."""
    parser = argparse.ArgumentParser(prog="rop", add_help=False)
    parser.add_argument("--module", "-m", type=str, default=None,
                        help="Search only in this module")
    parser.add_argument("--search", "-s", type=str, default=None,
                        help="Filter gadgets containing this string")
    parser.add_argument("--depth", "-d", type=int, default=3,
                        help="Max instructions before ret (default: 3)")
    parser.add_argument("--all", "-a", action="store_true",
                        help="Show all gadgets (no 500 limit)")

    import shlex
    try:
        arg_list = shlex.split(args) if isinstance(args, str) else args
    except ValueError:
        arg_list = args.split() if isinstance(args, str) else args

    try:
        parsed = parser.parse_args(arg_list)
    except SystemExit:
        error("Usage: rop [--module NAME] [--search PATTERN] [--depth N] [--all]")
        return

    if not debugger.process_handle:
        error("No process attached")
        return

    module_name = parsed.module
    search_filter = parsed.search
    depth = parsed.depth
    show_all = parsed.all

    # Collect executable regions
    if module_name:
        info(f"Scanning module [bold]{module_name}[/bold] for ROP gadgets (depth={depth})...")
    else:
        info(f"Scanning all executable regions for ROP gadgets (depth={depth})...")

    regions = _get_executable_regions(debugger, module_name)
    if not regions:
        return

    total_bytes = sum(sz for _, sz in regions)
    info(f"Scanning {len(regions)} region(s), {total_bytes:#x} bytes total...")

    # Find gadgets
    gadgets = _find_gadgets(debugger, regions, depth)

    if not gadgets:
        error("No gadgets found")
        return

    # Apply search filter
    if search_filter:
        search_lower = search_filter.lower()
        gadgets = {g: addrs for g, addrs in gadgets.items()
                   if search_lower in g.lower()}
        if not gadgets:
            error(f"No gadgets matching '{search_filter}'")
            return

    # Flatten to (address, gadget_str) and sort by address
    flat = []
    for gadget_str, addrs in gadgets.items():
        for addr in addrs:
            flat.append((addr, gadget_str))
    flat.sort(key=lambda x: x[0])

    # Remove duplicate (same address, same gadget)
    seen = set()
    unique = []
    for addr, gadget_str in flat:
        key = (addr, gadget_str)
        if key not in seen:
            seen.add(key)
            unique.append((addr, gadget_str))

    total_count = len(unique)

    # Apply display limit
    if not show_all and total_count > DEFAULT_MAX_DISPLAY:
        display_list = unique[:DEFAULT_MAX_DISPLAY]
        truncated = True
    else:
        display_list = unique
        truncated = False

    # Determine address format width
    is_64bit = not debugger.is_wow64
    addr_fmt = "0x{:016x}" if is_64bit else "0x{:08x}"

    # Display
    banner("ROP GADGETS")

    for addr, gadget_str in display_list:
        addr_str = addr_fmt.format(addr)

        line = Text()
        line.append(addr_str, style="bold cyan")
        line.append(" : ", style="dim")
        line.append(gadget_str, style="white")
        console.print(line)

    if truncated:
        info(f"Showing {DEFAULT_MAX_DISPLAY}/{total_count} gadgets. "
             f"Use --all to display all, or --search to filter.")

    unique_gadget_strings = len(gadgets)
    success(f"Found {total_count} gadgets ({unique_gadget_strings} unique sequences)")
