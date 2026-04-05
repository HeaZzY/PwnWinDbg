"""Memory display commands: stack, telescope, vmmap."""

from ..display.formatters import (
    display_stack, display_telescope, error, console,
)


def cmd_stack(debugger, args):
    """Show stack: stack [count]"""
    count = 8
    if args.strip():
        try:
            count = int(args.strip(), 0)
        except ValueError:
            error("Usage: stack [count]")
            return None

    from ..core.registers import get_context, get_sp
    th = debugger.get_active_thread_handle()
    if not th:
        error("Cannot read stack")
        return None
    ctx = get_context(th, debugger.is_wow64)
    sp = get_sp(ctx, debugger.is_wow64)

    chains = debugger.telescope(address=sp, depth=count)
    if not chains:
        error("Cannot read stack")
        return None

    display_telescope(chains, sp, debugger.ptr_size, title="STACK")
    return None


def cmd_telescope(debugger, args):
    """Telescope / pointer chain dereference: tel [addr] [depth]"""
    from ..utils.addr_expr import eval_expr
    parts = args.strip().split()
    addr = None
    depth = 8

    if parts:
        addr_str = parts[0]
        addr = eval_expr(debugger, addr_str)
        if addr is None:
            error(f"Cannot resolve: {addr_str}")
            return None
        if len(parts) > 1:
            try:
                depth = int(parts[1], 0)
            except ValueError:
                pass

    # If no addr given, use SP
    if addr is None:
        from ..core.registers import get_context, get_sp
        th = debugger.get_active_thread_handle()
        if th:
            ctx = get_context(th, debugger.is_wow64)
            addr = get_sp(ctx, debugger.is_wow64)
        else:
            addr = 0

    # Auto-advance on repeat
    original_addr = addr
    block_size = depth * debugger.ptr_size
    addr = debugger.track_examine("tel", original_addr, block_size)

    chains = debugger.telescope(address=addr, depth=depth)
    display_telescope(chains, addr, debugger.ptr_size, base_addr=original_addr)
    return None


def cmd_p2p(debugger, args):
    """Find pointers from one module/region that point into another.

    Usage:
        p2p <source_module> <target_module>   — scan source for pointers into target
        p2p <address>                         — deep pointer chain from address
    Examples:
        p2p ch72.exe ntdll.dll
        p2p 0x401000
    """
    from ..utils.addr_expr import eval_expr
    from ..core.memory import read_memory_safe, enumerate_memory_regions
    from ..utils.constants import MEM_COMMIT
    from ..display.formatters import banner, info, success
    from rich.text import Text
    import struct

    parts = args.strip().split()
    if not parts:
        error("Usage: p2p <source> <target>  or  p2p <address>")
        return None

    # Single address mode: deep telescope chain
    if len(parts) == 1:
        addr = eval_expr(debugger, parts[0])
        if addr is None:
            error(f"Cannot resolve: {parts[0]}")
            return None
        chains = debugger.telescope(address=addr, depth=1, chain_depth=10)
        if chains:
            display_telescope(chains, addr, debugger.ptr_size)
        return None

    # Two-arg mode: scan source for pointers into target
    # Source/target can be module names OR addresses (resolved to their memory region)
    from ..core.memory import virtual_query

    def _find_module(name):
        name_lower = name.lower()
        stem = name_lower.rsplit('.', 1)[0]
        for mod in debugger.symbols.modules:
            mod_lower = mod.name.lower()
            mod_stem = mod_lower.rsplit('.', 1)[0]
            if mod_lower == name_lower or mod_stem == stem:
                return mod.name, mod.base_address, mod.end_address
        return None

    def _resolve_range(token):
        """Resolve a module name or address to (label, start, end)."""
        # Try module first
        mod = _find_module(token)
        if mod:
            return mod
        # Try as address → use its memory region
        addr = eval_expr(debugger, token)
        if addr is not None:
            mbi = virtual_query(debugger.process_handle, addr)
            if mbi and mbi.State == MEM_COMMIT:
                base = mbi.BaseAddress
                if hasattr(base, 'value'):
                    base = base.value or 0
                end = base + mbi.RegionSize
                return f"region@{base:#x}", base, end
        return None

    src = _resolve_range(parts[0])
    if src is None:
        error(f"Cannot resolve '{parts[0]}' to a module or memory region")
        return None

    tgt = _resolve_range(parts[1])
    if tgt is None:
        error(f"Cannot resolve '{parts[1]}' to a module or memory region")
        return None

    src_name, src_start, src_end = src
    tgt_name, tgt_start, tgt_end = tgt

    info(f"Scanning [bold]{src_name}[/bold] ({src_start:#x}-{src_end:#x}) "
         f"for pointers into [bold]{tgt_name}[/bold] ({tgt_start:#x}-{tgt_end:#x})...")

    ptr_size = debugger.ptr_size
    ptr_fmt = "<Q" if ptr_size == 8 else "<I"
    addr_fmt = "0x{:016x}" if ptr_size == 8 else "0x{:08x}"

    results = []

    # Read source memory in region-sized chunks
    for base, mbi in enumerate_memory_regions(debugger.process_handle):
        if mbi.State != MEM_COMMIT:
            continue
        region_end = base + mbi.RegionSize
        # Check overlap with source range
        if base >= src_end or region_end <= src_start:
            continue
        start = max(base, src_start)
        end = min(region_end, src_end)
        if end <= start:
            continue

        data = read_memory_safe(debugger.process_handle, start, end - start)
        if not data:
            continue

        # Scan for pointer-aligned values that fall within target range
        for off in range(0, len(data) - ptr_size + 1, ptr_size):
            val = struct.unpack_from(ptr_fmt, data, off)[0]
            if tgt_start <= val < tgt_end:
                results.append((start + off, val))

    if not results:
        error(f"No pointers from {src_name} into {tgt_name}")
        return None

    banner(f"p2p {src_name} → {tgt_name}")

    for ptr_addr, val in results:
        text = Text()
        text.append(addr_fmt.format(ptr_addr), style="bright_cyan")

        # Label for source address
        src_sym = debugger.symbols.resolve_address(ptr_addr)
        if src_sym:
            text.append(f" ({src_sym})", style="bright_magenta")

        text.append(" —▸ ", style="bold bright_yellow")
        text.append(addr_fmt.format(val), style="bold red")

        # Label for target address
        tgt_sym = debugger.symbols.resolve_address(val)
        if tgt_sym:
            text.append(f" ({tgt_sym})", style="bright_magenta")

        # If target is executable, show first instruction
        mbi = virtual_query(debugger.process_handle, val)
        if mbi and mbi.State == MEM_COMMIT and (mbi.Protect & 0xF0):
            code = read_memory_safe(debugger.process_handle, val, 16)
            if code:
                from ..core.disasm import disassemble_at
                insns = disassemble_at(debugger.disassembler, code, val, 1)
                if insns:
                    _, _, mnem, ops = insns[0]
                    asm = f"{mnem} {ops}".strip()
                    text.append(f" ◂ {asm}", style="bright_yellow")

        console.print(text)

    success(f"Found {len(results)} pointer(s)")
    return None
