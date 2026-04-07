"""Memory display commands: stack, telescope, vmmap."""

import struct

from ..display.formatters import (
    display_stack, display_telescope, error, console, banner,
)
from rich.text import Text


def _kd_session():
    """Return active KD session or None."""
    from .kd_cmds import _kd_session as s
    return s if s and s.connected else None


def _kd_telescope(session, addr, depth, chain_depth=3):
    """Build telescope chains by reading kernel memory and following pointers.

    Matches userland telescope quality:
    - Deep pointer chain following (up to chain_depth levels)
    - UTF-16 string detection (Windows kernel uses UNICODE_STRING)
    - ASCII string detection
    - Disassembly for executable-looking pointers
    - Permission-based coloring via kernel module cache

    Batched network strategy (minimizes RTTs):
    - Phase 0: 1 RTT bulk-read all stack slots
    - Phase 1..N: for each chain level, batch ALL dereference targets
      into merged page-aligned reads (typically 2-4 RTTs per level)
    Total: ~3-7 RTTs instead of 8-32 sequential RTTs.
    """
    ptr_size = session.ptr_size
    fmt = "<Q" if ptr_size == 8 else "<I"
    max_addr = 0xffff_ffff_ffff_ffff if ptr_size == 8 else 0xffff_ffff

    # --- Helpers (pure local, no network) ---

    def _is_plausible_ptr(v):
        if v <= 0x1000 or v > max_addr:
            return False
        if ptr_size == 8:
            return (0xFFFF800000000000 <= v) or (0x10000 <= v <= 0x7FFFFFFFFFFF)
        return v >= 0x10000

    _mod_cache = None

    def _perm_for_addr(v):
        nonlocal _mod_cache
        if not _is_plausible_ptr(v):
            return ""
        if ptr_size == 8 and v < 0xFFFF800000000000:
            return ""  # userspace — can't query perms over GDB
        # Check kernel module cache for code sections
        if _mod_cache is None:
            from .kd_cmds import _cached_modules
            _mod_cache = _cached_modules or []
        for dll_base, size, ep, bname, _ in _mod_cache:
            if dll_base <= v < dll_base + size:
                return "r-x"
        return "rw-"

    def _detect_string(data):
        if not data or len(data) < 4:
            return False, ""
        # ASCII
        null_pos = data.find(b'\x00')
        if null_pos > 3:
            try:
                s = data[:null_pos].decode("ascii")
                if all(c.isprintable() or c in '\t\n\r' for c in s):
                    return True, s[:60]
            except (UnicodeDecodeError, ValueError):
                pass
        # UTF-16LE
        for j in range(0, min(len(data) - 1, 128), 2):
            if data[j] == 0 and data[j + 1] == 0:
                if j >= 4:
                    try:
                        s = data[:j].decode("utf-16-le")
                        if all(c.isprintable() or c in '\t\n\r' for c in s):
                            return True, s[:60]
                    except (UnicodeDecodeError, ValueError):
                        pass
                break
        return False, ""

    _md = None

    def _disasm_one(a, data):
        nonlocal _md
        if _md is None:
            try:
                from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
                mode = CS_MODE_64 if session.is_64bit else CS_MODE_32
                _md = Cs(CS_ARCH_X86, mode)
            except ImportError:
                return ""
        for insn in _md.disasm(data[:16], a):
            return f"{insn.mnemonic} {insn.op_str}".strip()
        return ""

    # --- Batch memory cache ---
    # Uses session page cache if available (GdbSession), else local cache.
    _has_session_cache = hasattr(session, 'prefetch_pages')

    if not _has_session_cache:
        _cache = {}  # page_base -> bytes (local fallback)

    def _bulk_prefetch(addrs, read_sz=128):
        """Batch-read pages covering all addresses + read_sz bytes."""
        pages_needed = set()
        for a in addrs:
            if _is_plausible_ptr(a):
                pages_needed.add(a & ~0xFFF)
                pages_needed.add((a + read_sz - 1) & ~0xFFF)
        if _has_session_cache:
            # Delegate to session's page cache (benefits from already-prefetched pages)
            session.prefetch_pages(pages_needed)
        else:
            # Local cache fallback
            pages_needed -= _cache.keys()
            if not pages_needed:
                return
            pages = sorted(pages_needed)
            i = 0
            while i < len(pages):
                start = pages[i]
                end = start + 0x1000
                while i + 1 < len(pages) and pages[i + 1] == end and end - start < 0x10000:
                    i += 1
                    end = pages[i] + 0x1000
                data = session.read_virtual(start, end - start)
                if data:
                    for off in range(0, len(data), 0x1000):
                        pg = start + off
                        if off + 0x1000 <= len(data):
                            _cache[pg] = data[off:off + 0x1000]
                i += 1

    def _read_cached(a, sz):
        """Read from cache, concatenating across page boundaries."""
        if _has_session_cache:
            return session.read_cached(a, sz)
        result = b""
        cur = a
        remaining = sz
        while remaining > 0:
            page = cur & ~0xFFF
            off = cur - page
            d = _cache.get(page)
            if not d:
                break
            avail = min(remaining, len(d) - off)
            if avail <= 0:
                break
            result += d[off:off + avail]
            cur += avail
            remaining -= avail
        if len(result) >= sz:
            return result
        # Cache miss / partial — fallback to direct read (1 RTT)
        return session.read_virtual(a, sz)

    # --- Phase 0: bulk-read all stack slots (1 RTT, or 0 if prefetched) ---
    read_fn = session.read_cached if _has_session_cache else session.read_virtual
    bulk_data = read_fn(addr, ptr_size * depth)
    if not bulk_data:
        bulk_data = b""

    slot_values = []
    for i in range(depth):
        off = i * ptr_size
        if off + ptr_size <= len(bulk_data):
            slot_values.append(struct.unpack_from(fmt, bulk_data, off)[0])
        else:
            slot_values.append(None)

    # --- Phase 1..N: level-by-level batched chain following ---
    # chains_wip[i] = list of (value, ...) entries built so far
    # frontier[i] = next value to dereference (or None if chain ended)
    chains_wip = []
    frontier = []  # current pointer to follow for each slot

    for i, val in enumerate(slot_values):
        if val is None:
            chains_wip.append([(None, "", "", False, "", "")])
            frontier.append(None)
        else:
            chains_wip.append([])
            frontier.append(val)

    seen_per_slot = [set() for _ in range(depth)]

    for level in range(chain_depth):
        # Collect all frontier addresses that need reading
        to_read = [v for v in frontier if v is not None and _is_plausible_ptr(v)]
        if not to_read:
            break

        # Batch prefetch all pages we need (few merged RTTs)
        _bulk_prefetch(to_read)

        # Now process each slot locally from cache
        new_frontier = []
        for i in range(depth):
            val = frontier[i]
            if val is None:
                new_frontier.append(None)
                continue
            if not _is_plausible_ptr(val):
                # Non-pointer value — record it and stop the chain
                chains_wip[i].append((val, "", "", False, "", ""))
                new_frontier.append(None)
                continue

            perm = _perm_for_addr(val)
            deref_data = _read_cached(val, 128)
            if not deref_data or len(deref_data) < ptr_size:
                chains_wip[i].append((val, "", perm, False, "", ""))
                new_frontier.append(None)
                continue

            # String detection
            is_str, str_val = _detect_string(deref_data)
            if is_str:
                chains_wip[i].append((val, "", perm, True, str_val, ""))
                new_frontier.append(None)
                continue

            # Disassembly for code pointers
            asm_str = ""
            if perm and "x" in perm:
                asm_str = _disasm_one(val, deref_data)

            chains_wip[i].append((val, "", perm, False, "", asm_str))

            # Follow pointer to next level
            next_val = struct.unpack_from(fmt, deref_data, 0)[0]
            if next_val in seen_per_slot[i] or next_val == val:
                new_frontier.append(None)
            else:
                seen_per_slot[i].add(val)
                new_frontier.append(next_val)

        frontier = new_frontier

    # Handle any remaining frontier values (chain ended at max depth)
    for i in range(depth):
        if frontier[i] is not None and _is_plausible_ptr(frontier[i]):
            val = frontier[i]
            perm = _perm_for_addr(val)
            chains_wip[i].append((val, "", perm, False, "", ""))
        if not chains_wip[i]:
            v = slot_values[i]
            chains_wip[i] = [(v if v is not None else 0, "", "", False, "", "")]

    return [(i * ptr_size, chains_wip[i]) for i in range(depth)]


def cmd_stack(debugger, args):
    """Show stack: stack [count]"""
    count = 8
    if args.strip():
        try:
            count = int(args.strip(), 0)
        except ValueError:
            error("Usage: stack [count]")
            return None

    kd = _kd_session()
    if kd:
        regs = kd.get_context()
        sp_key = "Rsp" if kd.is_64bit else "Esp"
        sp = regs.get(sp_key, 0)
        if not sp:
            error("Cannot read RSP")
            return None
        chains = _kd_telescope(kd, sp, count)
        display_telescope(chains, sp, kd.ptr_size, title="STACK")
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

    kd = _kd_session()

    if parts:
        addr_str = parts[0]
        addr = eval_expr(debugger, addr_str)
        if addr is None and kd:
            try:
                addr = int(addr_str, 0)
            except ValueError:
                pass
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
        if kd:
            regs = kd.get_context()
            sp_key = "Rsp" if kd.is_64bit else "Esp"
            addr = regs.get(sp_key, 0)
        else:
            from ..core.registers import get_context, get_sp
            th = debugger.get_active_thread_handle()
            if th:
                ctx = get_context(th, debugger.is_wow64)
                addr = get_sp(ctx, debugger.is_wow64)
            else:
                addr = 0

    if kd:
        # Auto-advance on repeat
        original_addr = addr
        block_size = depth * kd.ptr_size
        addr = debugger.track_examine("tel", original_addr, block_size)

        chains = _kd_telescope(kd, addr, depth)
        display_telescope(chains, addr, kd.ptr_size, base_addr=original_addr)
        return None

    # Userland path
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
