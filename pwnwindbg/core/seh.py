"""SEH (Structured Exception Handling) chain walker.

Two flavors:

* x86 — classic in-memory chain rooted at TIB.ExceptionList (fs:[0]). Each
  EXCEPTION_REGISTRATION_RECORD is { Next, Handler } — 8 bytes — terminated by
  Next == 0xFFFFFFFF. We walk this from the active thread's TEB.

* x64 — Microsoft moved away from in-memory chains. Exception handlers are
  registered in each module's `.pdata` section as RUNTIME_FUNCTION entries
  whose UNWIND_INFO carries an UNW_FLAG_EHANDLER / UNW_FLAG_UHANDLER. The
  unwinder finds them by RVA lookup at exception time. We mirror that:

    - `list_handlers_in_module(base, path)` walks the .pdata of a loaded
      module and returns every RUNTIME_FUNCTION whose unwind info exposes an
      ExceptionHandler RVA.
    - `find_handler_for_rip(modules, rip)` does the runtime lookup: it locates
      the module covering RIP, then binary-searches its handler list for the
      function whose [Begin, End) range contains the offset.

The handler RVA itself sits *after* the unwind codes inside UNWIND_INFO,
which pefile does not expose directly — so we read it ourselves with the
formula: handler_offset_in_ui = 4 + ((CountOfCodes + 1) & ~1) * 2.
"""

import pefile
import struct

from .memory import read_memory_safe, read_dword, read_ptr


# Unwind info flags
UNW_FLAG_EHANDLER = 0x01
UNW_FLAG_UHANDLER = 0x02
UNW_FLAG_CHAININFO = 0x04


# ---------------------------------------------------------------------------
# x86 SEH chain
# ---------------------------------------------------------------------------

SEH_CHAIN_END_32 = 0xFFFFFFFF


def walk_seh_x86(process_handle, teb_addr):
    """Walk the x86 EXCEPTION_REGISTRATION_RECORD chain from TIB.ExceptionList.

    Returns a list of dicts: {address, next, handler}. Empty list on
    failure or empty chain.
    """
    if not teb_addr:
        return []

    # On x86 TEB, NtTib.ExceptionList is the first field (offset 0)
    head = read_dword(process_handle, teb_addr)
    if head is None or head == SEH_CHAIN_END_32:
        return []

    chain = []
    visited = set()
    cur = head
    # Hard cap: an SEH chain longer than this is broken/under attack
    for _ in range(256):
        if cur == SEH_CHAIN_END_32 or cur == 0:
            break
        if cur in visited:
            break
        visited.add(cur)

        raw = read_memory_safe(process_handle, cur, 8)
        if not raw or len(raw) < 8:
            break
        nxt, handler = struct.unpack("<II", raw)
        chain.append({"address": cur, "next": nxt, "handler": handler})
        cur = nxt

    return chain


# ---------------------------------------------------------------------------
# x64 .pdata-based SEH
# ---------------------------------------------------------------------------

def _parse_pe_pdata(pe_path):
    """Open a PE on disk and parse its .pdata directory.

    Returns the parsed pefile.PE object, or None on failure. Caller must
    close it. We use fast_load + selective directory parsing to avoid the
    multi-second cost of full pefile.PE() on large modules like ntdll.
    """
    try:
        pe = pefile.PE(pe_path, fast_load=True)
    except Exception:
        return None
    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION']]
        )
    except Exception:
        pe.close()
        return None
    return pe


def _read_handler_rva(pe, unwind_rva, count_of_codes):
    """Pull the ExceptionHandler RVA out of UNWIND_INFO.

    UNWIND_INFO layout:
        +0 Version:Flags
        +1 SizeOfProlog
        +2 CountOfCodes
        +3 FrameRegister:FrameOffset
        +4 UnwindCode[CountOfCodes]   (2 bytes each, padded to 4-byte boundary)
        +X ExceptionHandler (ULONG)   if Flags & (EHANDLER|UHANDLER)
    """
    # Align CountOfCodes up to even (each pair = 4 bytes total)
    aligned_codes = (count_of_codes + 1) & ~1
    handler_off = 4 + aligned_codes * 2
    try:
        return pe.get_dword_at_rva(unwind_rva + handler_off)
    except Exception:
        return None


def list_handlers_in_module(module_base, module_path, max_count=None):
    """Return list of {begin, end, handler, flags} for the module's .pdata.

    `begin`, `end`, `handler` are absolute (runtime) addresses. Returns []
    on parse failure.
    """
    pe = _parse_pe_pdata(module_path)
    if pe is None:
        return []

    handlers = []
    try:
        entries = getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", None) or []
        for rf in entries:
            ui = rf.unwindinfo
            if ui is None:
                continue
            flags = ui.Flags
            if not (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)):
                continue
            handler_rva = _read_handler_rva(pe, rf.struct.UnwindData,
                                            ui.CountOfCodes)
            if handler_rva is None:
                continue
            handlers.append({
                "begin": module_base + rf.struct.BeginAddress,
                "end": module_base + rf.struct.EndAddress,
                "handler": module_base + handler_rva,
                "flags": flags,
            })
            if max_count and len(handlers) >= max_count:
                break
    finally:
        pe.close()

    return handlers


def list_runtime_functions(module_base, module_path):
    """Return raw RUNTIME_FUNCTION list (no handler filter).

    Each entry is {begin, end, unwind_rva}. Useful for `find_function_at`.
    """
    pe = _parse_pe_pdata(module_path)
    if pe is None:
        return []
    out = []
    try:
        entries = getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", None) or []
        for rf in entries:
            out.append({
                "begin": module_base + rf.struct.BeginAddress,
                "end": module_base + rf.struct.EndAddress,
                "unwind_rva": rf.struct.UnwindData,
            })
    finally:
        pe.close()
    return out


# ---------------------------------------------------------------------------
# x64 stack unwinder built on UNWIND_INFO codes
# ---------------------------------------------------------------------------

# UnwindOp values from winnt.h
UWOP_PUSH_NONVOL     = 0
UWOP_ALLOC_LARGE     = 1
UWOP_ALLOC_SMALL     = 2
UWOP_SET_FPREG       = 3
UWOP_SAVE_NONVOL     = 4
UWOP_SAVE_NONVOL_FAR = 5
UWOP_SAVE_XMM128     = 8
UWOP_SAVE_XMM128_FAR = 9
UWOP_PUSH_MACHFRAME  = 10


def _compute_stack_delta_from_unwind(unwind_bytes):
    """Sum the stack adjustments encoded in an UNWIND_INFO blob.

    Returns (total_bytes, chained_runtime_function_rva or None).

    `unwind_bytes` must be the raw UNWIND_INFO starting at the Version:Flags
    byte. We assume RIP is past the function's full prolog — i.e. every
    unwind code applies — which is the common case for any non-leaf frame.
    Codes are walked in declaration order; the actual semantics is "in
    reverse for unwinding", but for *summing* deltas the order is irrelevant.
    """
    if len(unwind_bytes) < 4:
        return 0, None

    ver_flags = unwind_bytes[0]
    flags = ver_flags >> 3
    count_of_codes = unwind_bytes[2]
    codes_off = 4

    total = 0
    i = 0
    while i < count_of_codes:
        slot_off = codes_off + i * 2
        if slot_off + 2 > len(unwind_bytes):
            break
        # CodeOffset = unwind_bytes[slot_off]   (unused — past-prolog assumption)
        opcode_byte = unwind_bytes[slot_off + 1]
        op = opcode_byte & 0x0F
        op_info = (opcode_byte >> 4) & 0x0F

        if op == UWOP_PUSH_NONVOL:
            total += 8
            slots = 1
        elif op == UWOP_ALLOC_LARGE:
            if op_info == 0:
                # Next slot holds size in qwords
                if slot_off + 4 > len(unwind_bytes):
                    break
                size_qw = unwind_bytes[slot_off + 2] | (unwind_bytes[slot_off + 3] << 8)
                total += size_qw * 8
                slots = 2
            else:
                # Next two slots hold full byte size
                if slot_off + 6 > len(unwind_bytes):
                    break
                size = (unwind_bytes[slot_off + 2]
                        | (unwind_bytes[slot_off + 3] << 8)
                        | (unwind_bytes[slot_off + 4] << 16)
                        | (unwind_bytes[slot_off + 5] << 24))
                total += size
                slots = 3
        elif op == UWOP_ALLOC_SMALL:
            total += (op_info + 1) * 8
            slots = 1
        elif op == UWOP_SET_FPREG:
            slots = 1
        elif op == UWOP_SAVE_NONVOL:
            slots = 2
        elif op == UWOP_SAVE_NONVOL_FAR:
            slots = 3
        elif op == UWOP_SAVE_XMM128:
            slots = 2
        elif op == UWOP_SAVE_XMM128_FAR:
            slots = 3
        elif op == UWOP_PUSH_MACHFRAME:
            # 0 = no error code (5*8), 1 = with error code (6*8)
            total += 0x30 if op_info else 0x28
            slots = 1
        else:
            # Unknown op — bail out, we'd be guessing
            return 0, None

        i += slots

    chained_rva = None
    if flags & UNW_FLAG_CHAININFO:
        # Skip codes (rounded to even count for alignment) — chained
        # RUNTIME_FUNCTION sits right after.
        aligned_codes = (count_of_codes + 1) & ~1
        chain_off = codes_off + aligned_codes * 2
        if chain_off + 12 <= len(unwind_bytes):
            # We don't have the parent module base here, just return the offset
            # so the caller can dispatch a recursive lookup.
            chained_rva = chain_off

    return total, chained_rva


def unwind_one_frame_x64(read_mem_fn, modules, rip, rsp):
    """Unwind a single x64 frame.

    `read_mem_fn(addr, size)` reads bytes from the target.
    `modules` is the list of loaded modules.
    Returns (caller_rip, caller_rsp) or (None, None) if the frame can't be
    resolved (leaf function, no .pdata coverage, or read failure).
    """
    # Find the module containing RIP
    target_mod = None
    for m in modules:
        if m.base_address <= rip < m.end_address:
            target_mod = m
            break
    if target_mod is None:
        return None, None

    rfs = list_runtime_functions(target_mod.base_address, target_mod.path)
    if not rfs:
        return None, None

    # Find covering RUNTIME_FUNCTION
    rf = None
    for cand in rfs:
        if cand["begin"] <= rip < cand["end"]:
            rf = cand
            break
    if rf is None:
        # Leaf function: no .pdata entry. RA is at [rsp].
        ra = read_mem_fn(rsp, 8)
        if ra is None or len(ra) < 8:
            return None, None
        import struct
        return struct.unpack("<Q", ra)[0], rsp + 8

    # Read the UNWIND_INFO blob from the loaded module's memory
    ui_addr = target_mod.base_address + rf["unwind_rva"]
    ui_bytes = read_mem_fn(ui_addr, 64)  # most are <32B; 64 covers the long ones
    if not ui_bytes or len(ui_bytes) < 4:
        return None, None

    delta, _chained = _compute_stack_delta_from_unwind(ui_bytes)
    # Note: chained unwind info would need recursion. Most prologs don't
    # use it, so v1 ignores it and we accept some accuracy loss.

    # The return address is right above the saved registers + stack alloc
    ra_addr = rsp + delta
    ra_bytes = read_mem_fn(ra_addr, 8)
    if not ra_bytes or len(ra_bytes) < 8:
        return None, None
    import struct
    caller_rip = struct.unpack("<Q", ra_bytes)[0]
    caller_rsp = ra_addr + 8
    return caller_rip, caller_rsp


def backtrace_x64(read_mem_fn, modules, rip, rsp, max_frames=32):
    """Walk frames using .pdata UNWIND_INFO. Returns list of (idx, rip)."""
    frames = [(0, rip)]
    cur_rip, cur_rsp = rip, rsp
    seen = set()
    for i in range(1, max_frames):
        cur_rip, cur_rsp = unwind_one_frame_x64(read_mem_fn, modules, cur_rip, cur_rsp)
        if cur_rip is None or cur_rip == 0:
            break
        if cur_rip in seen:
            break
        seen.add(cur_rip)
        if cur_rip < 0x10000:
            break
        frames.append((i, cur_rip))
    return frames


def find_handler_for_address(modules, rip):
    """Find the SEH handler protecting `rip`, if any.

    `modules` is a list of objects exposing .base_address, .end_address, .path
    (matches SymbolManager.ModuleInfo). Returns dict {module, begin, end,
    handler, flags} or None.
    """
    # 1. Find the covering module
    target_mod = None
    for m in modules:
        if m.base_address <= rip < m.end_address:
            target_mod = m
            break
    if target_mod is None:
        return None

    handlers = list_handlers_in_module(target_mod.base_address, target_mod.path)
    if not handlers:
        return None

    # 2. Linear scan — handler ranges are sorted by begin in .pdata so
    #    we could binary search, but typical .pdata has < 5000 entries and
    #    this only runs on user request.
    for h in handlers:
        if h["begin"] <= rip < h["end"]:
            return {"module": target_mod, **h}
    return None
