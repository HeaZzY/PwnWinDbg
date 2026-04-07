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
