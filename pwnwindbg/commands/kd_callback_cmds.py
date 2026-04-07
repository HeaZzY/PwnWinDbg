"""Kernel notification callback enumeration.

Commands:
    kdcallbacks  — enumerate Windows kernel notification callback arrays:
                     * nt!PspCreateProcessNotifyRoutine
                     * nt!PspCreateProcessNotifyRoutineEx
                     * nt!PspCreateThreadNotifyRoutine
                     * nt!PspLoadImageNotifyRoutine

Strategy
--------
The Psp* arrays are NOT exported from ntoskrnl. We locate each array by
disassembling the public registration function that *is* exported
(`PsSetCreateProcessNotifyRoutine`, etc.) and scanning the first ~512
bytes for any RIP-relative `lea r64, [rip+disp32]` or `mov rax, [rip+disp32]`
instructions. Each candidate target that lands inside the kernel image
is then validated by reading 64 EX_FAST_REF slots and counting how many
are non-zero — the real callback array is sparse (typically 1 to 30
populated entries), so we filter `0 < populated < 50` and prefer the
candidate with the lowest count when several pass.

Each EX_FAST_REF (8 bytes) encodes a pointer to an EX_CALLBACK_ROUTINE_BLOCK
in the upper bits and a refcount in the low 4 bits:

    typedef struct _EX_CALLBACK_ROUTINE_BLOCK {
        EX_RUNDOWN_REF  RundownProtect;   // +0x00 (8 bytes)
        PVOID           Function;          // +0x08  <-- the callback
        PVOID           Context;           // +0x10
    } EX_CALLBACK_ROUTINE_BLOCK;

So for each non-zero slot we mask the low 4 bits, follow the pointer,
read 8 bytes at +0x08, and that's the callback function pointer.
"""

import struct

import capstone

from ..display.formatters import (
    info, error, success, warn, console, banner,
)

from rich.table import Table


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Each callback array is fixed at 64 slots of 8 bytes (EX_FAST_REF)
_NUM_SLOTS = 64
_SLOT_SIZE = 8
_ARRAY_BYTES = _NUM_SLOTS * _SLOT_SIZE  # 512

# EX_FAST_REF: low 4 bits are the refcount, mask them off to get the pointer
_EX_FAST_REF_MASK = ~0xF & 0xFFFFFFFFFFFFFFFF

# Offset of the Function field inside _EX_CALLBACK_ROUTINE_BLOCK
_CB_BLOCK_FUNC_OFFSET = 0x08

# Maximum bytes to read for any one function body before giving up
_FN_READ_BYTES = 1024

# How many levels of `call` to follow when chasing the real Psp* helper.
# All four PsSetCreate*Notify exports on Win10/11 are tiny ~25-byte wrappers
# that immediately `call PspSet*` — so we need at least depth 1. Allow 2 for
# defence in depth on builds that add an extra hop.
_MAX_CALL_DEPTH = 2

# Sparse-array heuristic: a real callback array is rarely full. Empty arrays
# are also valid (e.g. PspCreateThreadNotifyRoutine on a fresh box with no
# AV/EDR), but they're indistinguishable from any other 512-byte zero region
# so we treat them as a *fallback* candidate — see `_find_callback_array`.
_MIN_POPULATED = 1
_MAX_POPULATED = 50

# Kernel image span around the base used to validate "looks like ntoskrnl"
_KERNEL_IMAGE_SPAN = 0x2000000  # 32 MiB — same as elsewhere in the codebase

# Lower bound for "this looks like a kernel virtual address"
_KERNEL_VA_BASE = 0xFFFF800000000000


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Module-level disassembler — capstone Cs() is heavyweight to construct,
# so reuse the same instance across all callback resolutions.
_cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
_cs.detail = False


def _walk_function_for_lea_targets(session, fn_addr: int, kernel_lo: int,
                                   kernel_hi: int, depth: int, visited: set):
    """Linearly disassemble a function and collect every RIP-relative target.

    Yields ``target_va`` integers in instruction order. Stops at the first
    `ret` / `int3` / unconditional `jmp` (function epilogue or tail call).
    When a `call` to a *direct* in-kernel target is encountered we recurse
    into it (subject to ``_MAX_CALL_DEPTH``), because all four
    `PsSetCreate*NotifyRoutine` exports are tiny wrappers that immediately
    call into the real `PspSet*` helper which holds the `lea` to the array.

    `visited` is a set of function addresses we've already walked, to avoid
    infinite recursion through mutually-recursive helpers.
    """
    if fn_addr in visited:
        return
    visited.add(fn_addr)

    code = session.read_virtual(fn_addr, _FN_READ_BYTES)
    if not code or len(code) < 8:
        return

    tail_calls = []   # collected for post-walk recursion (preserves yield order)

    for ins in _cs.disasm(code, fn_addr):
        mnem = ins.mnemonic

        # ----- collect lea/mov RIP-relative targets ------------------------
        # capstone gives us the resolved displacement target as ins.operands
        # only with detail=True. To stay cheap, parse the raw bytes for the
        # two patterns we care about — same encoding as the old scanner but
        # now anchored on real instruction starts so no false positives.
        ib = ins.bytes
        if len(ib) >= 7:
            b0, b1, b2 = ib[0], ib[1], ib[2]
            is_lea = (b0 in (0x48, 0x4C)) and b1 == 0x8D and (b2 & 0xC7) == 0x05
            is_mov = b0 == 0x48 and b1 == 0x8B and b2 == 0x05
            if is_lea or is_mov:
                disp32 = struct.unpack_from("<i", ib, 3)[0]
                target = (ins.address + 7 + disp32) & 0xFFFFFFFFFFFFFFFF
                if kernel_lo <= target < kernel_hi:
                    yield target

        # ----- track direct calls / jumps for recursion --------------------
        if mnem in ("call", "jmp"):
            # Direct relative branches show up with a numeric op_str.
            try:
                tgt = int(ins.op_str, 0)
            except (ValueError, TypeError):
                tgt = 0
            if tgt and kernel_lo <= tgt < kernel_hi:
                tail_calls.append(tgt)
            # An unconditional jmp / ret terminates the function body.
            if mnem == "jmp":
                break

        if mnem in ("ret", "int3"):
            break

    # ----- recurse into discovered call targets ----------------------------
    if depth + 1 <= _MAX_CALL_DEPTH:
        for tgt in tail_calls:
            yield from _walk_function_for_lea_targets(
                session, tgt, kernel_lo, kernel_hi, depth + 1, visited
            )


def _count_populated_slots(data: bytes):
    """Return ``(populated, kernel_like)`` slot counts for `data`.

    A "kernel-like" slot is one whose EX_FAST_REF, after masking the low 4
    bits, lands in the canonical x64 kernel half (≥ 0xFFFF800000000000).
    Real callback arrays have ALL of their populated slots pointing into
    the kernel pool, so the second number is what we actually filter on —
    `populated` is just for display.

    `data` must be exactly _ARRAY_BYTES long.
    """
    populated = 0
    kernel_like = 0
    for i in range(0, _ARRAY_BYTES, _SLOT_SIZE):
        slot = struct.unpack_from("<Q", data, i)[0]
        if slot == 0:
            continue
        populated += 1
        if (slot & _EX_FAST_REF_MASK) >= _KERNEL_VA_BASE:
            kernel_like += 1
    return populated, kernel_like


def _looks_like_kernel_va(addr: int) -> bool:
    """Cheap sanity check: is `addr` plausibly a kernel virtual address?"""
    return addr >= _KERNEL_VA_BASE


def _resolve_addr_to_module(addr: int, modules):
    """Map a kernel address to ``module!offset`` form, or None.

    `modules` is the list returned by `_walk_module_list` —
    tuples of `(dll_base, size, entry_point, base_name, full_name)`.
    """
    if not modules:
        return None
    for entry in modules:
        # Defensive unpacking: tuple shape may vary slightly
        if len(entry) < 4:
            continue
        dll_base = entry[0]
        size = entry[1]
        base_name = entry[3]
        if dll_base <= addr < dll_base + size:
            base_clean = base_name.replace(".sys", "").replace(".dll", "").replace(".exe", "")
            return f"{base_clean}!{addr - dll_base:#x}"
    return None


def _find_callback_array(session, kbase: int, export_name: str):
    """Locate a Psp* callback array starting from a public Ps* registration export.

    Returns ``(array_addr, array_data)`` on success or ``(0, None)`` on failure.

    Algorithm:
      1. Resolve the export RVA via `_find_export`.
      2. Linearly disassemble the export with capstone, following any `call`
         instructions one or two levels deep (`_MAX_CALL_DEPTH`). All four
         `PsSetCreate*Notify` exports on Win10/11 are tiny ~25-byte wrappers
         that immediately `call PspSet*` — the `lea` to the actual callback
         array lives inside that helper, never in the wrapper itself.
      3. Collect every RIP-relative `lea`/`mov rax` target encountered along
         the way, in instruction order.
      4. For each target, read 64*8 bytes and validate that it looks like a
         sparse EX_FAST_REF array (1 ≤ populated < 50, every populated slot
         masks down to a kernel VA).
      5. Return the FIRST target that passes — the order is meaningful since
         the helper's `lea` to its array is one of the first things it does.
    """
    from .kd_cmds import _find_export

    rva = _find_export(session, kbase, export_name)
    if not rva:
        return 0, None

    export_addr = kbase + rva
    kernel_lo = kbase
    kernel_hi = kbase + _KERNEL_IMAGE_SPAN

    # Walk the export wrapper + (up to depth 2) any helpers it calls into.
    # Preserve discovery order; deduplicate so we never validate the same
    # candidate twice.
    seen = set()
    ordered_targets = []
    for tgt in _walk_function_for_lea_targets(
        session, export_addr, kernel_lo, kernel_hi, depth=0, visited=set()
    ):
        if tgt in seen:
            continue
        seen.add(tgt)
        ordered_targets.append(tgt)

    if not ordered_targets:
        return 0, None

    # Walk candidates in code order; the first one whose 64-slot footprint
    # looks like a sparse EX_FAST_REF array of kernel pointers wins.
    #
    # Validation rule (strict): every populated slot must mask down to a
    # canonical kernel VA. Random kernel data near a function will have
    # qwords scattered across user/zero/garbage values, so requiring
    # `kernel_like == populated` cleanly rejects them.
    #
    # An EMPTY array (e.g. PspCreateThreadNotifyRoutine on a fresh box) is
    # exactly 512 bytes of 0x00. We can't distinguish it from any other
    # zero region by content alone, so it's only used as a *last resort*
    # fallback — we keep walking and only return it if no populated array
    # matched at all.
    empty_fallback = None
    empty_data = None

    for addr in ordered_targets:
        data = session.read_virtual(addr, _ARRAY_BYTES)
        if not data or len(data) < _ARRAY_BYTES:
            continue
        populated, kernel_like = _count_populated_slots(data)

        if populated == 0:
            # Remember the first all-zero candidate; if nothing populated
            # matches in this scan we'll fall back to it.
            if empty_fallback is None and data == b"\x00" * _ARRAY_BYTES:
                empty_fallback = addr
                empty_data = data
            continue

        if not (_MIN_POPULATED <= populated < _MAX_POPULATED):
            continue
        if kernel_like != populated:
            # At least one populated slot is NOT a kernel pointer — this
            # is data, not a callback array.
            continue
        return addr, data

    if empty_fallback is not None:
        return empty_fallback, empty_data

    return 0, None


def _enum_array_callbacks(session, array_data: bytes, modules):
    """Decode an EX_FAST_REF array into a list of callback descriptors.

    Returns a list of ``(slot_index, callback_addr_or_None, label)`` tuples
    for each non-zero slot. ``label`` is either ``module!offset`` or
    ``"<invalid>"``.
    """
    out = []
    for i in range(_NUM_SLOTS):
        slot = struct.unpack_from("<Q", array_data, i * _SLOT_SIZE)[0]
        if slot == 0:
            continue

        block_addr = slot & _EX_FAST_REF_MASK
        if not _looks_like_kernel_va(block_addr):
            out.append((i, None, "<invalid block ptr>"))
            continue

        fn_data = session.read_virtual(block_addr + _CB_BLOCK_FUNC_OFFSET, 8)
        if not fn_data or len(fn_data) < 8:
            out.append((i, None, "<unreadable>"))
            continue

        fn_addr = struct.unpack_from("<Q", fn_data, 0)[0]
        if not _looks_like_kernel_va(fn_addr):
            out.append((i, fn_addr, "<invalid fn ptr>"))
            continue

        label = _resolve_addr_to_module(fn_addr, modules) or "<unknown module>"
        out.append((i, fn_addr, label))
    return out


def _print_array(name: str, array_addr: int, callbacks):
    """Render one callback array as a Rich table under a banner.

    `callbacks` is the list returned by `_enum_array_callbacks`.
    """
    banner(f"{name} (located at {array_addr:#x})")

    if not callbacks:
        info("No callbacks registered.")
        return

    tbl = Table(show_header=True, border_style="cyan", header_style="bold bright_white")
    tbl.add_column("#", style="bright_yellow", justify="right")
    tbl.add_column("Callback Address", style="bright_cyan")
    tbl.add_column("Module", style="bold bright_green")

    for idx, fn_addr, label in callbacks:
        addr_col = f"{fn_addr:#x}" if fn_addr is not None else "-"
        tbl.add_row(str(idx), addr_col, label)
    console.print(tbl)
    info(f"{len(callbacks)} populated / {_NUM_SLOTS} total slots")


# ---------------------------------------------------------------------------
# kdcallbacks — enumerate kernel notification callbacks
# ---------------------------------------------------------------------------

# (Display name, registration export name)
_CALLBACK_TARGETS = [
    ("PspCreateProcessNotifyRoutine",   "PsSetCreateProcessNotifyRoutine"),
    ("PspCreateProcessNotifyRoutineEx", "PsSetCreateProcessNotifyRoutineEx"),
    ("PspCreateThreadNotifyRoutine",    "PsSetCreateThreadNotifyRoutine"),
    ("PspLoadImageNotifyRoutine",       "PsSetLoadImageNotifyRoutine"),
]


def cmd_kdcallbacks(debugger, args):
    """Enumerate Windows kernel notification callback arrays.

    Walks the four well-known Psp* notification arrays
    (process create, process create-Ex, thread create, image load) by
    disassembling their respective `Ps*` registration exports and following
    the first in-kernel RIP-relative target whose 64-slot footprint looks
    like a sparse EX_FAST_REF array.

    Each populated slot is decoded as an `EX_CALLBACK_ROUTINE_BLOCK*` whose
    `Function` field (offset +0x08) holds the actual callback. Callback
    addresses are resolved to `module!offset` form using the kernel module
    list when possible.
    """
    from .kd_ps_cmds import _get_session_and_system
    from .kd_cmds import _find_kernel_base, _walk_module_list

    session, _sys_eproc = _get_session_and_system()
    if session is None:
        return None

    kbase = _find_kernel_base(session)
    if not kbase:
        error("Cannot locate kernel base — try running `lm` first")
        return None

    # Module list — used purely for symbolisation. If unavailable we still
    # show raw addresses, so failure is non-fatal.
    try:
        modules = _walk_module_list(session)
    except Exception as exc:  # noqa: BLE001
        warn(f"Module list walk failed ({exc}) — addresses will be raw")
        modules = None
    if not modules:
        warn("No kernel modules — callback addresses will not be symbolised")

    # Dedupe by array address — on Win10/11 the Process and ProcessEx
    # registration paths funnel through the same `PspSetCreateProcessNotifyRoutine`
    # helper and use a single shared `PspCreateProcessNotifyRoutine` array
    # (the Ex flag is recorded inside the EX_CALLBACK_ROUTINE_BLOCK, not in
    # the array itself). Showing the same callbacks twice would be noise.
    any_found = False
    seen_arrays = {}   # array_addr -> display_name shown earlier
    for display_name, export_name in _CALLBACK_TARGETS:
        info(f"Resolving {display_name} via {export_name} ...")
        array_addr, array_data = _find_callback_array(session, kbase, export_name)
        if not array_addr or array_data is None:
            warn(f"Could not locate {display_name} (export {export_name})")
            continue

        any_found = True
        if array_addr in seen_arrays:
            info(
                f"  {display_name} shares its array with {seen_arrays[array_addr]} "
                f"(same kernel storage at {array_addr:#x}) — skipping"
            )
            continue
        seen_arrays[array_addr] = display_name

        callbacks = _enum_array_callbacks(session, array_data, modules)
        _print_array(display_name, array_addr, callbacks)

    if not any_found:
        error("No callback arrays could be located.")
    else:
        success("Callback enumeration complete.")
    return None
