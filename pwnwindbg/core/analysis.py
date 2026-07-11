"""Capstone-based function auto-discovery for stripped PE images.

A stripped executable exposes no symbols, so the debugger and decompiler have
no idea where the target's functions live. This module performs a lightweight,
self-contained analysis pass: it reads the ``.text`` section straight off the PE
on disk (with pefile), disassembles it with capstone, and heuristically recovers
function entry points (call/jmp targets + common prologues). Results are rebased
to the live ``image_base`` so they line up with the running process.

Self-contained by design: imports only pefile/capstone/os and never imports the
debugger at module load. Every entry point degrades to an empty result rather
than raising, so analysis failures never crash the REPL.
"""

import os

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

try:  # operand-type constant for immediate targets
    from capstone.x86 import X86_OP_IMM
except Exception:  # pragma: no cover - fallback if layout differs
    X86_OP_IMM = 2

# PE section characteristic flags
_IMAGE_SCN_MEM_EXECUTE = 0x20000000

# Machine types
_MACHINE_AMD64 = 0x8664
_MACHINE_I386 = 0x14C

# Common function-prologue byte signatures (matched at any offset in .text).
# Kept multi-byte and conservative to avoid flooding the result with junk.
_PROLOGUE_SIGS = (
    b"\x8b\xff\x55\x8b\xec",  # hotpatch: mov edi,edi; push ebp; mov ebp,esp
    b"\x55\x8b\xec",          # push ebp; mov ebp,esp  (also AT&T 55 89 e5 == 55 8b ec)
    b"\xf3\x0f\x1e\xfb",      # endbr32
    b"\xf3\x0f\x1e\xfa",      # endbr64
)

# Padding bytes between functions (int3 / nop).
_PAD_BYTES = (0xCC, 0x90)


def _find_text_section(pe):
    """Return the ``.text`` section, or the first executable section, or None."""
    exec_fallback = None
    for s in pe.sections:
        try:
            name = s.Name.decode("utf-8", errors="replace").strip("\x00")
        except Exception:
            name = ""
        if name == ".text":
            return s
        if exec_fallback is None and (s.Characteristics & _IMAGE_SCN_MEM_EXECUTE):
            exec_fallback = s
    return exec_fallback


def _scan_prologues(data, text_va, text_lo, text_hi, starts, max_funcs):
    """Byte-scan ``data`` for common prologue signatures and add their VAs."""
    for sig in _PROLOGUE_SIGS:
        pos = data.find(sig)
        while pos != -1:
            va = text_va + pos
            if text_lo <= va < text_hi:
                starts.add(va)
                if len(starts) >= max_funcs:
                    return
            pos = data.find(sig, pos + 1)

    # Conservative bare `55` (push ebp): only when it directly follows inter-
    # function padding (int3/nop run) that is itself preceded by a `C3` (ret).
    # This catches functions that start with a bare `push ebp` without flooding
    # the result with every stray 0x55 byte.
    n = len(data)
    for i in range(1, n):
        if data[i] != 0x55:
            continue
        j = i - 1
        if data[j] not in _PAD_BYTES:
            continue
        while j >= 0 and data[j] in _PAD_BYTES:
            j -= 1
        if j >= 0 and data[j] == 0xC3:
            va = text_va + i
            if text_lo <= va < text_hi:
                starts.add(va)
                if len(starts) >= max_funcs:
                    return


def discover_functions(exe_path, image_base, is_64=False, max_funcs=20000):
    """Discover function entry points in the main executable's ``.text``.

    Args:
        exe_path: Path to the PE on disk.
        image_base: Live load base of the image (targets are rebased to this).
        is_64: True for x64, False for x86. If ``None``, inferred from the PE
            machine type.
        max_funcs: Hard cap on the number of discovered starts.

    Returns:
        dict mapping ``addr:int -> name:str`` (``"_start"`` for the entry point,
        ``"sub_<HEX>"`` otherwise). Returns ``{}`` on any error; never raises.
    """
    pe = None
    try:
        if not exe_path or not os.path.exists(exe_path):
            return {}

        pe = pefile.PE(exe_path, fast_load=True)

        # Resolve architecture.
        if is_64 is None:
            machine = int(pe.FILE_HEADER.Machine)
            is_64 = machine == _MACHINE_AMD64
        mode = CS_MODE_64 if is_64 else CS_MODE_32

        section = _find_text_section(pe)
        if section is None:
            return {}

        data = section.get_data()
        if not data:
            return {}

        text_va = int(image_base) + int(section.VirtualAddress)
        vsize = int(section.Misc_VirtualSize) or len(data)
        text_lo = text_va
        text_hi = text_va + vsize

        md = Cs(CS_ARCH_X86, mode)
        md.detail = True  # need operands to extract call/jmp immediate targets

        starts = set()

        # Entry point, if it lands in .text.
        try:
            entry_va = int(image_base) + int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            if text_lo <= entry_va < text_hi:
                starts.add(entry_va)
        except Exception:
            entry_va = None

        # Linear sweep. `call <imm>` targets are always function heads.
        # `jmp <imm>` is ambiguous: an intra-function jump (loop/branch) vs a
        # tailcall into another function. Collect jmp targets as candidates and
        # only promote the ones that look like tailcalls (see below) — including
        # every jmp target shatters functions into basic blocks (huge overcount),
        # while dropping them all merges tailcall-reached functions.
        jmp_candidates = []  # (target, off_after_jmp)
        try:
            for insn in md.disasm(data, text_va):
                if len(starts) >= max_funcs:
                    break
                mn = insn.mnemonic
                if mn != "call" and mn != "jmp":
                    continue
                try:
                    ops = insn.operands
                except Exception:
                    continue
                if len(ops) != 1 or ops[0].type != X86_OP_IMM:
                    continue
                target = ops[0].imm
                if not (text_lo <= target < text_hi):
                    continue
                if mn == "call":
                    starts.add(target)
                else:
                    jmp_candidates.append((target, insn.address + insn.size - text_va))
        except Exception:
            pass

        # Promote a jmp target to a function head only when the jmp is a TAILCALL:
        # the bytes immediately after it are inter-function padding (int3/nop), a
        # known prologue, or the end of the section. Ordinary intra-function jumps
        # are followed by more code of the same function, so they are ignored.
        _plen = max(len(s) for s in _PROLOGUE_SIGS)
        for target, after in jmp_candidates:
            if len(starts) >= max_funcs:
                break
            if after >= len(data):
                starts.add(target)
                continue
            if 0 <= after < len(data):
                if data[after] in _PAD_BYTES or any(
                    data[after:after + len(s)] == s for s in _PROLOGUE_SIGS
                ):
                    starts.add(target)

        # Prologue byte-scan.
        if len(starts) < max_funcs:
            try:
                _scan_prologues(data, text_va, text_lo, text_hi, starts, max_funcs)
            except Exception:
                pass

        # Name and return.
        result = {}
        for addr in sorted(starts):
            if addr == entry_va:
                result[addr] = "_start"
            else:
                result[addr] = "sub_%X" % addr
        return result
    except Exception:
        return {}
    finally:
        if pe is not None:
            try:
                pe.close()
            except Exception:
                pass


def estimate_bounds(func_starts_sorted, addr, text_hi):
    """Estimate the [start, end) bounds of the function containing ``addr``.

    The containing function starts at the greatest discovered start ``<= addr``;
    it ends at the next discovered start (or ``text_hi`` if it is the last one).

    Args:
        func_starts_sorted: Sorted list of discovered start addresses.
        addr: Address to locate.
        text_hi: Upper bound of the code range (fallback end).

    Returns:
        ``(start, end)`` tuple of ints.
    """
    import bisect

    starts = func_starts_sorted
    if not starts:
        return (addr, text_hi)

    pos = bisect.bisect_right(starts, addr) - 1
    if pos < 0:
        # addr precedes every known start; treat addr as the start.
        return (addr, starts[0])

    start = starts[pos]
    end = starts[pos + 1] if pos + 1 < len(starts) else text_hi
    return (start, end)
