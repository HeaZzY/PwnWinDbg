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
import re

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

try:  # operand-type constants
    from capstone.x86 import X86_OP_IMM, X86_OP_REG, X86_OP_MEM
except Exception:  # pragma: no cover - fallback if layout differs
    X86_OP_IMM = 2
    X86_OP_REG = 1
    X86_OP_MEM = 3

# PE section characteristic flags
_IMAGE_SCN_MEM_EXECUTE = 0x20000000

# Machine types
_MACHINE_AMD64 = 0x8664
_MACHINE_I386 = 0x14C

# Common function-prologue byte signatures (matched at any offset in .text).
# Kept multi-byte and conservative to avoid flooding the result with junk.
_PROLOGUE_SIGS = (
    b"\x8b\xff\x55\x8b\xec",  # hotpatch: mov edi,edi; push ebp; mov ebp,esp
    b"\x55\x8b\xec",          # push ebp; mov ebp,esp  (MSVC encoding)
    b"\x55\x89\xe5",          # push ebp; mov ebp,esp  (GCC/MinGW encoding)
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


def _detect_main_gcc(data, text_va, text_lo, text_hi, md, thunks):
    """Locate ``main`` in a MinGW/gcc x86 PE from the CRT startup shape.

    Across MinGW versions the CRT startup calls ``main(argc, argv, envp)`` and
    hands its return value to ``exit``/``ExitProcess``, compiling to:

        call main            ; <- main
        mov  <reg>, eax      ; capture the exit code
        ... (a few insns) ...
        call exit/_cexit/ExitProcess

    So ``main`` is the direct user-code call whose result is copied out of eax
    and, within a short window, passed to an exit-family import. This is robust
    to how far ``main`` sits from ``__getmainargs`` (which varies by version).
    ``thunks`` maps IAT-jump-thunk VA -> import name. Returns the main VA or None.
    """
    rev = {}
    for a, nm in thunks.items():
        rev.setdefault(nm, a)
    gma_addrs = {rev[n] for n in ("__getmainargs", "__wgetmainargs") if n in rev}
    exit_addrs = {
        rev[n] for n in ("exit", "_exit", "ExitProcess", "_cexit", "_amsg_exit")
        if n in rev
    }
    if not gma_addrs and not exit_addrs:
        return None
    thunk_addrs = set(thunks)

    def _imm_call(ins):
        ops = ins.operands
        if ins.mnemonic == "call" and len(ops) == 1 and ops[0].type == X86_OP_IMM:
            return ops[0].imm
        return None

    def _writes_esp0(ins):
        """True for `mov dword ptr [esp], <imm/reg>` (the argc cdecl arg)."""
        if ins.mnemonic != "mov" or len(ins.operands) != 2:
            return False
        dst = ins.operands[0]
        if dst.type != X86_OP_MEM:
            return False
        m = dst.mem
        return (ins.reg_name(m.base) == "esp" and m.index == 0 and m.disp == 0)

    def _captures_eax(ins):
        """True for `mov <reg|mem>, eax` (storing a call's return value)."""
        if ins.mnemonic != "mov" or len(ins.operands) != 2:
            return False
        src = ins.operands[1]
        return src.type == X86_OP_REG and ins.reg_name(src.reg) == "eax"

    insns = list(md.disasm(data, text_va))
    # Anchor on the CRT startup: __getmainargs is called only there (fall back to
    # the first exit-family call). GCC block-reordering means `call main` may sit
    # before OR after the anchor in address order, so scan a symmetric window and
    # pick the main-shaped call NEAREST the anchor.
    gidx = [i for i, ins in enumerate(insns) if _imm_call(ins) in gma_addrs]
    if gidx:
        center = gidx[0]
    else:
        eidx = [i for i, ins in enumerate(insns) if _imm_call(ins) in exit_addrs]
        if not eidx:
            return None
        center = eidx[0]
    lo, hi = max(1, center - 160), min(len(insns), center + 160)

    strong, weak = [], []          # (distance-to-anchor, target)
    for i in range(lo, hi):
        tgt = _imm_call(insns[i])
        if tgt is None or not (text_lo <= tgt < text_hi) or tgt in thunk_addrs:
            continue
        eax_used = any(_captures_eax(insns[k])
                       for k in range(i + 1, min(hi, i + 4)))
        if not eax_used:
            continue
        # main(argc, argv, ...): the argc arg is written to [esp] in the very
        # instruction before the call — a tight, main-specific signature.
        if _writes_esp0(insns[i - 1]):
            strong.append((abs(i - center), tgt))
        elif any(_writes_esp0(insns[k]) for k in range(max(lo, i - 4), i)):
            weak.append((abs(i - center), tgt))
    if strong:
        return min(strong)[1]
    if weak:
        return min(weak)[1]
    return None


def detect_main(exe_path, image_base, is_64=False):
    """Best-effort locate the user's ``main`` in an MSVC-compiled x86 PE.

    The CRT entry point tail-jumps into ``__scrt_common_main_seh``, which calls
    ``main(argc, argv, envp)`` — recognizable as a ``call <imm>`` immediately
    preceded by three ``push`` instructions (the three arguments). Returns the
    main VA (rebased to ``image_base``) or ``None``. x64 uses register args, so
    this heuristic is skipped there. Never raises.
    """
    pe = None
    try:
        if not exe_path or not os.path.exists(exe_path):
            return None
        pe = pefile.PE(exe_path, fast_load=True)
        if is_64 is None:
            is_64 = int(pe.FILE_HEADER.Machine) == _MACHINE_AMD64
        if is_64:
            return None
        section = _find_text_section(pe)
        if section is None:
            return None
        data = section.get_data()
        if not data:
            return None
        text_va = int(image_base) + int(section.VirtualAddress)
        vsize = int(section.Misc_VirtualSize) or len(data)
        text_lo, text_hi = text_va, text_va + vsize

        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.detail = True

        entry = int(image_base) + int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        if not (text_lo <= entry < text_hi):
            return None

        # 0) MinGW/gcc: locate main via the __getmainargs -> main -> exit shape.
        #    Try this first; it's a no-op on MSVC (no __getmainargs import).
        try:
            thunks = name_thunks(exe_path, image_base, is_64=is_64)
            gcc_main = _detect_main_gcc(data, text_va, text_lo, text_hi, md, thunks)
            if gcc_main is not None:
                return gcc_main
        except Exception:
            pass

        # 1) From the entry point, follow the first jmp <imm> into the CRT
        #    main wrapper (__scrt_common_main_seh).
        wrapper = entry
        eoff = entry - text_va
        for ins in md.disasm(data[eoff:eoff + 64], entry):
            if ins.mnemonic == "jmp":
                ops = ins.operands
                if len(ops) == 1 and ops[0].type == X86_OP_IMM:
                    t = ops[0].imm
                    if text_lo <= t < text_hi:
                        wrapper = t
                        break

        # 2) In the wrapper, the FIRST `push;push;push; call <imm>` is the
        #    call to main(argc, argv, envp). Take the first match and stop —
        #    scanning further bleeds into other functions. `ret`/int3 ends it.
        woff = wrapper - text_va
        push_run = 0
        for ins in md.disasm(data[woff:woff + 0x400], wrapper):
            mn = ins.mnemonic
            if mn == "push":
                push_run += 1
                continue
            if mn == "call":
                ops = ins.operands
                if (push_run >= 3 and len(ops) == 1
                        and ops[0].type == X86_OP_IMM
                        and text_lo <= ops[0].imm < text_hi):
                    return ops[0].imm
                push_run = 0
                continue
            if mn in ("ret", "retn", "int3"):
                break
            push_run = 0
        return None
    except Exception:
        return None
    finally:
        if pe is not None:
            try:
                pe.close()
            except Exception:
                pass


def name_thunks(exe_path, image_base, is_64=False):
    """Name IAT jump-thunks after their import.

    A `jmp dword ptr [__imp_X]` (bytes ``FF 25 <ptr>``) whose pointer targets an
    Import Address Table slot is really the imported function ``X``; naming the
    thunk after it makes calls resolve to real names (ReadFile, printf, ...).
    Returns {thunk_addr:int -> name:str}. Never raises.
    """
    pe = None
    try:
        if not exe_path or not os.path.exists(exe_path):
            return {}
        pe = pefile.PE(exe_path, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        # Match everything in FILE (preferred-ImageBase) space — the .text bytes
        # and the IAT VAs from pefile are both pre-relocation — then rebase the
        # resulting thunk addresses to the runtime image base. Getting this wrong
        # silently yields zero thunks on ASLR/dynamic-base images (delta != 0).
        base = int(pe.OPTIONAL_HEADER.ImageBase)
        delta = int(image_base) - base
        iat = {}
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for dll in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in dll.imports:
                    if imp.address:
                        va = int(imp.address)          # file space (no rebase)
                        if imp.name:
                            iat[va] = imp.name.decode("utf-8", "replace")
                        elif imp.ordinal is not None:
                            dn = (dll.dll or b"").decode("utf-8", "replace")
                            iat[va] = "%s_ord_%d" % (dn.split(".")[0], imp.ordinal)
        if not iat:
            return {}
        section = _find_text_section(pe)
        if section is None:
            return {}
        data = section.get_data()
        file_text_va = base + int(section.VirtualAddress)   # file space
        ptr_w = 8 if is_64 else 4
        result = {}
        for m in re.finditer(b"\xff\x25", data):
            off = m.start()
            raw = data[off + 2:off + 2 + ptr_w]
            if len(raw) < ptr_w:
                continue
            ptr = int.from_bytes(raw, "little")
            thunk_run_va = file_text_va + off + delta        # rebased result
            if not is_64 and ptr in iat:
                result[thunk_run_va] = iat[ptr]
            elif is_64:
                # x64 uses rip-relative: [rip + disp]; target = next_ip + disp
                disp = int.from_bytes(raw, "little")
                if disp & 0x80000000:
                    disp -= 0x100000000
                tgt = (file_text_va + off + 6) + disp        # file space
                if tgt in iat:
                    result[thunk_run_va] = iat[tgt]
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
