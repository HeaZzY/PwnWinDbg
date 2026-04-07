"""Kernel stack walker — heuristic backtrace.

x64 Windows kernel code is built with FPO (frame pointer omission), so
the classic RBP-chain walk does not work. The robust approach is to use
PE .pdata RUNTIME_FUNCTION unwinding, which is complex.

This module implements a simpler scan-based heuristic:
    - Read N bytes of stack starting at RSP
    - For every 8-byte slot, check if the value lands inside a known
      kernel module's executable range
    - Validate by checking the byte just before is a `call` instruction
      (E8 / FF /2 / FF /3) — drops most false positives

Good enough for typical kernel debugging without symbols.
"""

import struct


def _is_in_module(addr, modules):
    """Return (base, size, name) of the module containing addr, or None."""
    for dll_base, size, ep, bname, fpath in modules:
        if dll_base <= addr < dll_base + size:
            return dll_base, size, bname
    return None


def _looks_like_call_target(session, addr):
    """Check if the byte just before addr is part of a call instruction.

    Reads up to 6 bytes preceding addr and checks for:
        E8 xx xx xx xx          — call rel32 (5 bytes)
        FF /2 ...               — call indirect (variable, 2-7 bytes)
        FF /3 ...               — far call indirect
    Conservative: only checks E8 and FF.
    """
    pre = session.read_virtual(addr - 6, 6)
    if not pre or len(pre) < 6:
        return False
    # E8 rel32 is 5 bytes total → byte at offset -5 must be 0xE8
    if pre[1] == 0xE8:
        return True
    # FF /2 (call r/m) — check FF then ModR/M with reg field == 2 (010 in bits 5-3)
    for off in (2, 3, 4, 5):
        if pre[off] == 0xFF and off + 1 < len(pre):
            modrm = pre[off + 1]
            reg = (modrm >> 3) & 7
            if reg == 2 or reg == 3:
                return True
    return False


def scan_backtrace(session, rsp, modules, max_frames=20, scan_bytes=0x800):
    """Scan the stack for return addresses pointing into kernel modules.

    Args:
        session: KD session (must have read_virtual)
        rsp: stack pointer
        modules: list of (dll_base, size, ep, base_name, full_name)
        max_frames: stop after this many candidates
        scan_bytes: how many bytes of stack to scan

    Returns list of dicts: { offset, addr, value, module, mod_offset }
    """
    data = session.read_virtual(rsp, scan_bytes)
    if not data:
        return []

    frames = []
    for i in range(0, len(data) - 7, 8):
        val = struct.unpack_from("<Q", data, i)[0]
        if val < 0xFFFF800000000000:  # not a kernel pointer
            continue
        mod = _is_in_module(val, modules)
        if mod is None:
            continue
        # Validate the call instruction precedes this address
        if not _looks_like_call_target(session, val):
            continue
        base, size, name = mod
        frames.append({
            "offset": i,
            "addr": rsp + i,
            "value": val,
            "module": name,
            "mod_offset": val - base,
        })
        if len(frames) >= max_frames:
            break
    return frames
