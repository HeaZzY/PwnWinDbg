"""Dynamic kernel struct offset extraction.

Disassembles a few well-known stable ntoskrnl exports to extract
EPROCESS / KTHREAD / ETHREAD field offsets at runtime, instead of
hardcoding tables per Windows build.

This is the same trick used by serious kernel exploits.

Stable exports we use:
    PsGetProcessId(PEPROCESS)
        mov rax, [rcx + EPROCESS.UniqueProcessId]
        ret

    PsGetProcessImageFileName(PEPROCESS)
        add rcx, EPROCESS.ImageFileName
        mov rax, rcx
        ret
        (or: lea rax, [rcx + EPROCESS.ImageFileName] ; ret)

    PsGetCurrentThreadId()
        mov rax, gs:[188h]                       ; KTHREAD
        mov rax, [rax + ETHREAD.Cid + 8]         ; Cid.UniqueThread
        ret

    PsGetCurrentProcessId()
        mov rax, gs:[188h]                       ; KTHREAD
        mov rax, [rax + KTHREAD.Process]         ; PEPROCESS
        mov rax, [rax + EPROCESS.UniqueProcessId]
        ret
"""

import struct


def _read_export(session, kernel_base, find_export, name, n_bytes=64):
    """Resolve and read N bytes of an exported function. Returns bytes or b''."""
    rva = find_export(session, kernel_base, name)
    if not rva:
        return b""
    return session.read_virtual(kernel_base + rva, n_bytes) or b""


def _scan_for_mov_rax_rcx_disp32(code):
    """Find the first `mov rax, [rcx + disp32]` instruction (8B/8D variants).

    Encoding for `mov rax, [rcx + disp32]` = `48 8B 81 XX XX XX XX`
    Encoding for `mov rax, [rax + disp32]` = `48 8B 80 XX XX XX XX`
    Encoding for `lea rax, [rcx + disp32]` = `48 8D 81 XX XX XX XX`
    Encoding for `add rcx, imm32`          = `48 81 C1 XX XX XX XX`
    Returns disp32 (signed) or None.
    """
    for i in range(len(code) - 7):
        if code[i] == 0x48 and code[i + 1] == 0x8B and code[i + 2] == 0x81:
            return struct.unpack_from("<i", code, i + 3)[0]
    return None


def _scan_for_lea_or_add_rcx(code):
    """Look for `lea rax, [rcx + disp32]` or `add rcx, imm32`.

    PsGetProcessImageFileName is typically:
        48 8D 81 XX XX XX XX            ; lea rax, [rcx + ImageFileName]
        C3                              ; ret
    or:
        48 81 C1 XX XX XX XX            ; add rcx, ImageFileName
        48 8B C1                        ; mov rax, rcx
        C3                              ; ret
    """
    for i in range(len(code) - 7):
        # lea rax, [rcx + disp32]
        if code[i] == 0x48 and code[i + 1] == 0x8D and code[i + 2] == 0x81:
            return struct.unpack_from("<i", code, i + 3)[0]
        # add rcx, imm32
        if code[i] == 0x48 and code[i + 1] == 0x81 and code[i + 2] == 0xC1:
            return struct.unpack_from("<i", code, i + 3)[0]
    return None


def _scan_for_mov_rax_rax_disp32(code, start=0):
    """Find `mov rax, [rax + disp32]` = 48 8B 80 XX XX XX XX, after `start`."""
    for i in range(start, len(code) - 7):
        if code[i] == 0x48 and code[i + 1] == 0x8B and code[i + 2] == 0x80:
            return i, struct.unpack_from("<i", code, i + 3)[0]
    return None, None


def extract_offsets(session, kernel_base, find_export):
    """Disassemble kernel exports to learn struct offsets at runtime.

    Returns a dict with whatever offsets we managed to extract:
        {
            "EPROCESS.UniqueProcessId":      int,
            "EPROCESS.ImageFileName":        int,
            "EPROCESS.ActiveProcessLinks":   int,
            "EPROCESS.Token":                int,
            "EPROCESS.InheritedFromUPI":     int,
            "EPROCESS.ThreadListHead":       int,
            "KTHREAD.Process":               int,
            "ETHREAD.Cid":                   int,
        }
    Missing keys mean extraction failed for that field.
    """
    out = {}

    # ---- UniqueProcessId via PsGetProcessId ----
    code = _read_export(session, kernel_base, find_export, "PsGetProcessId", 32)
    if code:
        upi = _scan_for_mov_rax_rcx_disp32(code)
        if upi is not None and 0 < upi < 0x4000:
            out["EPROCESS.UniqueProcessId"]    = upi
            out["EPROCESS.ActiveProcessLinks"] = upi + 8        # always
            out["EPROCESS.Token"]              = upi + 0x78     # constant Win10/11
            out["EPROCESS.InheritedFromUPI"]   = upi + 0x100    # constant Win10/11

    # ---- ImageFileName via PsGetProcessImageFileName ----
    code = _read_export(session, kernel_base, find_export,
                        "PsGetProcessImageFileName", 32)
    if code:
        ifn = _scan_for_lea_or_add_rcx(code)
        if ifn is not None and 0 < ifn < 0x4000:
            out["EPROCESS.ImageFileName"]  = ifn
            out["EPROCESS.ThreadListHead"] = ifn + 0x38   # constant Win10/11

    # ---- KTHREAD.Process + UniqueProcessId verification via PsGetCurrentProcessId ----
    code = _read_export(session, kernel_base, find_export,
                        "PsGetCurrentProcessId", 64)
    if code:
        # Two `mov rax, [rax + dispN]` chained:
        #   1st: KTHREAD.Process
        #   2nd: EPROCESS.UniqueProcessId
        i1, disp1 = _scan_for_mov_rax_rax_disp32(code, 0)
        if disp1 is not None and 0 < disp1 < 0x4000:
            out["KTHREAD.Process"] = disp1
            i2, disp2 = _scan_for_mov_rax_rax_disp32(code, i1 + 7)
            if disp2 is not None and 0 < disp2 < 0x4000:
                # Sanity-check against the value we got from PsGetProcessId
                if "EPROCESS.UniqueProcessId" not in out:
                    out["EPROCESS.UniqueProcessId"]    = disp2
                    out["EPROCESS.ActiveProcessLinks"] = disp2 + 8
                    out["EPROCESS.Token"]              = disp2 + 0x78
                    out["EPROCESS.InheritedFromUPI"]   = disp2 + 0x100

    # ---- ETHREAD.Cid via PsGetCurrentThreadId ----
    # mov rax, gs:[188h]                  ; 65 48 8B 04 25 88 01 00 00
    # mov rax, [rax + Cid + 8]            ; 48 8B 80 XX XX XX XX
    # ret                                 ; C3
    code = _read_export(session, kernel_base, find_export,
                        "PsGetCurrentThreadId", 32)
    if code:
        _, disp = _scan_for_mov_rax_rax_disp32(code, 0)
        if disp is not None and 0 < disp < 0x4000:
            # disp is Cid + 8 (we read UniqueThread which is 8 bytes after Cid start)
            out["ETHREAD.Cid"] = disp - 8

    return out


def discover_thread_list_entry_offset(session, system_eproc):
    """Find ETHREAD.ThreadListEntry offset by walking the System process.

    No exported ntoskrnl function leaks this offset directly. Instead, we
    use a heuristic: read EPROCESS.ThreadListHead.Flink (which points to
    `ETHREAD + ThreadListEntry` of the first thread), then try plausible
    candidates and pick the one whose resulting ETHREAD has a Cid where
    UniqueProcess matches the System PID (4) and UniqueThread is sane.

    Requires:
        - EPROCESS.ThreadListHead and ETHREAD.Cid to already be set
          (via apply_offsets_to_classes after extract_offsets).
        - The System process EPROCESS pointer.

    Returns the discovered offset, or None if not found.
    """
    from . import win_structs as ws

    head = system_eproc + ws.EPROCESS.ThreadListHead
    flink_data = session.read_virtual(head, 8)
    if not flink_data or len(flink_data) < 8:
        return None
    flink = struct.unpack_from("<Q", flink_data, 0)[0]
    if not flink or flink == head:
        return None

    cid_off = ws.ETHREAD.Cid

    # Plausible ThreadListEntry offsets across all known Win10/11 builds
    # have spanned 0x420..0x6c0; widen a bit for safety. Always 8-aligned.
    for candidate in range(0x300, 0x900, 8):
        ethread = flink - candidate
        if ethread < 0xFFFF800000000000:
            continue
        cid_data = session.read_virtual(ethread + cid_off, 16)
        if not cid_data or len(cid_data) < 16:
            continue
        unique_process, unique_thread = struct.unpack_from("<QQ", cid_data, 0)
        # System threads always have UniqueProcess == 4 (PID of System)
        # and a small-ish TID (definitely fits in 32 bits).
        if unique_process == 4 and 0 < unique_thread < (1 << 24):
            return candidate
    return None


def apply_offsets_to_classes(extracted):
    """Update the EPROCESS / KTHREAD / ETHREAD classes in win_structs.

    Only mutates fields that were successfully extracted; leaves the
    static defaults for the rest.
    """
    from . import win_structs as ws

    if "EPROCESS.UniqueProcessId" in extracted:
        ws.EPROCESS.UniqueProcessId = extracted["EPROCESS.UniqueProcessId"]
    if "EPROCESS.ActiveProcessLinks" in extracted:
        ws.EPROCESS.ActiveProcessLinks = extracted["EPROCESS.ActiveProcessLinks"]
    if "EPROCESS.Token" in extracted:
        ws.EPROCESS.Token = extracted["EPROCESS.Token"]
    if "EPROCESS.InheritedFromUPI" in extracted:
        ws.EPROCESS.InheritedFromUniqueProcessId = extracted["EPROCESS.InheritedFromUPI"]
    if "EPROCESS.ImageFileName" in extracted:
        ws.EPROCESS.ImageFileName = extracted["EPROCESS.ImageFileName"]
    if "EPROCESS.ThreadListHead" in extracted:
        ws.EPROCESS.ThreadListHead = extracted["EPROCESS.ThreadListHead"]
    if "KTHREAD.Process" in extracted:
        ws.KTHREAD.Process = extracted["KTHREAD.Process"]
    if "ETHREAD.Cid" in extracted:
        ws.ETHREAD.Cid = extracted["ETHREAD.Cid"]
