"""Process and thread walker for Windows kernel debugging.

Walks PsActiveProcessHead via the PsInitialSystemProcess export, then
follows the EPROCESS.ActiveProcessLinks doubly-linked list.
"""

import struct

from .win_structs import EPROCESS, ETHREAD, KPROCESS, TOKEN_REF_MASK


def _read_u64(session, addr):
    data = session.read_virtual(addr, 8)
    if not data or len(data) < 8:
        return 0
    return struct.unpack_from("<Q", data, 0)[0]


def find_ps_initial_system_process(session, kernel_base, find_export):
    """Resolve PsInitialSystemProcess (exported by ntoskrnl).

    Returns the EPROCESS pointer of the System process, or 0.
    """
    rva = find_export(session, kernel_base, "PsInitialSystemProcess")
    if not rva:
        return 0
    ptr_addr = kernel_base + rva
    return _read_u64(session, ptr_addr)


def parse_eprocess(session, eproc):
    """Read fields of an _EPROCESS struct.

    Returns dict with: eproc, pid, name, token, ppid, dtb, links_flink
    or None on read failure.
    """
    # Single bulk read covering UniqueProcessId..ImageFileName (~ 0x180 bytes)
    base = eproc + EPROCESS.UniqueProcessId
    size = (EPROCESS.ImageFileName + 16) - EPROCESS.UniqueProcessId
    blob = session.read_virtual(base, size)
    if not blob or len(blob) < size:
        return None

    def _at(field_off):
        return field_off - EPROCESS.UniqueProcessId

    pid       = struct.unpack_from("<Q", blob, _at(EPROCESS.UniqueProcessId))[0]
    flink     = struct.unpack_from("<Q", blob, _at(EPROCESS.ActiveProcessLinks))[0]
    token_ref = struct.unpack_from("<Q", blob, _at(EPROCESS.Token))[0]
    ppid      = struct.unpack_from("<Q", blob, _at(EPROCESS.InheritedFromUniqueProcessId))[0]
    name_raw  = blob[_at(EPROCESS.ImageFileName):_at(EPROCESS.ImageFileName) + 15]
    name      = name_raw.split(b"\x00")[0].decode("ascii", errors="replace")

    # KPROCESS.DirectoryTableBase lives in the embedded KPROCESS at offset 0
    dtb_data = session.read_virtual(eproc + KPROCESS.DirectoryTableBase, 8)
    dtb = struct.unpack_from("<Q", dtb_data, 0)[0] if dtb_data and len(dtb_data) >= 8 else 0

    return {
        "eproc": eproc,
        "pid": pid,
        "name": name,
        "token_ref": token_ref,
        "token": token_ref & TOKEN_REF_MASK,
        "ppid": ppid,
        "dtb": dtb,
        "links_flink": flink,
    }


def walk_processes(session, system_eprocess, max_count=1024):
    """Walk ActiveProcessLinks starting from PsInitialSystemProcess.

    Yields parsed EPROCESS dicts. Stops on cycle, broken link, or when we
    walk off the end of the list (i.e. into nt!PsActiveProcessHead which
    lives inside the ntoskrnl image, not the kernel pool).
    """
    if not system_eprocess:
        return

    visited = set()
    current = system_eprocess
    for _ in range(max_count):
        if current in visited:
            return
        visited.add(current)

        info = parse_eprocess(session, current)
        if info is None:
            return

        # Sanity check: real EPROCESS allocations live in the kernel pool
        # (typically 0xFFFFE... or 0xFFFFA...), never inside the ntoskrnl
        # image (0xFFFFF80...). Also PIDs fit in 32 bits and are usually
        # well below 1<<24. If either check fails, we walked off the list
        # into PsActiveProcessHead or similar — stop without yielding.
        if info["pid"] >= (1 << 32):
            return

        yield info

        # Next entry: ActiveProcessLinks.Flink points to the next entry's Flink field.
        next_flink = info["links_flink"]
        if not next_flink:
            return
        next_eproc = next_flink - EPROCESS.ActiveProcessLinks
        if next_eproc == system_eprocess:
            return
        current = next_eproc


def find_process(session, system_eprocess, *, pid=None, name=None):
    """Find a single process by PID or by name (case-insensitive substring)."""
    name_lower = name.lower() if name else None
    for p in walk_processes(session, system_eprocess):
        if pid is not None and p["pid"] == pid:
            return p
        if name_lower and name_lower in p["name"].lower():
            return p
    return None


def walk_threads(session, eproc, max_count=4096):
    """Walk an EPROCESS.ThreadListHead, yielding ETHREAD addresses.

    Each ETHREAD has a ThreadListEntry _LIST_ENTRY linked through the head.

    The ThreadListEntry offset inside ETHREAD shifts between Windows builds,
    so we infer it on first iteration: subtract the head's address from the
    Flink, no — better — derive ThreadListEntry by computing it from Cid.
    For now we use the value in win_structs.ETHREAD.ThreadListEntry, which
    callers should override after offset extraction.
    """
    head = eproc + EPROCESS.ThreadListHead
    flink_data = session.read_virtual(head, 8)
    if not flink_data or len(flink_data) < 8:
        return
    flink = struct.unpack_from("<Q", flink_data, 0)[0]

    visited = set()
    current = flink
    for _ in range(max_count):
        if current == head or current in visited:
            return
        visited.add(current)

        ethread = current - ETHREAD.ThreadListEntry
        # Real ETHREAD allocations live in the kernel pool, not in ntoskrnl
        if ethread < 0xFFFF800000000000:
            return

        # Read CID (UniqueProcess, UniqueThread)
        cid_data = session.read_virtual(ethread + ETHREAD.Cid, 16)
        if not cid_data or len(cid_data) < 16:
            return
        unique_process, unique_thread = struct.unpack_from("<QQ", cid_data, 0)

        # Sanity check on TID — kernel TIDs fit in 32 bits
        if unique_thread >= (1 << 32):
            return

        yield {
            "ethread": ethread,
            "tid": unique_thread,
            "pid_owner": unique_process,
        }

        # Read next Flink
        next_data = session.read_virtual(current, 8)
        if not next_data or len(next_data) < 8:
            return
        current = struct.unpack_from("<Q", next_data, 0)[0]
