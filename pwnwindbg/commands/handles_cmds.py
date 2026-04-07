"""handles — enumerate kernel handles owned by the debuggee.

Uses NtQuerySystemInformation(SystemExtendedHandleInformation = 0x40) to
fetch the global handle table, filters by the debuggee's PID, then for
each handle:

  1. Duplicates it into the *debugger* process via DuplicateHandle so we
     can interrogate the underlying object.
  2. Calls NtQueryObject(ObjectTypeInformation) — always fast.
  3. Calls NtQueryObject(ObjectNameInformation) — can hang on synchronous
     File handles backed by named pipes; that path runs in a worker thread
     with a short timeout to keep the REPL responsive.

This is a userland-only command. The kernel-mode equivalent will live
under `kdhandles` and walk EPROCESS.ObjectTable directly.
"""

import ctypes
import threading
from ctypes import wintypes, sizeof, byref, POINTER, Structure

from rich.table import Table

from ..display.formatters import banner, console, error, info, success, warn


# ---------------------------------------------------------------------------
# Native bindings

_ntdll    = ctypes.WinDLL("ntdll")
_kernel32 = ctypes.windll.kernel32

NTSTATUS = ctypes.c_long
STATUS_SUCCESS              = 0
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004

SystemExtendedHandleInformation = 0x40
ObjectNameInformation           = 1
ObjectTypeInformation           = 2
ObjectAllTypesInformation       = 3

DUPLICATE_SAME_ACCESS = 0x2

PTR_SIZE = ctypes.sizeof(ctypes.c_void_p)


def _align_up(x, a):
    return (x + (a - 1)) & ~(a - 1)


class SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(Structure):
    _fields_ = [
        ("Object",                ctypes.c_void_p),
        ("UniqueProcessId",       ctypes.c_void_p),
        ("HandleValue",           ctypes.c_void_p),
        ("GrantedAccess",         ctypes.c_ulong),
        ("CreatorBackTraceIndex", ctypes.c_ushort),
        ("ObjectTypeIndex",       ctypes.c_ushort),
        ("HandleAttributes",      ctypes.c_ulong),
        ("Reserved",              ctypes.c_ulong),
    ]


class UNICODE_STRING(Structure):
    _fields_ = [
        ("Length",        ctypes.c_ushort),
        ("MaximumLength", ctypes.c_ushort),
        ("Buffer",        ctypes.c_void_p),
    ]


_NtQuerySystemInformation = _ntdll.NtQuerySystemInformation
_NtQuerySystemInformation.argtypes = [
    ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, POINTER(ctypes.c_ulong),
]
_NtQuerySystemInformation.restype = NTSTATUS

_NtQueryObject = _ntdll.NtQueryObject
_NtQueryObject.argtypes = [
    wintypes.HANDLE, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong,
    POINTER(ctypes.c_ulong),
]
_NtQueryObject.restype = NTSTATUS

_DuplicateHandle = _kernel32.DuplicateHandle
_DuplicateHandle.argtypes = [
    wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE,
    POINTER(wintypes.HANDLE), wintypes.DWORD, wintypes.BOOL, wintypes.DWORD,
]
_DuplicateHandle.restype = wintypes.BOOL

_GetCurrentProcess = _kernel32.GetCurrentProcess
_GetCurrentProcess.restype = wintypes.HANDLE

_CloseHandle = _kernel32.CloseHandle
_CloseHandle.argtypes = [wintypes.HANDLE]
_CloseHandle.restype = wintypes.BOOL


# ---------------------------------------------------------------------------
# System handle table

def _query_system_handles(target_pid=None):
    """Return the full SystemExtendedHandleInformation table.

    Returns a list of plain tuples
        (pid, handle_value, granted_access, object_type_index, object_addr)
    so callers don't keep references into the underlying buffer (which
    is freed when this function returns).

    If `target_pid` is given, entries are filtered during iteration so we
    don't materialise the ~700k handles owned by the rest of the system.
    """
    size = 0x10000
    for _ in range(10):
        buf = (ctypes.c_ubyte * size)()
        ret = ctypes.c_ulong(0)
        st = _NtQuerySystemInformation(
            SystemExtendedHandleInformation, buf, size, byref(ret),
        )
        st32 = st & 0xFFFFFFFF
        if st32 == 0:
            break
        if st32 == STATUS_INFO_LENGTH_MISMATCH:
            size = max(ret.value + 0x4000, size * 2)
            continue
        return None
    else:
        return None

    n = ctypes.c_size_t.from_address(ctypes.addressof(buf)).value
    base = ctypes.addressof(buf) + 2 * sizeof(ctypes.c_size_t)
    EntryT = SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
    es = sizeof(EntryT)
    out = []
    for i in range(n):
        ent = EntryT.from_address(base + i * es)
        pid = ent.UniqueProcessId or 0
        if target_pid is not None and pid != target_pid:
            continue
        out.append((
            int(pid),
            int(ent.HandleValue or 0),
            int(ent.GrantedAccess),
            int(ent.ObjectTypeIndex),
            int(ent.Object or 0),
        ))
    return out


# ---------------------------------------------------------------------------
# Object name / type queries

def _read_unicode_string(addr):
    us = UNICODE_STRING.from_address(addr)
    if not us.Length or not us.Buffer:
        return ""
    raw = (ctypes.c_byte * us.Length).from_address(us.Buffer)
    return bytes(raw).decode("utf-16-le", errors="replace")


def _query_handle_type(h):
    buf = (ctypes.c_ubyte * 0x400)()
    ret = ctypes.c_ulong(0)
    st = _NtQueryObject(h, ObjectTypeInformation, buf, sizeof(buf), byref(ret))
    if st != STATUS_SUCCESS:
        return ""
    return _read_unicode_string(ctypes.addressof(buf))


def _query_handle_name_blocking(h):
    buf = (ctypes.c_ubyte * 0x1000)()
    ret = ctypes.c_ulong(0)
    st = _NtQueryObject(h, ObjectNameInformation, buf, sizeof(buf), byref(ret))
    if st != STATUS_SUCCESS:
        return ""
    return _read_unicode_string(ctypes.addressof(buf))


def _query_handle_name_safe(h, may_hang, timeout=0.2):
    """Wrap NtQueryObject(Name) in a thread when the type is one that may
    hang (sync File handles backed by named pipes / consoles).
    """
    if not may_hang:
        try:
            return _query_handle_name_blocking(h)
        except Exception:
            return ""
    out = [""]
    def _worker():
        try:
            out[0] = _query_handle_name_blocking(h)
        except Exception:
            out[0] = ""
    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        return "<timeout>"
    return out[0]


# Synchronous read access on a File can be a pipe — those hang.
_HANG_PRONE = {"File"}


# ---------------------------------------------------------------------------
# Object type index -> name table
#
# NtQueryObject(NULL, ObjectAllTypesInformation) returns OBJECT_TYPES_INFORMATION
# which is a header { ULONG NumberOfTypes; } followed by a packed array of
# OBJECT_TYPE_INFORMATION_V2 entries. Each entry's TypeName.Buffer points to
# the chars *immediately* after the struct, and the next entry starts at
# pointer-aligned (struct + buffer) bytes later. The TypeIndex byte tells us
# which kernel object type index this entry represents.

class OBJECT_TYPE_INFORMATION_V2(Structure):
    _fields_ = [
        ("TypeName",                       UNICODE_STRING),
        ("TotalNumberOfObjects",           ctypes.c_ulong),
        ("TotalNumberOfHandles",           ctypes.c_ulong),
        ("TotalPagedPoolUsage",            ctypes.c_ulong),
        ("TotalNonPagedPoolUsage",         ctypes.c_ulong),
        ("TotalNamePoolUsage",             ctypes.c_ulong),
        ("TotalHandleTableUsage",          ctypes.c_ulong),
        ("HighWaterNumberOfObjects",       ctypes.c_ulong),
        ("HighWaterNumberOfHandles",       ctypes.c_ulong),
        ("HighWaterPagedPoolUsage",        ctypes.c_ulong),
        ("HighWaterNonPagedPoolUsage",     ctypes.c_ulong),
        ("HighWaterNamePoolUsage",         ctypes.c_ulong),
        ("HighWaterHandleTableUsage",      ctypes.c_ulong),
        ("InvalidAttributes",              ctypes.c_ulong),
        ("GenericMappingGenericRead",      ctypes.c_ulong),
        ("GenericMappingGenericWrite",     ctypes.c_ulong),
        ("GenericMappingGenericExecute",   ctypes.c_ulong),
        ("GenericMappingGenericAll",       ctypes.c_ulong),
        ("ValidAccessMask",                ctypes.c_ulong),
        ("SecurityRequired",               ctypes.c_ubyte),
        ("MaintainHandleCount",            ctypes.c_ubyte),
        ("TypeIndex",                      ctypes.c_ubyte),
        ("ReservedByte",                   ctypes.c_ubyte),
        ("PoolType",                       ctypes.c_ulong),
        ("DefaultPagedPoolCharge",         ctypes.c_ulong),
        ("DefaultNonPagedPoolCharge",      ctypes.c_ulong),
    ]


_TYPE_INDEX_NAMES = None  # cached after first call


def _build_type_index_table():
    """Return { type_index: type_name } for every kernel object type."""
    global _TYPE_INDEX_NAMES
    if _TYPE_INDEX_NAMES is not None:
        return _TYPE_INDEX_NAMES

    size = 0x4000
    for _ in range(8):
        buf = (ctypes.c_ubyte * size)()
        ret = ctypes.c_ulong(0)
        st = _NtQueryObject(
            wintypes.HANDLE(0), ObjectAllTypesInformation,
            buf, size, byref(ret),
        )
        st32 = st & 0xFFFFFFFF
        if st32 == 0:
            break
        if st32 == STATUS_INFO_LENGTH_MISMATCH:
            size = max(ret.value + 0x1000, size * 2)
            continue
        _TYPE_INDEX_NAMES = {}
        return _TYPE_INDEX_NAMES
    else:
        _TYPE_INDEX_NAMES = {}
        return _TYPE_INDEX_NAMES

    base = ctypes.addressof(buf)
    n_types = ctypes.c_ulong.from_address(base).value
    # First entry starts at base + sizeof(ULONG_PTR) (aligned)
    cur = base + PTR_SIZE
    out = {}
    for _i in range(n_types):
        cur = _align_up(cur, PTR_SIZE)
        if cur + sizeof(OBJECT_TYPE_INFORMATION_V2) > base + size:
            break
        ent = OBJECT_TYPE_INFORMATION_V2.from_address(cur)
        name = ""
        if ent.TypeName.Buffer and ent.TypeName.Length:
            try:
                raw = (ctypes.c_byte * ent.TypeName.Length).from_address(
                    ent.TypeName.Buffer
                )
                name = bytes(raw).decode("utf-16-le", errors="replace")
            except Exception:
                name = ""
        if name:
            out[int(ent.TypeIndex)] = name
        # Advance past struct + name buffer (MaximumLength includes null term)
        cur = cur + sizeof(OBJECT_TYPE_INFORMATION_V2) + ent.TypeName.MaximumLength
    _TYPE_INDEX_NAMES = out
    return out


# ---------------------------------------------------------------------------
# Command

def cmd_handles(debugger, args):
    """List kernel handles held by the debuggee.

    Usage:
        handles                 — show all handles
        handles <substring>     — filter type or name (case-insensitive)
        handles --type File     — show only the given object type
    """
    if not debugger.process_handle:
        error("No process attached")
        return None
    pid = getattr(debugger, "process_id", None)
    if not pid:
        error("Could not determine target PID")
        return None

    parts = args.strip().split()
    type_filter = None
    name_filter = None
    i = 0
    while i < len(parts):
        p = parts[i]
        if p in ("--type", "-t") and i + 1 < len(parts):
            type_filter = parts[i + 1].lower()
            i += 2
            continue
        if p.startswith("-"):
            warn(f"Unknown flag: {p}")
            i += 1
            continue
        name_filter = p.lower()
        i += 1

    info(f"Querying system handle table…")
    mine = _query_system_handles(target_pid=pid)
    if mine is None:
        error("NtQuerySystemInformation(SystemExtendedHandleInformation) failed")
        return None
    if not mine:
        warn(f"No handles found for PID {pid}")
        return None

    type_index_map = _build_type_index_table()

    me = _GetCurrentProcess()
    rows = []
    for _pid, hval, gaccess, type_idx, obj in mine:
        dup = wintypes.HANDLE(0)
        ok = _DuplicateHandle(
            debugger.process_handle,
            wintypes.HANDLE(hval),
            me, byref(dup),
            0, False, DUPLICATE_SAME_ACCESS,
        )
        tname = type_index_map.get(type_idx, "")
        nname = ""
        if ok and dup.value:
            try:
                # Prefer the type query from the duped handle — more accurate
                # than the cached index table for edge cases.
                t_live = _query_handle_type(dup) or ""
                if t_live:
                    tname = t_live
                nname = _query_handle_name_safe(dup, may_hang=tname in _HANG_PRONE)
            except Exception:
                pass
            _CloseHandle(dup)
        rows.append((hval, tname, gaccess, obj, nname))

    # Apply filters
    if type_filter:
        rows = [r for r in rows if r[1].lower() == type_filter]
    if name_filter:
        rows = [r for r in rows
                if name_filter in r[1].lower() or name_filter in r[4].lower()]

    rows.sort(key=lambda r: (r[1].lower(), r[0]))

    banner(f"Handles — PID {pid}, {len(rows)} entries")
    tbl = Table(show_header=True, border_style="cyan",
                header_style="bold bright_white")
    tbl.add_column("Handle",  style="bright_yellow", justify="right")
    tbl.add_column("Type",    style="bright_green")
    tbl.add_column("Access",  style="bright_magenta")
    tbl.add_column("Object",  style="bright_blue")
    tbl.add_column("Name",    style="bright_white", overflow="fold")
    for h, t, acc, obj, nm in rows:
        tbl.add_row(
            f"{h:#x}",
            t or "?",
            f"{acc:#010x}",
            f"{obj:#018x}" if obj else "",
            nm or "",
        )
    console.print(tbl)

    # Quick stats by type
    counts = {}
    for _, t, *_rest in rows:
        counts[t or "?"] = counts.get(t or "?", 0) + 1
    if counts:
        line = "  ".join(f"[bright_green]{t}[/]: {n}"
                          for t, n in sorted(counts.items(), key=lambda x: -x[1]))
        console.print(line)
    return None
