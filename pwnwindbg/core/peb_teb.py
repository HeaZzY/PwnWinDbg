"""PEB / TEB introspection.

Reads the Process Environment Block (PEB) and Thread Environment Block (TEB)
of the debuggee. Currently x64-only — WoW64 is *partially* supported (we read
the 64-bit PEB only; the 32-bit PEB is not parsed because none of the existing
commands need it yet).

The offsets below are stable across Windows 10/11 x64 (verified against
public symbols on builds 19041 / 22000 / 22621 / 26100). They are not extracted
dynamically because PEB/TEB layout has been frozen for years and we'd need
PDB symbol resolution against ntdll structs (which DbgHelp doesn't expose
without TYPE info).

If a field ever moves on a future build the right fix is to bump the constant
here, not to invent runtime offset extraction. Don't go down that road.
"""

import ctypes
import struct
from collections import OrderedDict
from ctypes import byref, sizeof

from ..utils.constants import (
    ntdll, PROCESS_BASIC_INFORMATION, ProcessBasicInformation,
)
from .memory import (
    read_memory_safe, read_ptr, read_qword, read_dword, read_word,
    read_byte, read_wstring,
)


# ---------------------------------------------------------------------------
# PEB x64 offsets (stable across Win10/11)
# ---------------------------------------------------------------------------

PEB_X64 = OrderedDict([
    ("InheritedAddressSpace",          (0x000, "u8")),
    ("ReadImageFileExecOptions",       (0x001, "u8")),
    ("BeingDebugged",                  (0x002, "u8")),
    ("BitField",                       (0x003, "u8")),
    ("Mutant",                         (0x008, "ptr")),
    ("ImageBaseAddress",               (0x010, "ptr")),
    ("Ldr",                            (0x018, "ptr")),
    ("ProcessParameters",              (0x020, "ptr")),
    ("SubSystemData",                  (0x028, "ptr")),
    ("ProcessHeap",                    (0x030, "ptr")),
    ("FastPebLock",                    (0x038, "ptr")),
    ("AtlThunkSListPtr",               (0x040, "ptr")),
    ("IFEOKey",                        (0x048, "ptr")),
    ("CrossProcessFlags",              (0x050, "u32")),
    ("KernelCallbackTable",            (0x058, "ptr")),
    ("SystemReserved",                 (0x060, "u32")),
    ("AtlThunkSListPtr32",             (0x064, "u32")),
    ("ApiSetMap",                      (0x068, "ptr")),
    ("TlsExpansionCounter",            (0x070, "u32")),
    ("TlsBitmap",                      (0x078, "ptr")),
    ("ReadOnlySharedMemoryBase",       (0x088, "ptr")),
    ("SharedData",                     (0x090, "ptr")),
    ("ReadOnlyStaticServerData",       (0x098, "ptr")),
    ("AnsiCodePageData",               (0x0a0, "ptr")),
    ("OemCodePageData",                (0x0a8, "ptr")),
    ("UnicodeCaseTableData",           (0x0b0, "ptr")),
    ("NumberOfProcessors",             (0x0b8, "u32")),
    ("NtGlobalFlag",                   (0x0bc, "u32")),
    ("HeapSegmentReserve",             (0x0c8, "ptr")),
    ("HeapSegmentCommit",              (0x0d0, "ptr")),
    ("NumberOfHeaps",                  (0x0e8, "u32")),
    ("MaximumNumberOfHeaps",           (0x0ec, "u32")),
    ("ProcessHeaps",                   (0x0f0, "ptr")),
    ("GdiSharedHandleTable",           (0x0f8, "ptr")),
    ("ProcessStarterHelper",           (0x100, "ptr")),
    ("GdiDCAttributeList",             (0x108, "u32")),
    ("LoaderLock",                     (0x110, "ptr")),
    ("OSMajorVersion",                 (0x118, "u32")),
    ("OSMinorVersion",                 (0x11c, "u32")),
    ("OSBuildNumber",                  (0x120, "u16")),
    ("OSCSDVersion",                   (0x122, "u16")),
    ("OSPlatformId",                   (0x124, "u32")),
    ("ImageSubsystem",                 (0x128, "u32")),
    ("ImageSubsystemMajorVersion",     (0x12c, "u32")),
    ("ImageSubsystemMinorVersion",     (0x130, "u32")),
    ("ActiveProcessAffinityMask",      (0x138, "ptr")),
    ("SessionId",                      (0x2c0, "u32")),
])


# ---------------------------------------------------------------------------
# TEB x64 offsets
# ---------------------------------------------------------------------------

TEB_X64 = OrderedDict([
    ("NtTib.ExceptionList",            (0x000, "ptr")),
    ("NtTib.StackBase",                (0x008, "ptr")),
    ("NtTib.StackLimit",               (0x010, "ptr")),
    ("NtTib.SubSystemTib",             (0x018, "ptr")),
    ("NtTib.FiberData",                (0x020, "ptr")),
    ("NtTib.ArbitraryUserPointer",     (0x028, "ptr")),
    ("NtTib.Self",                     (0x030, "ptr")),
    ("EnvironmentPointer",             (0x038, "ptr")),
    ("ClientId.UniqueProcess",         (0x040, "ptr")),
    ("ClientId.UniqueThread",          (0x048, "ptr")),
    ("ActiveRpcHandle",                (0x050, "ptr")),
    ("ThreadLocalStoragePointer",      (0x058, "ptr")),
    ("ProcessEnvironmentBlock",        (0x060, "ptr")),
    ("LastErrorValue",                 (0x068, "u32")),
    ("CountOfOwnedCriticalSections",   (0x06c, "u32")),
    ("CsrClientThread",                (0x070, "ptr")),
    ("Win32ThreadInfo",                (0x078, "ptr")),
    ("CurrentLocale",                  (0x108, "u32")),
    ("FpSoftwareStatusRegister",       (0x10c, "u32")),
    ("ExceptionCode",                  (0x2c0, "u32")),
    ("LastStatusValue",                (0x1250, "u32")),
    ("StaticUnicodeString.Buffer",     (0x1258, "ptr")),
    ("DeallocationStack",              (0x1478, "ptr")),
    ("TlsSlots",                       (0x1480, "ptr")),  # array start
])


# ---------------------------------------------------------------------------
# RTL_USER_PROCESS_PARAMETERS — useful for command line / env / std handles
# ---------------------------------------------------------------------------

RTL_USER_PROCESS_PARAMS_X64 = OrderedDict([
    ("Flags",                  (0x008, "u32")),
    ("DebugFlags",             (0x00c, "u32")),
    ("ConsoleHandle",          (0x010, "ptr")),
    ("ConsoleFlags",           (0x018, "u32")),
    ("StandardInput",          (0x020, "ptr")),
    ("StandardOutput",         (0x028, "ptr")),
    ("StandardError",          (0x030, "ptr")),
    # CurrentDirectory is a CURDIR { UNICODE_STRING DosPath; HANDLE Handle; }
    ("CurrentDirectoryPath",   (0x038, "unicode_string")),
    ("CurrentDirectoryHandle", (0x048, "ptr")),
    ("DllPath",                (0x050, "unicode_string")),
    ("ImagePathName",          (0x060, "unicode_string")),
    ("CommandLine",            (0x070, "unicode_string")),
    ("Environment",            (0x080, "ptr")),
    ("WindowTitle",            (0x0b0, "unicode_string")),
    ("DesktopInfo",            (0x0c0, "unicode_string")),
    ("ShellInfo",              (0x0d0, "unicode_string")),
    ("RuntimeData",            (0x0e0, "unicode_string")),
])


# PEB_LDR_DATA — used by `peb modules`
PEB_LDR_DATA_X64 = OrderedDict([
    ("Length",                          (0x000, "u32")),
    ("Initialized",                     (0x004, "u8")),
    ("SsHandle",                        (0x008, "ptr")),
    ("InLoadOrderModuleList.Flink",     (0x010, "ptr")),
    ("InLoadOrderModuleList.Blink",     (0x018, "ptr")),
    ("InMemoryOrderModuleList.Flink",   (0x020, "ptr")),
    ("InMemoryOrderModuleList.Blink",   (0x028, "ptr")),
    ("InInitOrderModuleList.Flink",     (0x030, "ptr")),
    ("InInitOrderModuleList.Blink",     (0x038, "ptr")),
])


# ---------------------------------------------------------------------------
# Thread basic info  (NtQueryInformationThread → ThreadBasicInformation)
# ---------------------------------------------------------------------------

class CLIENT_ID(ctypes.Structure):
    _fields_ = [
        ("UniqueProcess", ctypes.c_void_p),
        ("UniqueThread",  ctypes.c_void_p),
    ]


class THREAD_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("ExitStatus",      ctypes.c_long),
        ("TebBaseAddress",  ctypes.c_void_p),
        ("ClientId",        CLIENT_ID),
        ("AffinityMask",    ctypes.c_void_p),
        ("Priority",        ctypes.c_long),
        ("BasePriority",    ctypes.c_long),
    ]


_ThreadBasicInformation = 0  # THREADINFOCLASS

# Lazy bind once
_NtQueryInformationThread = None


def _get_nt_query_thread():
    global _NtQueryInformationThread
    if _NtQueryInformationThread is None:
        ntdll.NtQueryInformationThread.argtypes = [
            ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
            ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong),
        ]
        ntdll.NtQueryInformationThread.restype = ctypes.c_long
        _NtQueryInformationThread = ntdll.NtQueryInformationThread
    return _NtQueryInformationThread


def get_peb_address(process_handle):
    """Return PebBaseAddress from NtQueryInformationProcess, or None."""
    pbi = PROCESS_BASIC_INFORMATION()
    ret_len = ctypes.c_ulong(0)
    status = ntdll.NtQueryInformationProcess(
        process_handle, ProcessBasicInformation,
        byref(pbi), sizeof(pbi), byref(ret_len),
    )
    if status != 0 or not pbi.PebBaseAddress:
        return None
    return pbi.PebBaseAddress


def get_teb_address(thread_handle):
    """Return TebBaseAddress for a thread via NtQueryInformationThread."""
    qti = _get_nt_query_thread()
    tbi = THREAD_BASIC_INFORMATION()
    ret_len = ctypes.c_ulong(0)
    status = qti(
        thread_handle, _ThreadBasicInformation,
        byref(tbi), sizeof(tbi), byref(ret_len),
    )
    if status != 0 or not tbi.TebBaseAddress:
        return None
    return tbi.TebBaseAddress


# ---------------------------------------------------------------------------
# Field readers
# ---------------------------------------------------------------------------

def _read_field(process_handle, base, offset, kind):
    """Read a single field. Returns int, or None on read failure."""
    addr = base + offset
    if kind == "ptr":
        return read_qword(process_handle, addr)
    if kind == "u64":
        return read_qword(process_handle, addr)
    if kind == "u32":
        return read_dword(process_handle, addr)
    if kind == "u16":
        return read_word(process_handle, addr)
    if kind == "u8":
        return read_byte(process_handle, addr)
    if kind == "unicode_string":
        return _read_unicode_string(process_handle, addr)
    return None


def _read_unicode_string(process_handle, addr):
    """Read a UNICODE_STRING { USHORT Length; USHORT MaxLen; PWSTR Buffer; }
    on x64. Returns the buffer text (Python str), or None.
    """
    length = read_word(process_handle, addr)
    if length is None:
        return None
    if length == 0:
        return ""
    # +0: Length, +2: MaxLen, +4: padding, +8: Buffer (x64)
    buffer_ptr = read_qword(process_handle, addr + 8)
    if not buffer_ptr:
        return ""
    raw = read_memory_safe(process_handle, buffer_ptr, length)
    if not raw:
        return None
    try:
        return raw.decode("utf-16-le", errors="replace")
    except Exception:
        return raw.hex()


def read_struct(process_handle, base, layout):
    """Read every field in a layout dict. Returns dict name->value (or None)."""
    out = OrderedDict()
    for name, (off, kind) in layout.items():
        out[name] = _read_field(process_handle, base, off, kind)
    return out


# ---------------------------------------------------------------------------
# High level helpers used by the commands
# ---------------------------------------------------------------------------

def read_peb(process_handle):
    """Return (peb_address, parsed_peb_dict)."""
    peb = get_peb_address(process_handle)
    if peb is None:
        return None, None
    return peb, read_struct(process_handle, peb, PEB_X64)


def read_teb(thread_handle, process_handle):
    """Return (teb_address, parsed_teb_dict)."""
    teb = get_teb_address(thread_handle)
    if teb is None:
        return None, None
    return teb, read_struct(process_handle, teb, TEB_X64)


def read_process_parameters(process_handle, params_addr):
    """Parse RTL_USER_PROCESS_PARAMETERS at the given address."""
    if not params_addr:
        return None
    return read_struct(process_handle, params_addr, RTL_USER_PROCESS_PARAMS_X64)


def read_environment_block(process_handle, env_addr, max_bytes=0x4000):
    """Read the environment block: a sequence of UTF-16 KEY=VALUE strings
    terminated by an extra null. Returns a list of strings.
    """
    if not env_addr:
        return []
    raw = read_memory_safe(process_handle, env_addr, max_bytes)
    if not raw:
        return []
    out = []
    i = 0
    while i + 2 <= len(raw):
        # find next double-null pair (end of one string)
        j = i
        while j + 2 <= len(raw):
            if raw[j] == 0 and raw[j + 1] == 0:
                break
            j += 2
        if j == i:
            break  # double-null at start = end of block
        try:
            s = raw[i:j].decode("utf-16-le", errors="replace")
        except Exception:
            s = ""
        if s:
            out.append(s)
        i = j + 2
    return out


def read_ldr_modules(process_handle, ldr_addr, max_modules=512):
    """Walk PEB.Ldr.InLoadOrderModuleList → list of (base, size, name, fullpath).

    Each LDR_DATA_TABLE_ENTRY (x64):
        +0x00 InLoadOrderLinks   (LIST_ENTRY)
        +0x10 InMemoryOrderLinks (LIST_ENTRY)
        +0x20 InInitOrderLinks   (LIST_ENTRY)
        +0x30 DllBase            (PVOID)
        +0x38 EntryPoint         (PVOID)
        +0x40 SizeOfImage        (ULONG)
        +0x48 FullDllName        (UNICODE_STRING)
        +0x58 BaseDllName        (UNICODE_STRING)
    """
    if not ldr_addr:
        return []
    list_head = ldr_addr + 0x10  # InLoadOrderModuleList
    first = read_qword(process_handle, list_head)  # Flink
    if not first:
        return []

    out = []
    cur = first
    visited = set()
    while cur and cur != list_head and len(out) < max_modules:
        if cur in visited:
            break
        visited.add(cur)
        # entry begins at cur (LDR is reached via InLoadOrderLinks @ 0)
        entry = cur
        dll_base = read_qword(process_handle, entry + 0x30)
        size_img = read_dword(process_handle, entry + 0x40)
        full_name = _read_unicode_string(process_handle, entry + 0x48)
        base_name = _read_unicode_string(process_handle, entry + 0x58)
        if dll_base:
            out.append({
                "base":  dll_base,
                "size":  size_img or 0,
                "name":  base_name or "",
                "path":  full_name or "",
                "entry": entry,
            })
        nxt = read_qword(process_handle, cur)  # Flink
        if not nxt:
            break
        cur = nxt
    return out
