"""Win32 / NT API prototype database for call-site argument display.

When the debugger is stopped on a `call` and the target resolves to a
known API, we use the matching prototype to (a) name the arguments
(`lpFileName` instead of `rcx`), (b) decode them with the right type
(`LPCWSTR` → wide string deref, `LPCSTR` → ANSI deref, `HANDLE` → just
the integer), and (c) pull more than the default four args from the
stack so the user sees the full call.

This is intentionally a curated, hand-edited list of the APIs that
matter most for malware analysis / pwn work — there is no automatic
prototype recovery. Adding new entries is a copy/paste job: pick the
arg names from MSDN and assign each to one of the `ArgType` constants
below.

Lookups are case-insensitive on the bare function name (without the
`module!` prefix). The same prototype is registered under both the
narrow/wide variants where it makes sense (e.g. `CreateFileA` and
`CreateFileW` differ only in the lpFileName type, but `Nt*` and `Zw*`
share an identical signature so we map both to one entry).
"""


class ArgType:
    """Type tags consumed by core.call_args._annotate_typed_value."""
    LPVOID = "lpvoid"            # generic pointer — telescope-style annotate
    LPCSTR = "lpcstr"            # ANSI null-terminated string
    LPCWSTR = "lpcwstr"          # UTF-16 null-terminated string
    HANDLE = "handle"            # opaque handle (kernel object)
    HMODULE = "hmodule"          # module base — try to resolve to module name
    DWORD = "dword"              # 32-bit unsigned, render as hex
    QWORD = "qword"              # 64-bit unsigned, render as hex
    BOOL = "bool"                # 0/1
    PUNICODE_STRING = "punicode_string"  # PUNICODE_STRING* (NT API)
    POBJECT_ATTRIBUTES = "pobject_attributes"
    SIZE_T = "size_t"            # size, render as hex


_T = ArgType


# Each entry is a list of (arg_name, ArgType). Order matches the call ABI.
_PROTOS = {
    # ----- Process / module loading -----
    "loadlibrarya": [
        ("lpLibFileName", _T.LPCSTR),
    ],
    "loadlibraryw": [
        ("lpLibFileName", _T.LPCWSTR),
    ],
    "loadlibraryexa": [
        ("lpLibFileName", _T.LPCSTR),
        ("hFile",         _T.HANDLE),
        ("dwFlags",       _T.DWORD),
    ],
    "loadlibraryexw": [
        ("lpLibFileName", _T.LPCWSTR),
        ("hFile",         _T.HANDLE),
        ("dwFlags",       _T.DWORD),
    ],
    "getprocaddress": [
        ("hModule",   _T.HMODULE),
        ("lpProcName", _T.LPCSTR),  # may also be ordinal
    ],
    "getmodulehandlea": [
        ("lpModuleName", _T.LPCSTR),
    ],
    "getmodulehandlew": [
        ("lpModuleName", _T.LPCWSTR),
    ],
    "freelibrary": [
        ("hLibModule", _T.HMODULE),
    ],

    # ----- File I/O -----
    "createfilea": [
        ("lpFileName",            _T.LPCSTR),
        ("dwDesiredAccess",       _T.DWORD),
        ("dwShareMode",           _T.DWORD),
        ("lpSecurityAttributes",  _T.LPVOID),
        ("dwCreationDisposition", _T.DWORD),
        ("dwFlagsAndAttributes",  _T.DWORD),
        ("hTemplateFile",         _T.HANDLE),
    ],
    "createfilew": [
        ("lpFileName",            _T.LPCWSTR),
        ("dwDesiredAccess",       _T.DWORD),
        ("dwShareMode",           _T.DWORD),
        ("lpSecurityAttributes",  _T.LPVOID),
        ("dwCreationDisposition", _T.DWORD),
        ("dwFlagsAndAttributes",  _T.DWORD),
        ("hTemplateFile",         _T.HANDLE),
    ],
    "readfile": [
        ("hFile",                _T.HANDLE),
        ("lpBuffer",             _T.LPVOID),
        ("nNumberOfBytesToRead", _T.DWORD),
        ("lpNumberOfBytesRead",  _T.LPVOID),
        ("lpOverlapped",         _T.LPVOID),
    ],
    "writefile": [
        ("hFile",                   _T.HANDLE),
        ("lpBuffer",                _T.LPVOID),
        ("nNumberOfBytesToWrite",   _T.DWORD),
        ("lpNumberOfBytesWritten",  _T.LPVOID),
        ("lpOverlapped",            _T.LPVOID),
    ],
    "closehandle": [
        ("hObject", _T.HANDLE),
    ],
    "deletefilea": [
        ("lpFileName", _T.LPCSTR),
    ],
    "deletefilew": [
        ("lpFileName", _T.LPCWSTR),
    ],

    # ----- Memory -----
    "virtualalloc": [
        ("lpAddress",        _T.LPVOID),
        ("dwSize",           _T.SIZE_T),
        ("flAllocationType", _T.DWORD),
        ("flProtect",        _T.DWORD),
    ],
    "virtualallocex": [
        ("hProcess",         _T.HANDLE),
        ("lpAddress",        _T.LPVOID),
        ("dwSize",           _T.SIZE_T),
        ("flAllocationType", _T.DWORD),
        ("flProtect",        _T.DWORD),
    ],
    "virtualfree": [
        ("lpAddress", _T.LPVOID),
        ("dwSize",    _T.SIZE_T),
        ("dwFreeType", _T.DWORD),
    ],
    "virtualprotect": [
        ("lpAddress",  _T.LPVOID),
        ("dwSize",     _T.SIZE_T),
        ("flNewProtect", _T.DWORD),
        ("lpflOldProtect", _T.LPVOID),
    ],
    "virtualprotectex": [
        ("hProcess",   _T.HANDLE),
        ("lpAddress",  _T.LPVOID),
        ("dwSize",     _T.SIZE_T),
        ("flNewProtect", _T.DWORD),
        ("lpflOldProtect", _T.LPVOID),
    ],
    "writeprocessmemory": [
        ("hProcess",       _T.HANDLE),
        ("lpBaseAddress",  _T.LPVOID),
        ("lpBuffer",       _T.LPVOID),
        ("nSize",          _T.SIZE_T),
        ("lpNumberOfBytesWritten", _T.LPVOID),
    ],
    "readprocessmemory": [
        ("hProcess",       _T.HANDLE),
        ("lpBaseAddress",  _T.LPVOID),
        ("lpBuffer",       _T.LPVOID),
        ("nSize",          _T.SIZE_T),
        ("lpNumberOfBytesRead", _T.LPVOID),
    ],
    "heapalloc": [
        ("hHeap",  _T.HANDLE),
        ("dwFlags", _T.DWORD),
        ("dwBytes", _T.SIZE_T),
    ],
    "heapfree": [
        ("hHeap",  _T.HANDLE),
        ("dwFlags", _T.DWORD),
        ("lpMem",  _T.LPVOID),
    ],
    "rtlallocateheap": [
        ("HeapHandle", _T.HANDLE),
        ("Flags",      _T.DWORD),
        ("Size",       _T.SIZE_T),
    ],

    # ----- Process / thread creation -----
    "createprocessa": [
        ("lpApplicationName",    _T.LPCSTR),
        ("lpCommandLine",        _T.LPCSTR),
        ("lpProcessAttributes",  _T.LPVOID),
        ("lpThreadAttributes",   _T.LPVOID),
        ("bInheritHandles",      _T.BOOL),
        ("dwCreationFlags",      _T.DWORD),
        ("lpEnvironment",        _T.LPVOID),
        ("lpCurrentDirectory",   _T.LPCSTR),
        ("lpStartupInfo",        _T.LPVOID),
        ("lpProcessInformation", _T.LPVOID),
    ],
    "createprocessw": [
        ("lpApplicationName",    _T.LPCWSTR),
        ("lpCommandLine",        _T.LPCWSTR),
        ("lpProcessAttributes",  _T.LPVOID),
        ("lpThreadAttributes",   _T.LPVOID),
        ("bInheritHandles",      _T.BOOL),
        ("dwCreationFlags",      _T.DWORD),
        ("lpEnvironment",        _T.LPVOID),
        ("lpCurrentDirectory",   _T.LPCWSTR),
        ("lpStartupInfo",        _T.LPVOID),
        ("lpProcessInformation", _T.LPVOID),
    ],
    "createremotethread": [
        ("hProcess",            _T.HANDLE),
        ("lpThreadAttributes",  _T.LPVOID),
        ("dwStackSize",         _T.SIZE_T),
        ("lpStartAddress",      _T.LPVOID),
        ("lpParameter",         _T.LPVOID),
        ("dwCreationFlags",     _T.DWORD),
        ("lpThreadId",          _T.LPVOID),
    ],
    "winexec": [
        ("lpCmdLine", _T.LPCSTR),
        ("uCmdShow",  _T.DWORD),
    ],
    "shellexecutea": [
        ("hwnd",            _T.HANDLE),
        ("lpOperation",     _T.LPCSTR),
        ("lpFile",          _T.LPCSTR),
        ("lpParameters",    _T.LPCSTR),
        ("lpDirectory",     _T.LPCSTR),
        ("nShowCmd",        _T.DWORD),
    ],
    "shellexecutew": [
        ("hwnd",            _T.HANDLE),
        ("lpOperation",     _T.LPCWSTR),
        ("lpFile",          _T.LPCWSTR),
        ("lpParameters",    _T.LPCWSTR),
        ("lpDirectory",     _T.LPCWSTR),
        ("nShowCmd",        _T.DWORD),
    ],
    "exitprocess": [
        ("uExitCode", _T.DWORD),
    ],
    "terminateprocess": [
        ("hProcess",  _T.HANDLE),
        ("uExitCode", _T.DWORD),
    ],

    # ----- Registry -----
    "regopenkeyexa": [
        ("hKey",      _T.HANDLE),
        ("lpSubKey",  _T.LPCSTR),
        ("ulOptions", _T.DWORD),
        ("samDesired", _T.DWORD),
        ("phkResult", _T.LPVOID),
    ],
    "regopenkeyexw": [
        ("hKey",      _T.HANDLE),
        ("lpSubKey",  _T.LPCWSTR),
        ("ulOptions", _T.DWORD),
        ("samDesired", _T.DWORD),
        ("phkResult", _T.LPVOID),
    ],
    "regsetvalueexa": [
        ("hKey",       _T.HANDLE),
        ("lpValueName", _T.LPCSTR),
        ("Reserved",   _T.DWORD),
        ("dwType",     _T.DWORD),
        ("lpData",     _T.LPVOID),
        ("cbData",     _T.DWORD),
    ],
    "regsetvalueexw": [
        ("hKey",       _T.HANDLE),
        ("lpValueName", _T.LPCWSTR),
        ("Reserved",   _T.DWORD),
        ("dwType",     _T.DWORD),
        ("lpData",     _T.LPVOID),
        ("cbData",     _T.DWORD),
    ],

    # ----- NT/Zw native APIs (same prototype, two names) -----
    "ntcreatefile": [
        ("FileHandle",        _T.LPVOID),
        ("DesiredAccess",     _T.DWORD),
        ("ObjectAttributes",  _T.POBJECT_ATTRIBUTES),
        ("IoStatusBlock",     _T.LPVOID),
        ("AllocationSize",    _T.LPVOID),
        ("FileAttributes",    _T.DWORD),
        ("ShareAccess",       _T.DWORD),
        ("CreateDisposition", _T.DWORD),
        ("CreateOptions",     _T.DWORD),
        ("EaBuffer",          _T.LPVOID),
        ("EaLength",          _T.DWORD),
    ],
    "ntopenfile": [
        ("FileHandle",       _T.LPVOID),
        ("DesiredAccess",    _T.DWORD),
        ("ObjectAttributes", _T.POBJECT_ATTRIBUTES),
        ("IoStatusBlock",    _T.LPVOID),
        ("ShareAccess",      _T.DWORD),
        ("OpenOptions",      _T.DWORD),
    ],
    "ntreadfile": [
        ("FileHandle",     _T.HANDLE),
        ("Event",          _T.HANDLE),
        ("ApcRoutine",     _T.LPVOID),
        ("ApcContext",     _T.LPVOID),
        ("IoStatusBlock",  _T.LPVOID),
        ("Buffer",         _T.LPVOID),
        ("Length",         _T.DWORD),
        ("ByteOffset",     _T.LPVOID),
        ("Key",            _T.LPVOID),
    ],
    "ntwritefile": [
        ("FileHandle",     _T.HANDLE),
        ("Event",          _T.HANDLE),
        ("ApcRoutine",     _T.LPVOID),
        ("ApcContext",     _T.LPVOID),
        ("IoStatusBlock",  _T.LPVOID),
        ("Buffer",         _T.LPVOID),
        ("Length",         _T.DWORD),
        ("ByteOffset",     _T.LPVOID),
        ("Key",            _T.LPVOID),
    ],
    "ntclose": [
        ("Handle", _T.HANDLE),
    ],
    "ntallocatevirtualmemory": [
        ("ProcessHandle",  _T.HANDLE),
        ("BaseAddress",    _T.LPVOID),
        ("ZeroBits",       _T.QWORD),
        ("RegionSize",     _T.LPVOID),
        ("AllocationType", _T.DWORD),
        ("Protect",        _T.DWORD),
    ],
    "ntprotectvirtualmemory": [
        ("ProcessHandle",  _T.HANDLE),
        ("BaseAddress",    _T.LPVOID),
        ("RegionSize",     _T.LPVOID),
        ("NewProtect",     _T.DWORD),
        ("OldProtect",     _T.LPVOID),
    ],
    "ntwritevirtualmemory": [
        ("ProcessHandle",   _T.HANDLE),
        ("BaseAddress",     _T.LPVOID),
        ("Buffer",          _T.LPVOID),
        ("BufferLength",    _T.SIZE_T),
        ("NumberOfBytesWritten", _T.LPVOID),
    ],

    # ----- Sockets -----
    "send": [
        ("s",     _T.HANDLE),
        ("buf",   _T.LPVOID),
        ("len",   _T.DWORD),
        ("flags", _T.DWORD),
    ],
    "recv": [
        ("s",     _T.HANDLE),
        ("buf",   _T.LPVOID),
        ("len",   _T.DWORD),
        ("flags", _T.DWORD),
    ],
    "connect": [
        ("s",       _T.HANDLE),
        ("name",    _T.LPVOID),
        ("namelen", _T.DWORD),
    ],

    # ----- Misc string / utility -----
    "lstrcmpa": [
        ("lpString1", _T.LPCSTR),
        ("lpString2", _T.LPCSTR),
    ],
    "lstrcmpw": [
        ("lpString1", _T.LPCWSTR),
        ("lpString2", _T.LPCWSTR),
    ],
    "messageboxa": [
        ("hWnd",     _T.HANDLE),
        ("lpText",   _T.LPCSTR),
        ("lpCaption", _T.LPCSTR),
        ("uType",    _T.DWORD),
    ],
    "messageboxw": [
        ("hWnd",     _T.HANDLE),
        ("lpText",   _T.LPCWSTR),
        ("lpCaption", _T.LPCWSTR),
        ("uType",    _T.DWORD),
    ],
}


# `Nt` and `Zw` versions of the same export share a single prototype.
for _name in list(_PROTOS):
    if _name.startswith("nt"):
        _PROTOS.setdefault("zw" + _name[2:], _PROTOS[_name])


def lookup(name):
    """Resolve a function name (case-insensitive) to a prototype list.

    Returns the [(arg_name, ArgType), ...] list, or None if unknown. Strips
    a trailing `+offset` since DbgHelp may name a few bytes into the prolog
    when the symbol fails to land exactly on the entry. Strips the leading
    `module!` prefix if present.
    """
    if not name:
        return None
    n = name
    if "!" in n:
        n = n.split("!", 1)[1]
    if "+" in n:
        n = n.split("+", 1)[0]
    return _PROTOS.get(n.lower())
