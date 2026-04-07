"""procs / ps — list running processes (system-wide).

Useful right before `attach <pid>`. Uses CreateToolhelp32Snapshot for the
basic listing and adds image path / session id via OpenProcess +
QueryFullProcessImageNameW + ProcessIdToSessionId when accessible.
"""

import ctypes
from ctypes import wintypes, byref, sizeof, Structure

from rich.table import Table

from ..display.formatters import banner, console, error, info, warn


_kernel32 = ctypes.windll.kernel32

TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
MAX_PATH = 260

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


class PROCESSENTRY32W(Structure):
    _fields_ = [
        ("dwSize",              wintypes.DWORD),
        ("cntUsage",            wintypes.DWORD),
        ("th32ProcessID",       wintypes.DWORD),
        ("th32DefaultHeapID",   ctypes.c_void_p),
        ("th32ModuleID",        wintypes.DWORD),
        ("cntThreads",          wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase",      ctypes.c_long),
        ("dwFlags",             wintypes.DWORD),
        ("szExeFile",           wintypes.WCHAR * MAX_PATH),
    ]


_CreateToolhelp32Snapshot = _kernel32.CreateToolhelp32Snapshot
_CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
_CreateToolhelp32Snapshot.restype = wintypes.HANDLE

_Process32FirstW = _kernel32.Process32FirstW
_Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
_Process32FirstW.restype = wintypes.BOOL

_Process32NextW = _kernel32.Process32NextW
_Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
_Process32NextW.restype = wintypes.BOOL

_OpenProcess = _kernel32.OpenProcess
_OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
_OpenProcess.restype = wintypes.HANDLE

_CloseHandle = _kernel32.CloseHandle
_CloseHandle.argtypes = [wintypes.HANDLE]
_CloseHandle.restype = wintypes.BOOL

_QueryFullProcessImageNameW = _kernel32.QueryFullProcessImageNameW
_QueryFullProcessImageNameW.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
]
_QueryFullProcessImageNameW.restype = wintypes.BOOL

_ProcessIdToSessionId = _kernel32.ProcessIdToSessionId
_ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
_ProcessIdToSessionId.restype = wintypes.BOOL

_IsWow64Process = _kernel32.IsWow64Process
_IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
_IsWow64Process.restype = wintypes.BOOL


def _query_image_path(pid):
    h = _OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return ""
    try:
        sz = wintypes.DWORD(MAX_PATH)
        buf = ctypes.create_unicode_buffer(MAX_PATH)
        if _QueryFullProcessImageNameW(h, 0, buf, byref(sz)):
            return buf.value
        return ""
    finally:
        _CloseHandle(h)


def _query_arch(pid):
    """Return 'x86' or 'x64' if we can probe, else ''."""
    h = _OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return ""
    try:
        wow = wintypes.BOOL(False)
        if _IsWow64Process(h, byref(wow)):
            return "x86" if wow.value else "x64"
        return ""
    finally:
        _CloseHandle(h)


def _query_session(pid):
    sid = wintypes.DWORD(0)
    if _ProcessIdToSessionId(pid, byref(sid)):
        return int(sid.value)
    return None


def _enum_processes():
    snap = _CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE or snap is None:
        return None
    out = []
    try:
        ent = PROCESSENTRY32W()
        ent.dwSize = sizeof(ent)
        ok = _Process32FirstW(snap, byref(ent))
        while ok:
            out.append((
                int(ent.th32ProcessID),
                int(ent.th32ParentProcessID),
                int(ent.cntThreads),
                ent.szExeFile,
            ))
            ok = _Process32NextW(snap, byref(ent))
    finally:
        _CloseHandle(snap)
    return out


def cmd_procs(debugger, args):
    """List running processes.

    Usage:
        procs                    — list every visible process
        procs <substring>        — case-insensitive name filter
        procs --full             — also resolve full image path (slower)
    """
    parts = args.strip().split()
    full = False
    name_filter = None
    for p in parts:
        if p in ("--full", "-f"):
            full = True
        elif p.startswith("-"):
            warn(f"Unknown flag: {p}")
        else:
            name_filter = p.lower()

    procs = _enum_processes()
    if procs is None:
        error("CreateToolhelp32Snapshot failed")
        return None

    if name_filter:
        procs = [p for p in procs if name_filter in p[3].lower()]

    procs.sort(key=lambda p: p[3].lower())
    banner(f"Processes — {len(procs)} entries")

    tbl = Table(show_header=True, border_style="cyan",
                header_style="bold bright_white")
    tbl.add_column("PID",    style="bright_yellow", justify="right")
    tbl.add_column("PPID",   style="bright_black",  justify="right")
    tbl.add_column("Thr",    style="bright_blue",   justify="right")
    tbl.add_column("Sess",   style="bright_magenta", justify="right")
    tbl.add_column("Arch",   style="bright_green")
    tbl.add_column("Name",   style="bright_white")
    if full:
        tbl.add_column("Path", style="bright_black", overflow="fold")

    for pid, ppid, nthr, name in procs:
        sess = _query_session(pid)
        arch = _query_arch(pid)
        row = [
            str(pid),
            str(ppid),
            str(nthr),
            "" if sess is None else str(sess),
            arch or "?",
            name,
        ]
        if full:
            row.append(_query_image_path(pid))
        tbl.add_row(*row)

    console.print(tbl)
    return None
