"""threads — list every thread in the debuggee with TEB / IP / name.

For each thread we collect:

- TID and the active marker (`*`) for the currently selected thread
- TEB base via NtQueryInformationThread(ThreadBasicInformation)
- Current RIP (or EIP under WoW64) — symbolized
- Last error value (TEB+0x68 / +0x34) — handy when a thread is parked
  inside a syscall return path
- Thread name via GetThreadDescription (Win10 1607+) when available
- Suspend count: read non-destructively by SuspendThread/ResumeThread

`thread <tid>` switches the active thread (used by other commands like
`regs`, `bt`, `disasm`).
"""

import ctypes
from ctypes import wintypes, byref

from rich.table import Table

from ..display.formatters import banner, console, error, info, success, warn
from ..core.peb_teb import get_teb_address
from ..core.registers import get_context, get_ip
from ..core.memory import read_dword


_kernel32 = ctypes.windll.kernel32

# GetThreadDescription is Win10 1607+, fall back gracefully if missing.
try:
    _GetThreadDescription = _kernel32.GetThreadDescription
    _GetThreadDescription.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.LPWSTR)]
    _GetThreadDescription.restype = ctypes.c_long  # HRESULT
except AttributeError:
    _GetThreadDescription = None

_LocalFree = _kernel32.LocalFree
_LocalFree.argtypes = [wintypes.HLOCAL]
_LocalFree.restype = wintypes.HLOCAL

_SuspendThread = _kernel32.SuspendThread
_SuspendThread.argtypes = [wintypes.HANDLE]
_SuspendThread.restype = wintypes.DWORD

_ResumeThread = _kernel32.ResumeThread
_ResumeThread.argtypes = [wintypes.HANDLE]
_ResumeThread.restype = wintypes.DWORD


def _thread_name(handle):
    if _GetThreadDescription is None:
        return ""
    pbuf = wintypes.LPWSTR()
    hr = _GetThreadDescription(handle, byref(pbuf))
    if hr < 0 or not pbuf:
        return ""
    try:
        return pbuf.value or ""
    finally:
        _LocalFree(ctypes.cast(pbuf, wintypes.HLOCAL))


def _suspend_count(handle):
    """Read suspend count without changing it.

    SuspendThread returns the *previous* count and increments it; we have
    to undo with ResumeThread immediately. The pair is atomic w.r.t. the
    thread itself but not w.r.t. concurrent suspends — good enough for an
    interactive list.
    """
    prev = _SuspendThread(handle)
    if prev == 0xFFFFFFFF:
        return None
    _ResumeThread(handle)
    return prev


def cmd_threads(debugger, args):
    """List threads of the debuggee, or switch active thread with `thread <tid>`."""
    if not debugger.process_handle:
        error("No process attached")
        return None
    if not debugger.threads:
        warn("No tracked threads")
        return None

    parts = args.strip().split()
    if parts and parts[0].isdigit():
        target = int(parts[0])
        if target not in debugger.threads:
            error(f"Unknown TID {target}")
            return None
        debugger.active_thread_id = target
        success(f"Active thread -> {target}")
        return None

    syms = debugger.symbols
    banner(f"Threads — {len(debugger.threads)} total  (active: {debugger.active_thread_id})")

    tbl = Table(show_header=True, border_style="cyan",
                header_style="bold bright_white")
    tbl.add_column("",        style="bright_red", width=1)
    tbl.add_column("Tid",     style="bright_yellow", justify="right")
    tbl.add_column("TEB",     style="bright_blue")
    tbl.add_column("RIP",     style="bright_magenta")
    tbl.add_column("Symbol",  style="bright_white")
    tbl.add_column("Susp",    style="bright_green", justify="right")
    tbl.add_column("LastErr", style="bright_red",   justify="right")
    tbl.add_column("Name",    style="bright_cyan")

    for tid in sorted(debugger.threads.keys()):
        h = debugger.threads[tid]
        marker = "*" if tid == debugger.active_thread_id else ""

        teb = get_teb_address(h) if h else None
        teb_str = f"{teb:#x}" if teb else "?"

        ip = 0
        sym = ""
        try:
            ctx = get_context(h, debugger.is_wow64)
            ip = get_ip(ctx, debugger.is_wow64)
            if syms:
                sym = syms.resolve_address(ip) or ""
        except Exception:
            pass

        last_err = None
        if teb:
            off = 0x34 if debugger.is_wow64 else 0x68
            last_err = read_dword(debugger.process_handle, teb + off)

        susp = _suspend_count(h) if h else None
        name = _thread_name(h) if h else ""

        tbl.add_row(
            marker,
            str(tid),
            teb_str,
            f"{ip:#018x}" if ip else "?",
            sym,
            "?" if susp is None else str(susp),
            "?" if last_err is None else f"{last_err}",
            name,
        )

    console.print(tbl)
    return None
