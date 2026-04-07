"""errno / gle — display the active thread's GetLastError value with text.

Reads TEB.LastErrorValue (offset 0x68 on x64, 0x34 on x86) for the active
thread and decodes it via FormatMessageW from the *debugger* process — the
NT status text tables are identical for every Windows process so this works
even when the debuggee is a different bitness.
"""

import ctypes
from ctypes import wintypes

from ..display.formatters import error, info, console
from ..core.peb_teb import get_teb_address
from ..core.memory import read_dword

from rich.text import Text


# FormatMessageW flags
FORMAT_MESSAGE_FROM_SYSTEM     = 0x00001000
FORMAT_MESSAGE_IGNORE_INSERTS  = 0x00000200
FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100

_kernel32 = ctypes.windll.kernel32
_FormatMessageW = _kernel32.FormatMessageW
_FormatMessageW.argtypes = [
    wintypes.DWORD, wintypes.LPCVOID, wintypes.DWORD, wintypes.DWORD,
    wintypes.LPWSTR, wintypes.DWORD, ctypes.c_void_p,
]
_FormatMessageW.restype = wintypes.DWORD


def format_win32_error(code):
    """Return the FormatMessage text for a Win32 error code, or '' on failure."""
    buf = ctypes.create_unicode_buffer(512)
    n = _FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        None, code, 0, buf, len(buf), None,
    )
    if n == 0:
        return ""
    return buf.value.strip().rstrip(".").replace("\r\n", " ")


def read_last_error(debugger):
    """Read the active thread's LastErrorValue from TEB. Returns int or None."""
    th = debugger.get_active_thread_handle()
    if not th:
        return None
    teb = get_teb_address(th)
    if not teb:
        return None
    # x64 TEB.LastErrorValue is at 0x68; x86 TEB.LastErrorValue is at 0x34.
    off = 0x34 if debugger.is_wow64 else 0x68
    return read_dword(debugger.process_handle, teb + off)


def cmd_errno(debugger, args):
    """Show the active thread's GetLastError value: errno / gle"""
    if not debugger.process_handle:
        error("No process attached")
        return None

    code = read_last_error(debugger)
    if code is None:
        error("Could not read TEB.LastErrorValue")
        return None

    text = Text()
    text.append("LastError = ", style="bright_white")
    if code == 0:
        text.append("0", style="bright_green")
        text.append("  (ERROR_SUCCESS)", style="bright_black")
    else:
        text.append(f"{code}", style="bold bright_red")
        text.append(f"  ({code:#x})", style="bright_black")
        msg = format_win32_error(code)
        if msg:
            text.append(f"  {msg}", style="bright_yellow")
    console.print(text)
    return None
