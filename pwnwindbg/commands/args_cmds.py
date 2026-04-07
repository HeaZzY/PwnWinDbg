"""args / argv — show how the debuggee was launched.

Reads PEB.ProcessParameters and reconstructs the parsed argv via
CommandLineToArgvW (called inside the debugger process — the parser is
locale-/process-independent so this is safe).
"""

import ctypes
from ctypes import wintypes

from rich.text import Text

from ..display.formatters import banner, console, error, info
from ..core.peb_teb import read_peb, read_process_parameters


_shell32 = ctypes.windll.shell32
_kernel32 = ctypes.windll.kernel32

_CommandLineToArgvW = _shell32.CommandLineToArgvW
_CommandLineToArgvW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
_CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)

_LocalFree = _kernel32.LocalFree
_LocalFree.argtypes = [wintypes.HLOCAL]
_LocalFree.restype = wintypes.HLOCAL


def parse_command_line(cmdline):
    """Parse a Windows command line into argv via CommandLineToArgvW."""
    if not cmdline:
        return []
    argc = ctypes.c_int(0)
    argv_ptr = _CommandLineToArgvW(cmdline, ctypes.byref(argc))
    if not argv_ptr:
        return []
    try:
        return [argv_ptr[i] for i in range(argc.value)]
    finally:
        _LocalFree(ctypes.cast(argv_ptr, wintypes.HLOCAL))


def cmd_args(debugger, args):
    """Show argv / image path / cwd / window title for the debuggee.

    Reads PEB.ProcessParameters which is exactly the source NT uses to seed
    the C runtime's argv (CRT pulls CommandLine and parses it the same way
    we do here via CommandLineToArgvW).
    """
    if not debugger.process_handle:
        error("No process attached")
        return None

    peb_addr, peb = read_peb(debugger.process_handle)
    if peb_addr is None:
        error("Failed to query PEB")
        return None
    params_addr = peb.get("ProcessParameters")
    if not params_addr:
        error("PEB.ProcessParameters is NULL")
        return None
    params = read_process_parameters(debugger.process_handle, params_addr)
    if not params:
        error("Failed to read RTL_USER_PROCESS_PARAMETERS")
        return None

    image_path  = params.get("ImagePathName") or ""
    cmdline     = params.get("CommandLine")  or ""
    cwd         = params.get("CurrentDirectoryPath") or ""
    title       = params.get("WindowTitle") or ""

    banner(f"Process arguments  (RTL_USER_PROCESS_PARAMETERS @ {params_addr:#x})")

    def _kv(k, v, style="bright_white"):
        text = Text()
        text.append(f"  {k:14s} ", style="bright_yellow")
        text.append(v if v else "<none>", style=style if v else "bright_black")
        console.print(text)

    _kv("ImagePath",   image_path)
    _kv("CommandLine", cmdline)
    _kv("CurrentDir",  cwd)
    _kv("WindowTitle", title, style="bright_cyan")

    parsed = parse_command_line(cmdline)
    console.print()
    console.print(Text(f"  argc = {len(parsed)}", style="bright_green"))
    for i, a in enumerate(parsed):
        line = Text()
        line.append(f"  argv[{i}] ", style="bright_yellow")
        line.append(f'"{a}"', style="bright_cyan")
        console.print(line)
    return None
