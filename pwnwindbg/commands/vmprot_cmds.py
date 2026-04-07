"""vmprot — change page protection of a memory region in the debuggee.

Wraps VirtualProtectEx with a friendly mnemonic argument:

    vmprot <addr> <size> rwx        — PAGE_EXECUTE_READWRITE
    vmprot <addr> <size> r-x        — PAGE_EXECUTE_READ
    vmprot <addr> <size> rw-        — PAGE_READWRITE
    vmprot <addr> <size> r--        — PAGE_READONLY
    vmprot <addr> <size> ---        — PAGE_NOACCESS

Address and size both go through the standard expression evaluator so
`vmprot ntdll+0x1000 0x100 rwx` works as expected. Returns the previous
protection so you can restore it later.

Note: this *only* changes the protection — it does not allocate, free,
or copy any memory. Pair it with `patch` / `write` to modify code that
sits in a read-only page without going through the auto-VirtualProtect
fallback in `core/memory.write_memory`.
"""

import ctypes
from ctypes import wintypes, byref

from rich.text import Text

from ..display.formatters import banner, console, error, info, success, warn
from ..utils.addr_expr import eval_expr
from ..utils.constants import (
    kernel32,
    PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY,
)


_PROT_MAP = {
    "---":  PAGE_NOACCESS,
    "noaccess": PAGE_NOACCESS,
    "r--":  PAGE_READONLY,
    "r":    PAGE_READONLY,
    "ro":   PAGE_READONLY,
    "rw-":  PAGE_READWRITE,
    "rw":   PAGE_READWRITE,
    "--x":  PAGE_EXECUTE,
    "x":    PAGE_EXECUTE,
    "r-x":  PAGE_EXECUTE_READ,
    "rx":   PAGE_EXECUTE_READ,
    "rwx":  PAGE_EXECUTE_READWRITE,
    "rwxc": PAGE_EXECUTE_WRITECOPY,
}


_PROT_NAMES = {
    PAGE_NOACCESS:           "---",
    PAGE_READONLY:           "r--",
    PAGE_READWRITE:          "rw-",
    PAGE_WRITECOPY:          "rw-c",
    PAGE_EXECUTE:            "--x",
    PAGE_EXECUTE_READ:       "r-x",
    PAGE_EXECUTE_READWRITE:  "rwx",
    PAGE_EXECUTE_WRITECOPY:  "rwxc",
}


def cmd_vmprot(debugger, args):
    """Change protection on a region. Usage: vmprot <addr> <size> <perm>"""
    if not debugger.process_handle:
        error("No process attached")
        return None

    parts = args.strip().split()
    if len(parts) != 3:
        error("Usage: vmprot <addr> <size> <perm>")
        info("  perm: ---, r--, rw-, --x, r-x, rwx")
        return None

    addr = eval_expr(debugger, parts[0])
    if addr is None:
        error(f"Cannot resolve address: {parts[0]}")
        return None

    size = eval_expr(debugger, parts[1])
    if size is None or size <= 0:
        error(f"Invalid size: {parts[1]}")
        return None

    perm_key = parts[2].lower()
    new_prot = _PROT_MAP.get(perm_key)
    if new_prot is None:
        error(f"Unknown permission: {parts[2]}")
        info("  Valid: " + ", ".join(sorted(set(_PROT_MAP.keys()))))
        return None

    old_prot = ctypes.c_ulong(0)
    ok = kernel32.VirtualProtectEx(
        debugger.process_handle,
        ctypes.c_void_p(addr),
        size,
        new_prot,
        byref(old_prot),
    )
    if not ok:
        err = ctypes.GetLastError()
        error(f"VirtualProtectEx failed (err={err})")
        return None

    old_str = _PROT_NAMES.get(old_prot.value, f"{old_prot.value:#x}")
    new_str = _PROT_NAMES.get(new_prot, f"{new_prot:#x}")
    text = Text()
    text.append("vmprot ", style="bright_black")
    text.append(f"{addr:#x}", style="bright_yellow")
    text.append(f" .. +{size:#x}  ", style="bright_black")
    text.append(old_str, style="bright_red")
    text.append(" -> ", style="bright_black")
    text.append(new_str, style="bright_green")
    console.print(text)
    success("ok")
    return None
