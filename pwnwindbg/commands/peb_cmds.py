"""PEB / TEB introspection commands.

    peb                show summary of the Process Environment Block
    peb -v             show every PEB field
    peb modules        walk PEB.Ldr.InLoadOrderModuleList
    peb env            dump the environment block
    peb params         dump RTL_USER_PROCESS_PARAMETERS

    teb                show summary of the active thread's TEB
    teb -v             show every TEB field
    teb <tid>          show TEB of a specific thread id
    teb all            show TEB of every known thread
"""

from rich.table import Table
from rich.text import Text

from ..display.formatters import (
    error, info, success, warn, console, banner,
)
from ..core.peb_teb import (
    PEB_X64, TEB_X64, RTL_USER_PROCESS_PARAMS_X64,
    read_peb, read_teb, read_process_parameters,
    read_environment_block, read_ldr_modules,
    get_peb_address, get_teb_address,
)


# ---------------------------------------------------------------------------
# peb
# ---------------------------------------------------------------------------

def cmd_peb(debugger, args):
    if not debugger.process_handle:
        error("No process attached")
        return None
    if debugger.is_wow64:
        warn("WoW64 process: showing the 64-bit PEB only")

    parts = args.strip().split()
    sub = parts[0].lower() if parts else ""

    if sub in ("modules", "mods", "lm", "m"):
        return _peb_modules(debugger)
    if sub in ("env", "environ", "environment"):
        return _peb_env(debugger)
    if sub in ("params", "param", "p", "rtl"):
        return _peb_params(debugger)

    verbose = sub in ("-v", "--verbose", "v", "all", "full")
    return _peb_show(debugger, verbose=verbose)


def _peb_show(debugger, verbose=False):
    peb_addr, peb = read_peb(debugger.process_handle)
    if peb_addr is None:
        error("Failed to query PEB address")
        return None

    banner(f"PEB @ {peb_addr:#x}")

    # Important fields shown by default
    summary_fields = [
        "BeingDebugged", "BitField", "ImageBaseAddress", "Ldr",
        "ProcessParameters", "ProcessHeap", "NumberOfHeaps", "ProcessHeaps",
        "KernelCallbackTable", "ApiSetMap", "NtGlobalFlag",
        "OSMajorVersion", "OSMinorVersion", "OSBuildNumber",
        "ImageSubsystem", "SessionId",
    ]
    fields = list(PEB_X64.keys()) if verbose else summary_fields

    table = Table(show_header=True, border_style="cyan",
                  header_style="bold bright_white")
    table.add_column("Offset", justify="right", style="bright_yellow")
    table.add_column("Field", style="bold bright_white")
    table.add_column("Value", style="bright_cyan")
    table.add_column("Note", style="bright_black")

    for name in fields:
        if name not in PEB_X64:
            continue
        off, kind = PEB_X64[name]
        val = peb.get(name)
        table.add_row(
            f"{off:#06x}", name, _fmt_value(val, kind),
            _peb_note(name, val, debugger),
        )
    console.print(table)

    if not verbose:
        console.print(
            "  [bright_black]use `peb -v` for the full struct, "
            "`peb modules`, `peb env`, `peb params` for sub-views[/]"
        )
    return None


def _peb_note(name, val, debugger):
    if val is None:
        return ""
    if name == "BeingDebugged":
        return "[red]TRUE[/]" if val else ""
    if name == "BitField":
        bits = []
        if val & 0x01: bits.append("ImageUsesLargePages")
        if val & 0x02: bits.append("IsProtectedProcess")
        if val & 0x04: bits.append("IsImageDynamicallyRelocated")
        if val & 0x08: bits.append("SkipPatchingUser32Forwarders")
        if val & 0x10: bits.append("IsPackagedProcess")
        if val & 0x20: bits.append("IsAppContainer")
        return " | ".join(bits)
    if name == "NtGlobalFlag" and val:
        # Common heap-debugging flags
        flags = []
        if val & 0x10:    flags.append("HEAP_ENABLE_TAIL_CHECK")
        if val & 0x20:    flags.append("HEAP_ENABLE_FREE_CHECK")
        if val & 0x40:    flags.append("HEAP_VALIDATE_PARAMETERS")
        if val & 0x70000000: flags.append("PAGE_HEAP")
        return " | ".join(flags) if flags else f"raw={val:#x}"
    if name == "ImageBaseAddress" and val and debugger.symbols:
        sym = debugger.symbols.resolve_address(val) or ""
        return sym
    if name == "ImageSubsystem":
        return {1: "NATIVE", 2: "GUI", 3: "CONSOLE", 5: "OS2_CUI",
                7: "POSIX_CUI", 9: "WIN_CE_GUI", 10: "EFI_APPLICATION"}.get(val, "")
    if name in ("Ldr", "ProcessParameters", "ProcessHeap",
                "KernelCallbackTable", "ApiSetMap"):
        if val and debugger.symbols:
            return debugger.symbols.resolve_address(val) or ""
    return ""


def _peb_modules(debugger):
    peb_addr, peb = read_peb(debugger.process_handle)
    if peb_addr is None:
        error("Failed to query PEB")
        return None
    ldr = peb.get("Ldr")
    if not ldr:
        error("PEB.Ldr is NULL")
        return None

    mods = read_ldr_modules(debugger.process_handle, ldr)
    if not mods:
        warn("PEB_LDR_DATA module list is empty")
        return None

    banner(f"PEB.Ldr modules ({len(mods)})")
    table = Table(show_header=True, border_style="cyan",
                  header_style="bold bright_white")
    table.add_column("Base", justify="right", style="bright_cyan")
    table.add_column("Size", justify="right", style="bright_white")
    table.add_column("Name", style="bold bright_green")
    table.add_column("Path", style="bright_black")

    for m in mods:
        table.add_row(
            f"{m['base']:#018x}",
            f"{m['size']:#x}",
            m['name'],
            m['path'],
        )
    console.print(table)
    return None


def _peb_env(debugger):
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
    env_addr = params.get("Environment")
    if not env_addr:
        error("ProcessParameters.Environment is NULL")
        return None

    entries = read_environment_block(debugger.process_handle, env_addr)
    banner(f"Environment @ {env_addr:#x}  ({len(entries)} variables)")
    for s in entries:
        if "=" in s:
            k, _, v = s.partition("=")
            console.print(f"  [bright_cyan]{k}[/]=[bright_white]{v}[/]")
        else:
            console.print(f"  [bright_white]{s}[/]")
    return None


def _peb_params(debugger):
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

    banner(f"RTL_USER_PROCESS_PARAMETERS @ {params_addr:#x}")
    table = Table(show_header=True, border_style="cyan",
                  header_style="bold bright_white")
    table.add_column("Offset", justify="right", style="bright_yellow")
    table.add_column("Field", style="bold bright_white")
    table.add_column("Value", style="bright_cyan")

    for name, (off, kind) in RTL_USER_PROCESS_PARAMS_X64.items():
        val = params.get(name)
        table.add_row(f"{off:#06x}", name, _fmt_value(val, kind))
    console.print(table)
    return None


# ---------------------------------------------------------------------------
# teb
# ---------------------------------------------------------------------------

def cmd_teb(debugger, args):
    if not debugger.process_handle:
        error("No process attached")
        return None
    if debugger.is_wow64:
        warn("WoW64 process: showing the 64-bit TEB only")

    parts = args.strip().split()
    sub = parts[0].lower() if parts else ""

    if sub == "all":
        return _teb_all(debugger)

    verbose = False
    tid = None
    for p in parts:
        pl = p.lower()
        if pl in ("-v", "--verbose", "v", "full"):
            verbose = True
        else:
            try:
                tid = int(p, 0)
            except ValueError:
                error(f"Invalid argument: {p}")
                return None

    if tid is None:
        tid = debugger.active_thread_id
    th = debugger.threads.get(tid) if tid else None
    if th is None:
        error(f"No thread handle for tid {tid}")
        return None
    return _teb_show(debugger, tid, th, verbose)


def _teb_show(debugger, tid, thread_handle, verbose=False):
    teb_addr, teb = read_teb(thread_handle, debugger.process_handle)
    if teb_addr is None:
        error(f"Failed to query TEB for tid {tid}")
        return None

    banner(f"TEB[tid={tid}] @ {teb_addr:#x}")

    summary_fields = [
        "NtTib.StackBase", "NtTib.StackLimit", "NtTib.Self",
        "NtTib.ExceptionList", "ClientId.UniqueProcess",
        "ClientId.UniqueThread", "ProcessEnvironmentBlock",
        "ThreadLocalStoragePointer", "LastErrorValue",
        "LastStatusValue", "DeallocationStack",
    ]
    fields = list(TEB_X64.keys()) if verbose else summary_fields

    table = Table(show_header=True, border_style="cyan",
                  header_style="bold bright_white")
    table.add_column("Offset", justify="right", style="bright_yellow")
    table.add_column("Field", style="bold bright_white")
    table.add_column("Value", style="bright_cyan")
    table.add_column("Note", style="bright_black")

    for name in fields:
        if name not in TEB_X64:
            continue
        off, kind = TEB_X64[name]
        val = teb.get(name)
        table.add_row(
            f"{off:#06x}", name, _fmt_value(val, kind),
            _teb_note(name, val, debugger),
        )
    console.print(table)

    if not verbose:
        console.print(
            "  [bright_black]use `teb -v` for the full struct, "
            "`teb all` to list every known thread[/]"
        )
    return None


def _teb_note(name, val, debugger):
    if val is None or not val:
        return ""
    if name == "NtTib.ExceptionList":
        return "(SEH chain head — x86 only on x64 it's used by structured WOW)"
    if name == "ProcessEnvironmentBlock":
        return "→ PEB"
    if name == "ClientId.UniqueProcess":
        return f"pid={val}"
    if name == "ClientId.UniqueThread":
        return f"tid={val}"
    if name == "NtTib.Self":
        return "(self ref)"
    return ""


def _teb_all(debugger):
    if not debugger.threads:
        warn("No tracked threads")
        return None

    banner(f"TEBs ({len(debugger.threads)} threads)")
    table = Table(show_header=True, border_style="cyan",
                  header_style="bold bright_white")
    table.add_column("Tid", justify="right", style="bright_yellow")
    table.add_column("TEB", style="bright_cyan")
    table.add_column("StackBase", style="bright_white")
    table.add_column("StackLimit", style="bright_white")
    table.add_column("LastError", justify="right", style="bright_magenta")

    for tid, th in debugger.threads.items():
        teb_addr, teb = read_teb(th, debugger.process_handle)
        if teb_addr is None:
            table.add_row(str(tid), "[red]?[/]", "", "", "")
            continue
        sb = teb.get("NtTib.StackBase") or 0
        sl = teb.get("NtTib.StackLimit") or 0
        le = teb.get("LastErrorValue") or 0
        marker = " *" if tid == debugger.active_thread_id else ""
        table.add_row(
            f"{tid}{marker}",
            f"{teb_addr:#x}",
            f"{sb:#x}" if sb else "",
            f"{sl:#x}" if sl else "",
            f"{le}" if le else "",
        )
    console.print(table)
    console.print("  [bright_black]* = active thread[/]")
    return None


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _fmt_value(val, kind):
    if val is None:
        return "[red]?[/]"
    if isinstance(val, str):
        return val if val else "[bright_black](empty)[/]"
    if kind == "ptr":
        return f"{val:#018x}" if val else "[bright_black]NULL[/]"
    if kind in ("u64", "u32", "u16", "u8"):
        return f"{val:#x}" if val > 9 else f"{val}"
    return str(val)
