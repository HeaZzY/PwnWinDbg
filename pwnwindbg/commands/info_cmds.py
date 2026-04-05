"""Info commands: info proc, checksec, iat/got, info maps, info functions."""

import os
from ..display.formatters import (
    display_process_info, display_checksec, display_iat,
    display_vmmap, error, info, banner, console,
)


def cmd_info_proc(debugger, args):
    """Show process info: info proc"""
    proc_info = {
        "PID": debugger.process_id or "N/A",
        "Executable": debugger.exe_path or "N/A",
        "Architecture": "x86 (WoW64)" if debugger.is_wow64 else "x64",
        "Pointer size": f"{debugger.ptr_size} bytes",
        "Image base": f"{debugger.image_base:#x}" if debugger.image_base else "N/A",
        "State": debugger.state,
        "Active TID": debugger.active_thread_id or "N/A",
        "Threads": len(debugger.threads),
        "Modules": len(debugger.symbols.modules),
    }
    display_process_info(proc_info)
    return None


def cmd_checksec(debugger, args):
    """Show PE mitigations: checksec"""
    path = args.strip() if args.strip() else debugger.exe_path
    if not path or not os.path.exists(path):
        error("No executable path available. Use: checksec <path>")
        return None

    from ..analysis.pe_info import checksec
    results = checksec(path)
    display_checksec(results)
    return None


def cmd_iat(debugger, args):
    """Show Import Address Table: iat / got"""
    path = args.strip() if args.strip() else debugger.exe_path
    if not path or not os.path.exists(path):
        error("No executable path available")
        return None

    from ..analysis.pe_info import get_iat
    entries = get_iat(path)
    if not entries:
        error("No imports found")
        return None

    display_iat(entries, debugger.ptr_size)
    return None


def cmd_vmmap(debugger, args):
    """Show memory map: vmmap / info maps"""
    if not debugger.process_handle:
        error("No process attached")
        return None

    regions = debugger.get_vmmap()
    display_vmmap(regions, symbol_resolver=debugger.symbols.resolve_address,
                  ptr_size=debugger.ptr_size)
    return None


def cmd_modules(debugger, args):
    """List loaded modules: modules"""
    if not debugger.process_handle:
        error("No process attached")
        return None

    # Refresh
    debugger.symbols.refresh_modules(debugger.process_id)

    banner("MODULES")
    from rich.text import Text
    for mod in debugger.symbols.modules:
        text = Text()
        text.append(f"  {mod.base_address:#018x}", style="bright_cyan")
        text.append(f" - {mod.end_address:#018x}", style="bright_cyan")
        text.append(f"  {mod.size:#010x}", style="white")
        text.append(f"  {mod.name}", style="bright_magenta")
        console.print(text)

    return None


def cmd_functions(debugger, args):
    """List functions from PE exports and known symbols: functions / info functions"""
    if not debugger.exe_path or not os.path.exists(debugger.exe_path):
        error("No executable path available")
        return None

    import pefile
    from rich.text import Text

    filter_str = args.strip().lower() if args.strip() else None

    banner("FUNCTIONS")

    count = 0

    # 1. PE exports (for DLLs or executables with exports)
    for mod in debugger.symbols.modules:
        if not mod.path or not os.path.exists(mod.path):
            continue
        try:
            pe = pefile.PE(mod.path, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']]
            )
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        fname = exp.name.decode('utf-8', errors='replace')
                        addr = mod.base_address + exp.address
                        if filter_str and filter_str not in fname.lower():
                            continue
                        text = Text()
                        text.append(f"  {addr:#010x}", style="bright_cyan")
                        text.append(f"  {mod.name}!", style="bright_black")
                        text.append(fname, style="bright_white")
                        console.print(text)
                        count += 1
            pe.close()
        except Exception:
            continue

    # 2. PE entry point and known named sections
    try:
        pe = pefile.PE(debugger.exe_path, fast_load=True)
        ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        # Find the exe module to get actual base
        exe_base = debugger.image_base or 0
        for mod in debugger.symbols.modules:
            if mod.path and os.path.normcase(mod.path) == os.path.normcase(debugger.exe_path):
                exe_base = mod.base_address
                break

        ep_va = exe_base + ep_rva
        exe_name = os.path.basename(debugger.exe_path)
        text = Text()
        text.append(f"  {ep_va:#010x}", style="bright_cyan")
        text.append(f"  {exe_name}!", style="bright_black")
        text.append("_entry", style="bold bright_green")
        console.print(text)
        count += 1

        # Import thunks as callable function addresses
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']]
        )
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for dll_entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = dll_entry.dll.decode('utf-8', errors='replace')
                for imp in dll_entry.imports:
                    if imp.name:
                        fname = imp.name.decode('utf-8', errors='replace')
                        iat_addr = imp.address
                        if filter_str and filter_str not in fname.lower() and filter_str not in dll_name.lower():
                            continue
                        text = Text()
                        text.append(f"  {iat_addr:#010x}", style="bright_cyan")
                        text.append(f"  {dll_name}!", style="bright_black")
                        text.append(fname, style="white")
                        text.append("  (IAT)", style="bright_black")
                        console.print(text)
                        count += 1
        pe.close()
    except Exception:
        pass

    if count == 0:
        console.print("  No functions found.", style="bright_black")
        if filter_str:
            console.print(f"  (filter: '{filter_str}')", style="bright_black")
    else:
        console.print(f"\n  [bright_black]{count} functions listed[/]")

    return None


def cmd_info(debugger, args):
    """Info dispatcher: info <subcmd>"""
    parts = args.strip().split(None, 1)
    if not parts:
        error("Usage: info <proc|maps|modules|functions>")
        return None

    subcmd = parts[0].lower()
    rest = parts[1] if len(parts) > 1 else ""

    dispatch = {
        "proc": cmd_info_proc,
        "maps": cmd_vmmap,
        "modules": cmd_modules,
        "functions": cmd_functions,
        "func": cmd_functions,
    }

    handler = dispatch.get(subcmd)
    if handler:
        return handler(debugger, rest)
    else:
        error(f"Unknown info subcommand: {subcmd}  (valid: proc, maps, modules, functions)")
        return None
