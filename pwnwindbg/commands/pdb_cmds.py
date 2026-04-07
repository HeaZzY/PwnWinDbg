"""PDB / symbol management commands.

Commands:
    pdb [status]            — show symbol path + per-module load state
    pdb path                — print current DbgHelp search path
    pdb path <new>          — set a new search path (e.g. plain dir, or srv*<cache>*<url>)
    pdb cache               — show local PDB cache directory + size
    pdb load <module|all>   — force-download PDBs for one module or every module

The default symbol path wires Microsoft's public symbol server with a local
cache under %LOCALAPPDATA%\\pwnWinDbg\\symbols. Once a PDB is downloaded the
file is reused on subsequent runs.
"""

import os

from rich.table import Table

from ..core.symbols import (
    build_default_symbol_path,
    default_symbol_cache_dir,
    MS_SYMBOL_SERVER,
)
from ..display.formatters import (
    error, info, success, warn, console, banner,
)


def cmd_pdb(debugger, args):
    """Dispatch pdb subcommands."""
    parts = args.strip().split(None, 1)
    sub = parts[0].lower() if parts else "status"
    rest = parts[1] if len(parts) > 1 else ""

    if sub in ("status", "info", ""):
        return _cmd_status(debugger)
    if sub == "path":
        return _cmd_path(debugger, rest)
    if sub == "cache":
        return _cmd_cache(debugger)
    if sub == "load":
        return _cmd_load(debugger, rest)
    if sub == "debug":
        return _cmd_debug(debugger)
    # Shortcut: `pdb all` == `pdb load all`, `pdb <module>` == `pdb load <module>`
    if sub == "all":
        return _cmd_load(debugger, "all")
    if _find_module(debugger.symbols, sub) is not None:
        return _cmd_load(debugger, sub)

    error(f"Unknown pdb subcommand: {sub}")
    info("Usage: pdb [status|path|cache|load <module|all>|debug]")
    info("Shortcut:  pdb <module>   — equivalent to 'pdb load <module>'")
    return None


# ---- subcommands ----

def _cmd_status(debugger):
    if not _check_debugger(debugger):
        return None
    sm = debugger.symbols

    # Make sure DbgHelp's view of loaded modules matches the live process
    sm.refresh_dbghelp_modules()

    sym_path = sm.get_search_path() or build_default_symbol_path()
    console.print(f"[bright_black]symbol path:[/] {sym_path}")
    console.print(f"[bright_black]cache dir:[/]   {default_symbol_cache_dir()}")
    console.print()

    if not sm.modules:
        warn("No modules loaded — run/attach a process first")
        return None

    table = Table(show_header=True, border_style="cyan", header_style="bold bright_white")
    table.add_column("Module", style="bright_cyan")
    table.add_column("Base", style="bright_yellow")
    table.add_column("Status", style="bold")
    table.add_column("Syms", justify="right", style="bright_white")
    table.add_column("Lines", justify="center")
    table.add_column("PDB", style="bright_black", overflow="fold")

    for mod in sm.modules:
        st = sm.get_module_sym_status(mod.base_address)
        if st["loaded"]:
            status = f"[green]{st['type']}[/]"
        elif st["deferred"]:
            status = "[yellow]deferred[/]"
        elif st["export_only"]:
            status = "[blue]export[/]"
        elif st["type"] == "unknown":
            status = "[red]unknown[/]"  # SymGetModuleInfo64 failed
        else:
            status = f"[red]{st['type']}[/]"
        table.add_row(
            mod.name,
            f"{mod.base_address:#x}",
            status,
            str(st["num_syms"]),
            "✓" if st["lines"] else "",
            os.path.basename(st["pdb"]) if st["pdb"] else "",
        )

    console.print(table)
    console.print()
    info("'pdb load <module>' to force-download a PDB, 'pdb load all' to grab them all")
    return None


def _cmd_path(debugger, new_path):
    if not _check_debugger(debugger):
        return None
    sm = debugger.symbols

    if not new_path:
        console.print(sm.get_search_path() or "(unset)")
        return None

    if sm.set_search_path(new_path):
        success(f"Symbol path set to: {new_path}")
    else:
        error("Failed to set symbol path")
    return None


def _cmd_cache(debugger):
    cache = default_symbol_cache_dir()
    console.print(f"[bright_black]cache:[/]  {cache}")
    if not os.path.isdir(cache):
        warn("Cache directory does not exist yet")
        return None

    total_bytes = 0
    file_count = 0
    pdb_count = 0
    for root, _dirs, files in os.walk(cache):
        for f in files:
            try:
                total_bytes += os.path.getsize(os.path.join(root, f))
                file_count += 1
                if f.lower().endswith(".pdb"):
                    pdb_count += 1
            except OSError:
                pass

    if total_bytes >= 1 << 30:
        size_str = f"{total_bytes / (1 << 30):.2f} GB"
    elif total_bytes >= 1 << 20:
        size_str = f"{total_bytes / (1 << 20):.1f} MB"
    elif total_bytes >= 1 << 10:
        size_str = f"{total_bytes / (1 << 10):.1f} KB"
    else:
        size_str = f"{total_bytes} B"

    console.print(f"[bright_black]server:[/] {MS_SYMBOL_SERVER}")
    console.print(f"[bright_black]size:[/]   {size_str}")
    console.print(f"[bright_black]files:[/]  {file_count} ({pdb_count} PDBs)")
    return None


def _cmd_load(debugger, target):
    if not _check_debugger(debugger):
        return None
    sm = debugger.symbols
    sm.refresh_dbghelp_modules()

    if not target:
        error("Usage: pdb load <module|all>")
        return None

    if target.lower() == "all":
        return _load_all(sm)

    mod = _find_module(sm, target)
    if not mod:
        error(f"Module not found: {target}")
        return None

    info(f"Loading PDB for {mod.name} ({mod.path})...")
    ok = sm.force_load_module(mod)
    st = sm.get_module_sym_status(mod.base_address)
    dl = getattr(sm, "_last_load_status", (None, None))[1]
    if dl:
        status, payload = dl
        if status == "downloaded":
            console.print(f"  [bright_black]download:[/] [green]downloaded[/] → {payload}")
        elif status == "cached":
            console.print(f"  [bright_black]download:[/] [cyan]cached[/]     → {payload}")
        else:
            console.print(f"  [bright_black]download:[/] [red]{status}[/]   {payload}")
    if ok:
        success(f"{mod.name}: {st['type']} ({st['num_syms']} symbols)")
    else:
        warn(f"{mod.name}: {st['type']} ({st['num_syms']} symbols) — no PDB")
    return None


def _load_all(sm):
    if not sm.modules:
        warn("No modules to load")
        return None

    info(f"Loading PDBs for {len(sm.modules)} modules — first run may take a while...")
    loaded = 0
    failed = 0
    for mod in sm.modules:
        ok = sm.force_load_module(mod)
        st = sm.get_module_sym_status(mod.base_address)
        dl = getattr(sm, "_last_load_status", (None, None))[1]
        dl_tag = ""
        if dl:
            status, _ = dl
            tag_color = {"downloaded": "green", "cached": "cyan"}.get(status, "red")
            dl_tag = f" [{tag_color}]{status}[/]"
        if ok and st["loaded"]:
            loaded += 1
            console.print(
                f"  [green]✓[/] {mod.name:<30} {st['num_syms']:>6} syms{dl_tag}"
            )
        else:
            failed += 1
            console.print(
                f"  [red]✗[/] {mod.name:<30} {st['type']:<10}{dl_tag}"
            )

    console.print()
    success(f"Loaded {loaded} PDBs, {failed} failed")
    return None


def _cmd_debug(debugger):
    """Print raw diagnostic info to figure out why PDB loading is broken."""
    if not _check_debugger(debugger):
        return None
    sm = debugger.symbols
    import ctypes as _ct
    from ..utils.constants import dbghelp, IMAGEHLP_MODULE64

    console.print(f"[bright_black]DBGHELP_AVAILABLE:[/] {dbghelp is not None}")
    console.print(f"[bright_black]dbghelp_initialized:[/] {sm.dbghelp_initialized}")
    if getattr(sm, "_init_error", None):
        console.print(f"[red]init_error:[/] {sm._init_error}")
    console.print(f"[bright_black]process_handle:[/] {sm.process_handle}")
    console.print(f"[bright_black]process_id:[/] {debugger.process_id}")
    console.print()

    # Try a fresh SymRefreshModuleList and report
    if sm.dbghelp_initialized:
        try:
            ok = dbghelp.SymRefreshModuleList(sm.process_handle)
            err = _ct.GetLastError()
            console.print(f"[bright_black]SymRefreshModuleList:[/] ok={bool(ok)} err={err}")
        except Exception as e:
            console.print(f"[red]SymRefreshModuleList exception:[/] {e!r}")

    # Inspect each module via SymGetModuleInfo64 with raw output
    if not sm.modules:
        warn("No modules tracked")
        return None

    console.print()
    console.print("[bold bright_white]Per-module raw status:[/]")
    for mod in sm.modules[:8]:
        info_struct = IMAGEHLP_MODULE64()
        info_struct.SizeOfStruct = _ct.sizeof(IMAGEHLP_MODULE64)
        try:
            ret = dbghelp.SymGetModuleInfo64(
                sm.process_handle, mod.base_address, _ct.byref(info_struct)
            )
            err = _ct.GetLastError()
            if ret:
                console.print(
                    f"  [cyan]{mod.name:<20}[/] base={mod.base_address:#x} "
                    f"SymType={info_struct.SymType} NumSyms={info_struct.NumSyms} "
                    f"PDB={info_struct.LoadedPdbName.decode('utf-8', 'replace')!r}"
                )
            else:
                console.print(
                    f"  [red]{mod.name:<20}[/] SymGetModuleInfo64 failed (err={err})"
                )
        except Exception as e:
            console.print(f"  [red]{mod.name}[/] exception: {e!r}")

    # Try a manual SymLoadModuleEx on the first module and report
    if sm.modules:
        first = sm.modules[0]
        console.print()
        console.print(f"[bold]Manual SymLoadModuleEx test on {first.name}:[/]")
        try:
            try:
                dbghelp.SymUnloadModule64(sm.process_handle, first.base_address)
            except Exception:
                pass
            image = first.path.encode("utf-8") if first.path else None
            ret = dbghelp.SymLoadModuleEx(
                sm.process_handle, None, image, None,
                first.base_address, first.size, None, 0,
            )
            err = _ct.GetLastError()
            console.print(f"  ret={ret:#x} err={err} image={first.path!r}")
        except Exception as e:
            console.print(f"  [red]exception:[/] {e!r}")

    return None


# ---- helpers ----

def _check_debugger(debugger):
    if not getattr(debugger, "process_handle", None):
        error("No process attached")
        return False
    if not getattr(debugger, "symbols", None):
        error("Symbol manager not initialized")
        return False
    return True


def _find_module(sm, name):
    name_lower = name.lower()
    stem = name_lower.rsplit(".", 1)[0] if "." in name_lower else name_lower
    for mod in sm.modules:
        mn = mod.name.lower()
        ms = mn.rsplit(".", 1)[0] if "." in mn else mn
        if mn == name_lower or ms == stem or ms == name_lower:
            return mod
    return None
