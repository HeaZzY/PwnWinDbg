"""SEH (Structured Exception Handling) inspection commands.

    seh                      — auto: x86 chain or x64 handler-at-RIP
    seh chain                — force x86-style chain walk (TIB.ExceptionList)
    seh here                 — find the .pdata handler covering current RIP
    seh module <name|base>   — list every registered handler in a loaded module
"""

from rich.table import Table

from ..display.formatters import error, info, warn, console, banner
from ..core.seh import (
    walk_seh_x86, list_handlers_in_module, find_handler_for_address,
    UNW_FLAG_EHANDLER, UNW_FLAG_UHANDLER,
)
from ..core.peb_teb import get_teb_address


def cmd_seh(debugger, args):
    if not debugger.process_handle:
        error("No process attached")
        return None

    parts = args.strip().split()
    sub = parts[0].lower() if parts else ""

    if sub in ("chain", "x86", "fs", "tib"):
        return _seh_chain(debugger)
    if sub in ("here", "rip", "current", ""):
        # Default behavior: chain on x86, here on x64
        if debugger.is_wow64:
            return _seh_chain(debugger)
        return _seh_here(debugger)
    if sub in ("module", "mod", "lm"):
        if len(parts) < 2:
            error("Usage: seh module <name|base>")
            return None
        return _seh_module(debugger, parts[1])
    if sub == "all":
        return _seh_all_modules(debugger)

    error(f"Unknown subcommand: {sub}  (try: chain | here | module <name>)")
    return None


# ---------------------------------------------------------------------------
# x86 chain
# ---------------------------------------------------------------------------

def _seh_chain(debugger):
    tid = debugger.active_thread_id
    th = debugger.threads.get(tid) if tid else None
    if th is None:
        error("No active thread")
        return None

    teb_addr = get_teb_address(th)
    if not teb_addr:
        error("Failed to query TEB")
        return None

    chain = walk_seh_x86(debugger.process_handle, teb_addr)
    if not chain:
        warn("SEH chain is empty (or x64-style table-based unwinding)")
        if not debugger.is_wow64:
            info("Tip: on x64, try `seh here` to inspect the .pdata handler "
                 "covering current RIP")
        return None

    banner(f"SEH chain (tid={tid}, {len(chain)} record(s))")
    table = Table(show_header=True, border_style="cyan",
                  header_style="bold bright_white")
    table.add_column("#", justify="right", style="bright_yellow")
    table.add_column("Record", style="bright_cyan")
    table.add_column("Next", style="bright_white")
    table.add_column("Handler", style="bright_green")
    table.add_column("Symbol", style="bright_magenta")

    for i, rec in enumerate(chain):
        sym = ""
        if debugger.symbols:
            sym = debugger.symbols.resolve_address(rec["handler"]) or ""
        next_str = "END" if rec["next"] == 0xFFFFFFFF else f"{rec['next']:#x}"
        table.add_row(
            str(i),
            f"{rec['address']:#x}",
            next_str,
            f"{rec['handler']:#x}",
            sym,
        )
    console.print(table)
    return None


# ---------------------------------------------------------------------------
# x64 .pdata
# ---------------------------------------------------------------------------

def _seh_here(debugger):
    rip = debugger._get_current_ip()
    if rip is None:
        error("Cannot read current RIP")
        return None

    if not debugger.symbols or not debugger.symbols.modules:
        warn("No modules loaded — cannot resolve .pdata")
        return None

    result = find_handler_for_address(debugger.symbols.modules, rip)
    if not result:
        # Look up the covering function (no handler) for context
        info(f"No SEH handler covers RIP={rip:#x}")
        return None

    mod = result["module"]
    sym = ""
    if debugger.symbols:
        sym = debugger.symbols.resolve_address(result["handler"]) or ""

    banner(f"SEH handler @ RIP={rip:#x}")
    flag_names = []
    if result["flags"] & UNW_FLAG_EHANDLER:
        flag_names.append("EHANDLER")
    if result["flags"] & UNW_FLAG_UHANDLER:
        flag_names.append("UHANDLER")
    flags_str = " | ".join(flag_names)

    console.print(f"  [bright_white]Module:[/]   "
                  f"[bright_green]{mod.name}[/] @ {mod.base_address:#x}")
    console.print(f"  [bright_white]Function:[/] "
                  f"[bright_cyan]{result['begin']:#x}[/]"
                  f"-[bright_cyan]{result['end']:#x}[/]")
    console.print(f"  [bright_white]Handler:[/]  "
                  f"[bright_yellow]{result['handler']:#x}[/]"
                  + (f"  [bright_magenta]({sym})[/]" if sym else ""))
    console.print(f"  [bright_white]Flags:[/]    "
                  f"[bright_black]{flags_str}[/]")
    return None


def _seh_module(debugger, name_or_base):
    if not debugger.symbols:
        error("Symbol manager unavailable")
        return None

    target = None
    try:
        addr = int(name_or_base, 0)
        for m in debugger.symbols.modules:
            if m.base_address == addr:
                target = m
                break
    except ValueError:
        name_lower = name_or_base.lower()
        for m in debugger.symbols.modules:
            if m.name.lower() == name_lower or \
               m.name.lower().startswith(name_lower + "."):
                target = m
                break

    if target is None:
        error(f"Module not found: {name_or_base}")
        return None

    handlers = list_handlers_in_module(target.base_address, target.path)
    if not handlers:
        warn(f"No SEH handlers in {target.name}  "
             f"(no .pdata or no UNW_FLAG_*HANDLER entries)")
        return None

    banner(f"SEH handlers in {target.name} ({len(handlers)})")
    table = Table(show_header=True, border_style="cyan",
                  header_style="bold bright_white")
    table.add_column("#", justify="right", style="bright_yellow")
    table.add_column("Begin", style="bright_cyan")
    table.add_column("End", style="bright_cyan")
    table.add_column("Handler", style="bright_green")
    table.add_column("Flags", style="bright_white")
    table.add_column("Symbol", style="bright_magenta")

    # Cap display to first 50 entries unless we add a flag
    LIMIT = 50
    for i, h in enumerate(handlers[:LIMIT]):
        flag_names = []
        if h["flags"] & UNW_FLAG_EHANDLER:
            flag_names.append("E")
        if h["flags"] & UNW_FLAG_UHANDLER:
            flag_names.append("U")
        sym = debugger.symbols.resolve_address(h["handler"]) or ""
        table.add_row(
            str(i),
            f"{h['begin']:#x}",
            f"{h['end']:#x}",
            f"{h['handler']:#x}",
            "".join(flag_names),
            sym,
        )
    console.print(table)
    if len(handlers) > LIMIT:
        console.print(f"  [bright_black]...{len(handlers) - LIMIT} more "
                      f"handler(s) not shown[/]")
    return None


def _seh_all_modules(debugger):
    if not debugger.symbols or not debugger.symbols.modules:
        warn("No modules loaded")
        return None

    banner("SEH handler counts per module")
    table = Table(show_header=True, border_style="cyan",
                  header_style="bold bright_white")
    table.add_column("Module", style="bold bright_green")
    table.add_column("Base", style="bright_cyan")
    table.add_column("# Handlers", justify="right", style="bright_yellow")

    for mod in debugger.symbols.modules:
        try:
            handlers = list_handlers_in_module(mod.base_address, mod.path)
        except Exception:
            handlers = []
        if handlers:
            table.add_row(mod.name, f"{mod.base_address:#x}", str(len(handlers)))
    console.print(table)
    return None
