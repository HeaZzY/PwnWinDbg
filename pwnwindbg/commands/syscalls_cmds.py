"""syscalls — trace NT syscalls via auto-continuing BPs on ntdll!Nt* exports.

A high-level wrapper over `dprintf`. Scans ntdll's exports for `Nt*` stubs
and installs a tracing BP on each one. Each BP fires, renders a one-line
log to the REPL, and resumes execution — same machinery as `dprintf`. The
optional positional filters narrow the set by case-insensitive substring
match (any-of, OR-style).

Usage:
    syscalls on                    — trace every ntdll!Nt* export
    syscalls on File               — only Nt* exports whose name contains "File"
    syscalls on Open Read Write    — multiple substring filters (OR)
    syscalls off                   — remove every active syscall trace
    syscalls list                  — show currently active traces

Logged format (x64):
    [tid=0x1234] NtCreateFile(rcx=0x..., rdx=0x..., r8=0x..., r9=0x...)

On WoW64 the args come from the stack ([esp+4..0x10]) instead.
"""

from ..display.formatters import banner, console, error, info, success


# x64 fastcall: first four args in rcx, rdx, r8, r9
_X64_FMT = (
    "[tid={tid:hex}] {name}("
    "rcx={rcx:hex}, rdx={rdx:hex}, r8={r8:hex}, r9={r9:hex})"
)
# WoW64 stdcall stub: args at [esp+4..0x10] (esp+0 is the return address)
_X86_FMT = (
    "[tid={tid:hex}] {name}("
    "a0={dword(esp+4):hex}, a1={dword(esp+8):hex}, "
    "a2={dword(esp+0xc):hex}, a3={dword(esp+0x10):hex})"
)


def _list_nt_exports(debugger, filters):
    """Yield (func_name, runtime_addr) for ntdll!Nt* exports matching filters.

    `filters` is a list of substrings; an export matches if any of them
    appears in the function name (case-insensitive). An empty list matches
    every Nt* export. Each address is yielded at most once even though the
    export cache contains both bare and module-prefixed keys.
    """
    debugger.symbols._ensure_exports_loaded()
    seen = set()
    for key, (mod_name, func_name, addr) in debugger.symbols._export_by_name.items():
        if "!" in key:
            continue  # skip the module-prefixed dupes
        if mod_name.lower() != "ntdll.dll":
            continue
        if not func_name.startswith("Nt"):
            continue
        if filters and not any(f.lower() in func_name.lower() for f in filters):
            continue
        if addr in seen:
            continue
        seen.add(addr)
        yield func_name, addr


def cmd_syscalls(debugger, args):
    """Trace NT syscalls via auto-continuing BPs on ntdll!Nt* exports.

    Subcommands:
        syscalls on [filter ...]   — install traces (filters are substring OR)
        syscalls off               — remove every trace
        syscalls list              — show active traces
    """
    if not debugger.process_handle:
        error("No process attached")
        return None

    raw = args.strip()
    if not raw:
        error("Usage: syscalls on [filter ...] | off | list")
        return None

    parts = raw.split()
    sub = parts[0].lower()

    if not hasattr(debugger, "syscall_trace_bps"):
        debugger.syscall_trace_bps = set()

    if sub in ("list", "ls"):
        rows = [
            debugger.bp_manager.get_by_id(bp_id)
            for bp_id in debugger.syscall_trace_bps
        ]
        rows = [bp for bp in rows if bp is not None]
        if not rows:
            info("No syscall traces installed")
            return None
        banner(f"syscalls — {len(rows)} active trace(s)")
        for bp in sorted(rows, key=lambda b: b.address):
            sym = (
                debugger.symbols.resolve_address(bp.address)
                or f"{bp.address:#x}"
            )
            console.print(
                f"  [bright_yellow]BP#{bp.id}[/]  "
                f"[bright_blue]{bp.address:#x}[/]  "
                f"hits={bp.hit_count}  {sym}"
            )
        return None

    if sub in ("off", "stop", "clear"):
        n_removed = 0
        for bp_id in list(debugger.syscall_trace_bps):
            if debugger.bp_manager.remove(debugger.process_handle, bp_id):
                n_removed += 1
        debugger.syscall_trace_bps.clear()
        if n_removed:
            success(f"Removed {n_removed} syscall trace(s)")
        else:
            info("No syscall traces were active")
        return None

    if sub != "on":
        error(f"Unknown subcommand: {sub}")
        return None

    filters = parts[1:]
    fmt_template = _X86_FMT if debugger.is_wow64 else _X64_FMT

    n_added = 0
    n_skipped = 0
    n_failed = 0
    for func_name, addr in _list_nt_exports(debugger, filters):
        # Don't disturb pre-existing BPs (could be a user BP at the same
        # address — they'd lose their condition/action if we mutated it).
        if debugger.bp_manager.get_by_address(addr) is not None:
            n_skipped += 1
            continue
        try:
            bp = debugger.bp_manager.add(debugger.process_handle, addr)
        except Exception:
            n_failed += 1
            continue
        # Bake the function name into the format string at install time so
        # the runtime eval namespace doesn't have to know about it.
        bp.action = fmt_template.replace("{name}", func_name)
        debugger.syscall_trace_bps.add(bp.id)
        n_added += 1

    if n_added == 0:
        if filters:
            error(f"No ntdll!Nt* exports matched filter(s): {' '.join(filters)}")
        else:
            error("No ntdll!Nt* exports found — has ntdll loaded yet?")
        return None

    success(
        f"Tracing {n_added} ntdll!Nt* exports "
        f"({n_skipped} skipped, {n_failed} failed)"
    )
    info("Use `syscalls off` to disable, `bl` to see all BPs")
    return None
