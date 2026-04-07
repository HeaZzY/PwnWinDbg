"""ntcalls — resolve NT syscall numbers <-> names from the live ntdll.

Useful when a target dispatches via raw `mov eax, NN; syscall` (rootkits,
packed malware, manual syscall stubs) instead of going through the named
ntdll exports. The table is built once on first use by parsing the
prologue bytes of every `ntdll!Nt*` export — see `core/ntcalls.py` for
the validation rules.

Usage:
    ntcalls table              — show the full sorted table
    ntcalls table <substring>  — filter by name substring (case-insensitive)
    ntcalls num <NN>           — look up a syscall number (hex or decimal)
    ntcalls name <NtClose>     — look up by name, returns the number

The cache is invalidated automatically on process restart / detach.
"""

from rich.text import Text

from ..display.formatters import banner, console, error, info, success


def _ensure_table(debugger):
    """Lazily build the syscall table on the symbol manager."""
    if not hasattr(debugger.symbols, "_nt_syscall_table"):
        from ..core.ntcalls import NtSyscallTable
        debugger.symbols._nt_syscall_table = NtSyscallTable()
    tbl = debugger.symbols._nt_syscall_table
    if not tbl.built:
        n = tbl.build(debugger)
        if n == 0:
            return None
        info(f"Built syscall table: {n} entries")
    return tbl


def cmd_ntcalls(debugger, args):
    """Inspect the runtime-recovered NT syscall table.

    Subcommands:
        ntcalls table [filter]   — full sorted listing (optional substring)
        ntcalls num <NN>         — number → name lookup
        ntcalls name <NtFn>      — name → number lookup
    """
    if not debugger.process_handle:
        error("No process attached")
        return None

    raw = args.strip()
    if not raw:
        error("Usage: ntcalls table [filter] | num <NN> | name <NtFn>")
        return None

    parts = raw.split()
    sub = parts[0].lower()

    tbl = _ensure_table(debugger)
    if tbl is None:
        error("Failed to build syscall table — is ntdll loaded? "
              "(WoW64 not supported)")
        return None

    if sub == "table":
        substr = parts[1].lower() if len(parts) >= 2 else None
        rows = sorted(tbl.num_to_name.items())
        if substr:
            rows = [(n, name) for n, name in rows if substr in name.lower()]
        if not rows:
            info("No entries match")
            return None
        title = (
            f"NT syscalls — {len(rows)} entries"
            + (f" matching '{substr}'" if substr else "")
        )
        banner(title)
        for ssn, name in rows:
            line = Text()
            line.append(f"  {ssn:#06x}", style="bright_yellow")
            line.append(f"  ({ssn:4d})  ", style="bright_black")
            line.append(name, style="bright_white")
            console.print(line)
        return None

    if sub == "num":
        if len(parts) < 2:
            error("Usage: ntcalls num <NN>")
            return None
        try:
            ssn = int(parts[1], 0)
        except ValueError:
            error(f"Invalid number: {parts[1]}")
            return None
        name = tbl.lookup_num(ssn)
        if name:
            success(f"{ssn:#x} ({ssn}) -> ntdll!{name}")
        else:
            error(f"No entry for syscall {ssn:#x}")
        return None

    if sub == "name":
        if len(parts) < 2:
            error("Usage: ntcalls name <NtFn>")
            return None
        ssn = tbl.lookup_name(parts[1])
        if ssn is not None:
            success(f"ntdll!{parts[1]} -> {ssn:#x} ({ssn})")
        else:
            error(f"No entry for {parts[1]}")
        return None

    error(f"Unknown subcommand: {sub}")
    return None
