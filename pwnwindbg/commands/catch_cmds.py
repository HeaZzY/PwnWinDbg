"""catch — break on debugger events that aren't ordinary code BPs.

Two flavors are supported:

`catch load <pattern>` stops the next time a DLL whose path or base
name contains <pattern> (case-insensitive substring) gets loaded into
the debuggee. Useful for:

  * pinning the moment a plugin/COM in-proc-server gets loaded
  * catching DLL hijacks at the load itself, not at DllMain
  * waiting for a deferred Windows runtime DLL (combase, sechost, ...)
    so you can break in before its first call

`catch exception <name|code>` stops on first-chance SEH exceptions of
a specific type. Without this, only access violations stop the debugger
by default — every other first-chance exception silently passes through
to the application's handlers. Friendly names: `av`, `cpp`, `divzero`,
`stack`, `illegal`, `priv`. A raw hex code like `0xC0000094` also works.

Multiple catches can be active simultaneously. The Debugger checks every
LOAD_DLL_DEBUG_EVENT and EXCEPTION_DEBUG_EVENT against the per-debugger
filter sets and converts a match into a `catch_load` / `catch_exception`
stop reason — no INT3, no setup-then-step dance, the offending thread
just stops cleanly inside the debug-event loop.

Usage
-----
    catch load <substring>           arm a load catchpoint
    catch exception <name|code>      arm an exception catchpoint
    catch list                       show active catchpoints + hit counts
    catch del <id>                   remove one
    catch clear                      remove all
"""

from ..display.formatters import banner, console, error, info, success


# Friendly aliases for the most useful first-chance exceptions. The
# canonical hex codes come from ntstatus.h. Lowercase keys; lookup is
# case-insensitive.
EXCEPTION_NAMES = {
    "av":           0xC0000005,  # ACCESS_VIOLATION
    "accessviolation": 0xC0000005,
    "cpp":          0xE06D7363,  # MSVC C++ EH magic ('msc' in ASCII)
    "msvc":         0xE06D7363,
    "throw":        0xE06D7363,
    "divzero":      0xC0000094,  # INTEGER_DIVIDE_BY_ZERO
    "div0":         0xC0000094,
    "intoverflow":  0xC0000095,  # INTEGER_OVERFLOW
    "stack":        0xC00000FD,  # STACK_OVERFLOW
    "illegal":      0xC000001D,  # ILLEGAL_INSTRUCTION
    "priv":         0xC0000096,  # PRIVILEGED_INSTRUCTION
    "guardpage":    0x80000001,  # GUARD_PAGE_VIOLATION
    "datatype":     0x80000002,  # DATATYPE_MISALIGNMENT
    "fpe":          0xC000008E,  # FLT_DIVIDE_BY_ZERO  (closest single code)
    "breakpoint":   0x80000003,  # EXCEPTION_BREAKPOINT
}


def _exception_name_for(code):
    """Return a friendly name for a known exception code, or the hex repr."""
    for name, c in EXCEPTION_NAMES.items():
        if c == code:
            return name
    return f"{code:#010x}"


_NEXT_ID = 1


def _alloc_id():
    global _NEXT_ID
    cid = _NEXT_ID
    _NEXT_ID += 1
    return cid


def cmd_catch(debugger, args):
    """Manage event catchpoints."""
    parts = args.strip().split(None, 1)
    if not parts:
        return _list(debugger)

    sub = parts[0].lower()
    rest = parts[1].strip() if len(parts) > 1 else ""

    if sub == "load":
        return _add_load(debugger, rest)
    if sub in ("exception", "exc", "ex"):
        return _add_exception(debugger, rest)
    if sub in ("list", "ls"):
        return _list(debugger)
    if sub in ("del", "delete", "rm"):
        return _remove(debugger, rest)
    if sub in ("clear", "clr"):
        return _clear(debugger)

    error(f"Unknown subcommand: {sub}")
    error("Usage: catch load <substring> | catch exception <name|code> | "
          "catch list | catch del <id> | catch clear")
    return None


def _add_load(debugger, pattern):
    if not pattern:
        error("Usage: catch load <substring>")
        return None
    pat = pattern.strip().strip('"').strip("'").lower()
    if not pat:
        error("Empty pattern")
        return None

    # Don't double-arm the same substring
    for entry in debugger.catch_load_patterns:
        if entry["pattern"] == pat:
            info(f"catch load #{entry['id']} already armed for {pat!r}")
            return None

    cid = _alloc_id()
    debugger.catch_load_patterns.append({
        "id": cid,
        "pattern": pat,
        "hit_count": 0,
    })
    success(f"catch load #{cid} armed: matches DLLs containing {pat!r}")
    return None


def _add_exception(debugger, spec):
    """Arm an exception catchpoint by friendly name or hex code."""
    if not spec:
        error("Usage: catch exception <name|code>")
        error(f"Known names: {', '.join(sorted(EXCEPTION_NAMES))}")
        return None
    spec = spec.strip().split()[0]

    code = EXCEPTION_NAMES.get(spec.lower())
    if code is None:
        try:
            code = int(spec, 0)
        except ValueError:
            error(f"Unknown exception name or code: {spec}")
            error(f"Known names: {', '.join(sorted(EXCEPTION_NAMES))}")
            return None

    if not hasattr(debugger, "catch_exception_filters"):
        debugger.catch_exception_filters = []

    for entry in debugger.catch_exception_filters:
        if entry["code"] == code:
            info(f"catch exception #{entry['id']} already armed for {code:#010x}")
            return None

    cid = _alloc_id()
    debugger.catch_exception_filters.append({
        "id": cid,
        "code": code,
        "name": _exception_name_for(code),
        "hit_count": 0,
    })
    success(
        f"catch exception #{cid} armed: stops on {code:#010x} "
        f"({_exception_name_for(code)})"
    )
    return None


def _list(debugger):
    cps = debugger.catch_load_patterns
    excs = getattr(debugger, "catch_exception_filters", [])
    if not cps and not excs:
        info("No catchpoints set")
        return None
    banner(f"catchpoints — {len(cps) + len(excs)} entries")
    for entry in cps:
        console.print(
            f"  [bright_yellow]#{entry['id']}[/]  load       "
            f"[bright_white]{entry['pattern']!r}[/]  "
            f"hits={entry['hit_count']}"
        )
    for entry in excs:
        console.print(
            f"  [bright_yellow]#{entry['id']}[/]  exception  "
            f"[bright_white]{entry['code']:#010x}[/] "
            f"({entry['name']})  "
            f"hits={entry['hit_count']}"
        )
    return None


def _remove(debugger, id_str):
    if not id_str:
        error("Usage: catch del <id>")
        return None
    try:
        cid = int(id_str.split()[0], 0)
    except ValueError:
        error(f"Invalid id: {id_str}")
        return None

    excs = getattr(debugger, "catch_exception_filters", [])
    before_load = len(debugger.catch_load_patterns)
    before_exc = len(excs)
    debugger.catch_load_patterns = [e for e in debugger.catch_load_patterns
                                    if e["id"] != cid]
    if hasattr(debugger, "catch_exception_filters"):
        debugger.catch_exception_filters = [
            e for e in debugger.catch_exception_filters if e["id"] != cid
        ]
    if (len(debugger.catch_load_patterns) == before_load
            and len(getattr(debugger, "catch_exception_filters", []))
                == before_exc):
        error(f"No catchpoint with id {cid}")
    else:
        success(f"Removed catchpoint #{cid}")
    return None


def _clear(debugger):
    n = len(debugger.catch_load_patterns) + len(
        getattr(debugger, "catch_exception_filters", [])
    )
    debugger.catch_load_patterns.clear()
    if hasattr(debugger, "catch_exception_filters"):
        debugger.catch_exception_filters.clear()
    if n:
        success(f"Cleared {n} catchpoint(s)")
    else:
        info("No catchpoints to clear")
    return None
