"""catch — break on debugger events that aren't ordinary code BPs.

Currently supports `catch load <pattern>`: stop the next time a DLL whose
path or base name contains <pattern> (case-insensitive substring) gets
loaded into the debuggee. Useful for:

  * pinning the moment a plugin/COM in-proc-server gets loaded
  * catching DLL hijacks at the load itself, not at DllMain
  * waiting for a deferred Windows runtime DLL (combase, sechost, ...)
    so you can break in before its first call

Multiple patterns can be active simultaneously. The Debugger checks every
LOAD_DLL_DEBUG_EVENT against `catch_load_patterns` and converts a match
into a `catch_load` stop reason — no INT3, no setup-then-step dance, the
loader thread just stops cleanly inside the debug-event loop.

Usage
-----
    catch load <substring>          arm a load catchpoint
    catch list                      show active catchpoints + hit counts
    catch del <id>                  remove one
    catch clear                     remove all
"""

from ..display.formatters import banner, console, error, info, success


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
    if sub in ("list", "ls"):
        return _list(debugger)
    if sub in ("del", "delete", "rm"):
        return _remove(debugger, rest)
    if sub in ("clear", "clr"):
        return _clear(debugger)

    error(f"Unknown subcommand: {sub}")
    error("Usage: catch load <substring> | catch list | catch del <id> | catch clear")
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


def _list(debugger):
    cps = debugger.catch_load_patterns
    if not cps:
        info("No catchpoints set")
        return None
    banner(f"catchpoints — {len(cps)} entries")
    for entry in cps:
        console.print(
            f"  [bright_yellow]#{entry['id']}[/]  load  "
            f"[bright_white]{entry['pattern']!r}[/]  "
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
    before = len(debugger.catch_load_patterns)
    debugger.catch_load_patterns = [e for e in debugger.catch_load_patterns
                                    if e["id"] != cid]
    if len(debugger.catch_load_patterns) == before:
        error(f"No catchpoint with id {cid}")
    else:
        success(f"Removed catchpoint #{cid}")
    return None


def _clear(debugger):
    n = len(debugger.catch_load_patterns)
    debugger.catch_load_patterns.clear()
    if n:
        success(f"Cleared {n} catchpoint(s)")
    else:
        info("No catchpoints to clear")
    return None
