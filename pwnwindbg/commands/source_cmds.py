"""source — execute pwnWinDbg commands from a script file.

Useful for repeatable setup (load symbols, set breakpoints, run, dump
context). Lines starting with `#` and blank lines are skipped. Each
non-empty line is dispatched through the normal command parser.

Errors in individual lines are reported but do not abort the script
unless `--strict` is passed.
"""

import os

from rich.text import Text

from ..display.formatters import banner, console, error, info, success, warn


def cmd_source(debugger, args):
    """Run a sequence of commands from a file.

    Usage:
        source <path>            — execute every command line in the file
        source <path> --strict   — abort on the first failing line
        source <path> --quiet    — don't echo commands as they run
    """
    parts = args.strip().split()
    if not parts:
        error("Usage: source <path> [--strict] [--quiet]")
        return None

    path = None
    strict = False
    quiet = False
    for p in parts:
        if p in ("--strict", "-s"):
            strict = True
        elif p in ("--quiet", "-q"):
            quiet = True
        else:
            path = p

    if not path:
        error("Missing file path")
        return None
    if not os.path.isfile(path):
        error(f"No such file: {path}")
        return None

    # Avoid circular import
    from .dispatcher import dispatch

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except Exception as ex:
        error(f"Failed to open {path}: {ex}")
        return None

    banner(f"Sourcing {path}  ({len(lines)} lines)")
    last_stop = None
    executed = 0
    failed = 0
    for lineno, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not quiet:
            t = Text()
            t.append(f"  [{lineno}] ", style="bright_black")
            t.append(line, style="bright_white")
            console.print(t)
        try:
            stop = dispatch(debugger, line)
            executed += 1
            if stop is not None:
                last_stop = stop
        except Exception as ex:
            failed += 1
            error(f"line {lineno}: {ex}")
            if strict:
                error("--strict: aborting script")
                break

    summary = f"sourced {executed} command(s), {failed} error(s)"
    if failed == 0:
        success(summary)
    else:
        warn(summary)
    return last_stop
