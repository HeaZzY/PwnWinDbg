"""decompile — native AI pseudo-C for the function at an address.

Extracts the current function's disassembly with our own Capstone engine and
asks the configured LLM to produce annotated pseudo-C (cached per function),
then prints it with the current line highlighted.

Usage:
    decompile [<addr|symbol>]     — decompile function at addr (default: current IP)
    decompile on | off            — toggle the auto-context decompile pane
    aliases: dc, pdc

A decompiler failure never crashes the REPL — everything is caught and reported.
"""

from ..core.decompiler import decompile_function
from ..display.decompile_view import display_decompile
from ..display.common import error, success
from ..utils.addr_expr import eval_expr


def _current_ip(debugger):
    """Return the current instruction pointer, or None.

    ``get_registers()`` may return a bare dict or a ``(dict, changed_set)``
    tuple depending on caller/version — handle both.
    """
    try:
        regs = debugger.get_registers()
    except Exception:
        return None
    if isinstance(regs, tuple):
        regs = regs[0] if regs else None
    if not regs:
        return None
    for key in ("Rip", "Eip", "rip", "eip"):
        if key in regs:
            return regs[key]
    return None


def cmd_decompile(debugger, args):
    """Decompile the function at an address (native AI decompiler).

    Usage: decompile [<addr|symbol>]  (default = current IP);  decompile on|off
    """
    try:
        arg = (args or "").strip()
        low = arg.lower()

        # Auto-context toggle.
        if low in ("on", "enable"):
            debugger.show_decompile = True
            success("decompile: auto-context pane ON")
            return None
        if low in ("off", "disable"):
            debugger.show_decompile = False
            success("decompile: auto-context pane OFF")
            return None

        # Resolve the target address.
        if arg:
            addr = eval_expr(debugger, arg)
            if addr is None:
                error(f"decompile: cannot resolve address/symbol: {arg}")
                return None
        else:
            addr = _current_ip(debugger)
            if addr is None:
                error(
                    "Usage: decompile [<addr|symbol>] (default = current IP); "
                    "decompile on|off"
                )
                return None

        # force=True so on-demand decompiling works even in library code.
        result = decompile_function(debugger, addr, force=True)
        if not result:
            error("decompile failed or unavailable")
            return None

        display_decompile(result, addr)
        return None
    except Exception as exc:  # never let a decompiler problem crash the REPL
        try:
            error(f"decompile: {exc}")
        except Exception:
            pass
        return None


# Aliases share the single handler.
cmd_dc = cmd_decompile
cmd_pdc = cmd_decompile
