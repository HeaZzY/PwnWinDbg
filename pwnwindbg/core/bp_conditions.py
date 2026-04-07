"""Conditional breakpoint expression evaluator.

A breakpoint can carry a Python expression that is evaluated each time the
INT3 fires; if the expression is falsy, the debugger re-arms the breakpoint
and silently continues.

Expressions run in a constrained namespace:
    - every register exposed by Debugger.get_registers() (lowercase + UPPER)
    - byte/word/dword/qword(addr)         — memory reads (return None on fault)
    - cstr(addr [, max_len]) / wstr(addr) — read null-terminated strings
    - hex(x), int(x)                      — Python builtins for convenience

`eval` is intentional here. The user is sitting at a local debugger prompt
typing into their own process — sandboxing the expression buys nothing.
We only block `__import__`, attribute access on the builtins module, etc.
through `__builtins__`: {} so a typo doesn't accidentally call `os.system`.
"""

import struct

from .memory import (
    read_memory_safe, read_byte, read_word, read_dword, read_qword,
    read_string, read_wstring,
)


def _safe_eval(expr, namespace):
    """Run `expr` with no builtins access. Returns result or raises."""
    return eval(expr, {"__builtins__": {}}, namespace)


def build_namespace(debugger):
    """Build an eval namespace exposing registers + memory helpers."""
    ns = {}

    # Registers — lowercase and uppercase aliases so both `rax` and `RAX` work
    from .debugger import DebuggerState
    if debugger.state == DebuggerState.STOPPED:
        try:
            regs, _ = debugger.get_registers()
        except Exception:
            regs = None
        if regs:
            for name, val in regs.items():
                lname = name.lower()
                ns[lname] = val
                ns[name.upper()] = val
                # Also strip the "Seg" prefix common on segment registers
                if lname.startswith("seg"):
                    ns[lname[3:]] = val

    # Memory readers — closures over the live process handle
    ph = debugger.process_handle

    def _u8(addr):  return read_byte(ph, addr)
    def _u16(addr): return read_word(ph, addr)
    def _u32(addr): return read_dword(ph, addr)
    def _u64(addr): return read_qword(ph, addr)
    def _cstr(addr, max_len=256): return read_string(ph, addr, max_len)
    def _wstr(addr, max_len=512): return read_wstring(ph, addr, max_len)
    def _bytes(addr, n):           return read_memory_safe(ph, addr, n)

    ns.update({
        "byte":  _u8,  "u8":  _u8,
        "word":  _u16, "u16": _u16,
        "dword": _u32, "u32": _u32,
        "qword": _u64, "u64": _u64,
        "cstr":  _cstr, "str": _cstr,
        "wstr":  _wstr,
        "mem":   _bytes,
        "hex":   hex,
        "int":   int,
        "len":   len,
        "True":  True, "False": False, "None": None,
        # Process / thread ids — handy in dprintf/syscall traces.
        "tid":   debugger.active_thread_id or 0,
        "pid":   debugger.process_id or 0,
    })
    return ns


def format_dprintf(debugger, fmt):
    """Render a `dprintf` format string against the live state.

    `{expr}` placeholders are evaluated in the same constrained namespace
    as `evaluate_condition`. A trailing `:hex`, `:x`, `:s`, `:d` modifier
    selects how the value is rendered. Examples:

        "rcx={rcx:hex}, len={rdx}, str={cstr(rcx)}"
        "name={wstr(rcx):s}"

    Returns the rendered string, or an "<error: ...>" marker on failure.
    """
    if not fmt:
        return ""
    ns = build_namespace(debugger)
    out = []
    i = 0
    while i < len(fmt):
        ch = fmt[i]
        if ch == "{" and i + 1 < len(fmt) and fmt[i + 1] == "{":
            out.append("{"); i += 2; continue
        if ch == "}" and i + 1 < len(fmt) and fmt[i + 1] == "}":
            out.append("}"); i += 2; continue
        if ch != "{":
            out.append(ch); i += 1; continue
        # Find matching close brace (no nesting)
        j = fmt.find("}", i + 1)
        if j == -1:
            out.append(fmt[i:]); break
        body = fmt[i + 1:j]
        i = j + 1
        # Optional :spec
        spec = ""
        if ":" in body:
            expr, spec = body.rsplit(":", 1)
            spec = spec.strip()
        else:
            expr = body
        try:
            val = _safe_eval(expr.strip(), ns)
        except Exception as e:
            out.append(f"<{type(e).__name__}: {e}>")
            continue
        if val is None:
            out.append("None"); continue
        if spec in ("x", "hex"):
            out.append(hex(int(val)))
        elif spec == "d":
            out.append(str(int(val)))
        elif spec == "s":
            out.append(str(val))
        elif isinstance(val, int):
            out.append(hex(val))
        else:
            out.append(str(val))
    return "".join(out)


def evaluate_condition(debugger, expr):
    """Evaluate `expr` against the current debugger state.

    Returns:
        (True,  result_truthiness, None)   on success
        (False, False, error_message)      on failure (treat as falsy/no-stop)
    """
    if not expr:
        return True, True, None
    try:
        ns = build_namespace(debugger)
        result = _safe_eval(expr, ns)
        return True, bool(result), None
    except Exception as e:
        return False, False, f"{type(e).__name__}: {e}"
