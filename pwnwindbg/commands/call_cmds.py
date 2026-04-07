"""`call` — invoke an arbitrary function in the debuggee.

Usage:
    call <func>(<arg1>, <arg2>, ...)
    call <func> <arg1> <arg2> ...

Supported argument forms:
    "ansi text"        — allocates an ANSI buffer in the target, passes ptr
    L"wide text"       — allocates a UTF-16 buffer in the target, passes ptr
    0x1234 / 42        — integer literal
    rcx+0x10           — anything `eval_expr` understands (regs, syms, …)
    rax / sym+offset   — same

The function is invoked on the currently active thread via the standard
event loop (see `core/call.py`). On return rax is captured, the original
context is rewound, all temporary string allocations are freed, and the
result is printed in hex / decimal / as a deref hint.

x64 only — wow64 targets are rejected with a clear error.

Examples:
    call WinExec("calc.exe", 1)
    call MessageBoxW(0, L"hi", L"title", 0)
    call GetCurrentProcessId()
    call VirtualAlloc(0, 0x1000, 0x3000, 0x40)
"""

import ctypes

from ..core.call import (
    CallError, MAX_CALL_ARGS, alloc_remote, free_remote, invoke_function,
)
from ..core.memory import write_memory, read_string, read_wstring
from ..display.formatters import error, info, success, console
from ..utils.addr_expr import eval_expr


def cmd_call(debugger, args):
    """Invoke a function in the debuggee. See module docstring."""
    if not debugger.process_handle:
        error("No process attached")
        return None
    if debugger.is_wow64:
        error("`call` is x64-only for now (target is wow64)")
        return None

    raw = args.strip()
    if not raw:
        error('Usage: call <func>(<args>) | call <func> <arg> [<arg> ...]')
        return None

    try:
        func_expr, parsed_args = _parse_call(raw)
    except ValueError as e:
        error(f"Parse error: {e}")
        return None

    func_addr = eval_expr(debugger, func_expr)
    if func_addr is None:
        error(f"Cannot resolve function: {func_expr}")
        return None

    if len(parsed_args) > MAX_CALL_ARGS:
        error(
            f"Too many args ({len(parsed_args)}); maximum is {MAX_CALL_ARGS}"
        )
        return None

    # Materialize each parsed arg into a 64-bit integer. String literals
    # get allocated in the target and the pointer is passed; everything
    # else is fed to eval_expr.
    raw_args = []
    allocated = []  # cleanup list
    try:
        for kind, payload in parsed_args:
            if kind == "ansi":
                buf = payload.encode("utf-8") + b"\x00"
                addr = alloc_remote(debugger.process_handle, len(buf))
                allocated.append(addr)
                write_memory(debugger.process_handle, addr, buf)
                raw_args.append(addr)
            elif kind == "wide":
                buf = payload.encode("utf-16-le") + b"\x00\x00"
                addr = alloc_remote(debugger.process_handle, len(buf))
                allocated.append(addr)
                write_memory(debugger.process_handle, addr, buf)
                raw_args.append(addr)
            elif kind == "expr":
                val = eval_expr(debugger, payload)
                if val is None:
                    error(f"Cannot resolve argument: {payload}")
                    return None
                raw_args.append(val & 0xFFFFFFFFFFFFFFFF)
            else:
                error(f"Internal: unknown arg kind {kind!r}")
                return None
    except CallError as e:
        error(f"Allocation failed: {e}")
        for addr in allocated:
            free_remote(debugger.process_handle, addr)
        return None

    # Show what we're about to call so the user has a chance to spot a
    # parser surprise before the function actually runs.
    info(f"Calling {func_expr} @ {func_addr:#x} with {len(raw_args)} arg(s)")
    for i, val in enumerate(raw_args):
        kind = parsed_args[i][0]
        if kind == "ansi":
            console.print(
                f"  arg{i + 1} = {val:#x}  → ANSI \"{parsed_args[i][1]}\""
            )
        elif kind == "wide":
            console.print(
                f"  arg{i + 1} = {val:#x}  → WIDE L\"{parsed_args[i][1]}\""
            )
        else:
            console.print(f"  arg{i + 1} = {val:#x}  ({parsed_args[i][1]})")

    try:
        rax = invoke_function(debugger, func_addr, raw_args)
    except CallError as e:
        error(str(e))
        for addr in allocated:
            free_remote(debugger.process_handle, addr)
        return None

    # Free our scratch buffers now that the call is done. The result
    # might point INTO one of them (e.g. strchr returning a substring),
    # but the user only sees the address — they can dump it before
    # issuing the next command if they care.
    for addr in allocated:
        free_remote(debugger.process_handle, addr)

    success(f"→ rax = {rax:#x} ({rax}, {ctypes.c_int64(rax).value:d} signed)")
    # If rax looks like a printable string pointer, opportunistically
    # decode the first few bytes for the user.
    s = read_string(debugger.process_handle, rax, max_len=64)
    if s and all(0x20 <= ord(c) < 0x7F or c in "\t\r\n" for c in s) and s:
        console.print(f"  rax → \"{s}\"")
    else:
        ws = read_wstring(debugger.process_handle, rax, max_len=128)
        if ws and all(0x20 <= ord(c) < 0x7F or c in "\t\r\n" for c in ws) and ws:
            console.print(f"  rax → L\"{ws}\"")
    return None


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def _parse_call(raw):
    """Split `raw` into (func_expr, [(kind, payload), ...]).

    Accepts both `func(a, b, c)` and `func a b c`. Inside the paren form
    we honour string literals and split on top-level commas; outside we
    fall back to a simple whitespace tokenizer that still understands
    quoted strings.

    Returned `kind` is one of:
        "ansi"  — payload is the decoded text (no NUL)
        "wide"  — payload is the decoded text (no NUL)
        "expr"  — payload is the raw token text to feed to eval_expr
    """
    # Paren-style: `func(arg1, arg2, ...)`
    # Find the first `(` that isn't inside a string. We don't allow
    # function names with embedded parens, so the first one wins.
    paren_idx = _find_top_level(raw, "(")
    if paren_idx >= 0:
        if not raw.rstrip().endswith(")"):
            raise ValueError("missing closing ')'")
        func_expr = raw[:paren_idx].strip()
        if not func_expr:
            raise ValueError("missing function name before '('")
        inner = raw[paren_idx + 1 : raw.rstrip().rfind(")")].strip()
        if not inner:
            return func_expr, []
        return func_expr, _split_args(inner, sep=",")

    # Whitespace-style: `func arg1 arg2 ...`
    tokens = _split_args(raw, sep=None)
    if not tokens:
        raise ValueError("empty call")
    # The first token must be the function expression — and it can't be
    # a string literal (that would make no sense).
    fkind, fexpr = tokens[0]
    if fkind != "expr":
        raise ValueError("function name cannot be a string literal")
    return fexpr, tokens[1:]


def _find_top_level(s, ch):
    """Find the first occurrence of `ch` in `s` that isn't inside a quoted
    string. Returns -1 if not found."""
    i = 0
    while i < len(s):
        c = s[i]
        if c == '"':
            # Skip the string
            i = _skip_string(s, i)
        elif c == "L" and i + 1 < len(s) and s[i + 1] == '"':
            i = _skip_string(s, i + 1)
        elif c == ch:
            return i
        else:
            i += 1
    return -1


def _skip_string(s, i):
    """Given that s[i] == '"', return the index just past the closing
    quote (handling backslash escapes inside)."""
    assert s[i] == '"'
    i += 1
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            i += 2
            continue
        if s[i] == '"':
            return i + 1
        i += 1
    raise ValueError("unterminated string literal")


def _split_args(text, sep):
    """Tokenize `text` into [(kind, payload), ...].

    sep=',' splits on top-level commas (paren form).
    sep=None splits on whitespace.
    """
    out = []
    i = 0
    n = len(text)
    while i < n:
        # Skip leading separators / whitespace
        while i < n and (text[i].isspace() or (sep and text[i] == sep)):
            i += 1
        if i >= n:
            break

        # String literal forms
        if text[i] == '"':
            end = _skip_string(text, i)
            out.append(("ansi", _decode_string(text[i + 1 : end - 1])))
            i = end
        elif text[i] == "L" and i + 1 < n and text[i + 1] == '"':
            end = _skip_string(text, i + 1)
            out.append(("wide", _decode_string(text[i + 2 : end - 1])))
            i = end
        else:
            # Bare token: read until the next top-level separator
            start = i
            while i < n:
                c = text[i]
                if sep == "," and c == ",":
                    break
                if sep is None and c.isspace():
                    break
                if c == '"':
                    i = _skip_string(text, i)
                    continue
                i += 1
            tok = text[start:i].strip()
            if tok:
                out.append(("expr", tok))
    return out


def _decode_string(s):
    """Decode the common backslash escapes inside a string literal.

    We handle the printf-style ones the user is most likely to type:
    \\n, \\r, \\t, \\\\, \\", \\0. Everything else is passed through.
    """
    out = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            mapping = {
                "n": "\n", "r": "\r", "t": "\t", "0": "\x00",
                "\\": "\\", '"': '"',
            }
            if nxt in mapping:
                out.append(mapping[nxt])
                i += 2
                continue
        out.append(s[i])
        i += 1
    return "".join(out)
