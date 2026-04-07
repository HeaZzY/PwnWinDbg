"""Address expression evaluator.

Supports expressions like:
    0x401000
    0x401000+0x10
    0x401000-1
    eax        — bare register name
    $rax       — GDB-style register prefix (same as bare)
    eax+8
    $rsp-0x18
    ntdll+0x1000
    ntdll.dll+0x1000
    ch72.exe+0x1347-1
"""

import re

# Tokenize: split on +/- while keeping the operators
_TOKEN_RE = re.compile(r'([+\-])')


def eval_expr(debugger, expr_str):
    """Evaluate an address expression string, returning an integer address.

    Supports:
      - hex/decimal literals: 0x401000, 12345
      - register names: rax, eip, rsp, ...
      - symbol/module names: ntdll, ntdll.dll, ch72.exe+0x1347
      - arithmetic: addr+offset, addr-offset (chained)

    Returns int address or None on failure.
    """
    expr_str = expr_str.strip()
    if not expr_str:
        return None

    # Strip leading '&' (GDB "address of" — symbols already resolve to addresses)
    if expr_str.startswith('&'):
        expr_str = expr_str[1:].strip()

    # Strip leading '*' (GDB dereference prefix for bp, etc.)
    if expr_str.startswith('*'):
        expr_str = expr_str[1:].strip()

    # Split into tokens and operators
    parts = _TOKEN_RE.split(expr_str)
    # parts example: ['0x401000', '-', '1'] or ['eax', '+', '8']
    # Filter empty strings
    parts = [p for p in parts if p]

    if not parts:
        return None

    # Evaluate first token
    result = _resolve_token(debugger, parts[0])
    if result is None:
        return None

    # Apply subsequent +/- operations
    i = 1
    while i < len(parts) - 1:
        op = parts[i]
        operand = _resolve_token(debugger, parts[i + 1])
        if operand is None:
            return None
        if op == '+':
            result += operand
        elif op == '-':
            result -= operand
        i += 2

    return result


def _resolve_token(debugger, token):
    """Resolve a single token (literal, register, or symbol) to an int."""
    token = token.strip()
    if not token:
        return None

    # GDB-style register prefix: $rax, $rip, ... — strip the $ and the
    # token must resolve as a register, not a symbol/literal.
    is_dollar_reg = False
    if token.startswith("$"):
        token = token[1:]
        is_dollar_reg = True
        if not token:
            return None

    # Hex / decimal literal (only when there was no $ prefix — $0x10 makes
    # no sense and we don't want to silently swallow it).
    if not is_dollar_reg:
        try:
            return int(token, 0)
        except ValueError:
            pass

    # Register name
    from ..core.debugger import DebuggerState
    if debugger.state == DebuggerState.STOPPED:
        regs, _ = debugger.get_registers()
        if regs:
            for k, v in regs.items():
                if k.lower() == token.lower():
                    return v

    # If the user explicitly asked for a register ($prefix) we don't fall
    # back to symbol lookup — that would mask typos.
    if is_dollar_reg:
        return None

    # Symbol / module via symbol manager
    resolved = debugger.symbols.resolve_name_to_address(token)
    if resolved is not None:
        return resolved

    return None
