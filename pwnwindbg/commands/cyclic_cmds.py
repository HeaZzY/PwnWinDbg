"""
De Bruijn cyclic pattern generation and lookup for buffer overflow offset finding.
Equivalent to pwndbg/pwntools cyclic functionality.
"""

import string
import argparse

from ..display.formatters import info, error, success, console


def _de_bruijn(k, n):
    """Generate De Bruijn sequence for alphabet size k, subsequence length n."""
    alphabet = string.ascii_lowercase[:k]
    a = [0] * (k * n)
    sequence = []

    def db(t, p):
        if t > n:
            if n % p == 0:
                sequence.extend(a[1 : p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    return "".join(alphabet[i] for i in sequence)


def cyclic(length, n=4):
    """Generate a cyclic pattern of given length.

    Args:
        length: Desired pattern length in bytes.
        n: Subsequence length (4 for 32-bit, 8 for 64-bit).

    Returns:
        A string containing the cyclic pattern truncated to ``length``.
    """
    k = 26  # a-z
    pattern = _de_bruijn(k, n)
    # Repeat if the base sequence is shorter than requested
    while len(pattern) < length:
        pattern += pattern
    return pattern[:length]


def cyclic_find(value, n=4):
    """Find the offset of a value in the cyclic pattern.

    ``value`` can be an int (interpreted as little-endian bytes) or a string.

    Args:
        value: The value to search for.
        n: Subsequence length (4 for 32-bit, 8 for 64-bit).

    Returns:
        The offset (>= 0) if found, or -1 if not found.
    """
    if isinstance(value, int):
        byte_len = n
        try:
            b = value.to_bytes(byte_len, "little")
            subseq = b.decode("ascii", errors="replace")
        except Exception:
            return -1
    else:
        subseq = value

    # Generate a large enough pattern to search in
    pattern = cyclic(0x10000, n)
    return pattern.find(subseq)


def _resolve_lookup_value(debugger, token, n):
    """Resolve a lookup token to an integer or string value.

    Handles:
      - ``$eip`` / ``$rip`` / ``$<reg>`` -- read register from debugger
      - ``0x...`` -- hex literal
      - Decimal string of digits -- decimal literal
      - Anything else -- treat as a raw ASCII subsequence
    """
    if token.startswith("$"):
        # Register lookup
        reg_name = token[1:]
        try:
            reg_val = debugger.read_register(reg_name)
        except Exception as exc:
            error(f"Could not read register [bold]{reg_name}[/bold]: {exc}")
            return None
        info(f"Register [bold]{reg_name}[/bold] = {hex(reg_val)}")
        return reg_val

    # Hex literal
    if token.startswith("0x") or token.startswith("0X"):
        try:
            return int(token, 16)
        except ValueError:
            error(f"Invalid hex value: [bold]{token}[/bold]")
            return None

    # Decimal literal
    if token.isdigit():
        return int(token)

    # Raw ASCII subsequence (e.g. "Aaab")
    return token


def cmd_cyclic(debugger, args):
    """Generate or search a De Bruijn cyclic pattern.

    Usage:
        cyclic 200          Generate and print a 200-byte pattern
        cyclic -l 0x41414141  Find offset for hex value
        cyclic -l Aaab        Find offset for ASCII subsequence
        cyclic -l $eip        Lookup current EIP value from debugger
    """
    parser = argparse.ArgumentParser(prog="cyclic", add_help=False)
    parser.add_argument("-l", "--lookup", type=str, default=None,
                        help="Look up the offset of a value in the pattern")
    parser.add_argument("-n", type=int, default=None,
                        help="Subsequence length (default: 4 for 32-bit, 8 for 64-bit)")
    parser.add_argument("count", nargs="?", type=int, default=None,
                        help="Number of bytes to generate")

    import shlex
    try:
        arg_list = shlex.split(args) if isinstance(args, str) else args
    except ValueError:
        arg_list = args.split() if isinstance(args, str) else args

    try:
        parsed = parser.parse_args(arg_list)
    except SystemExit:
        error("Usage: cyclic <count> | cyclic -l <value> [-n 4|8]")
        return

    # Determine subsequence length based on target bitness
    if parsed.n is not None:
        n = parsed.n
    else:
        # Default: 4 for 32-bit (WoW64), 8 for native 64-bit
        try:
            is_32bit = getattr(debugger, "is_wow64", True)
        except Exception:
            is_32bit = True
        n = 4 if is_32bit else 8

    # --- Lookup mode ---
    if parsed.lookup is not None:
        value = _resolve_lookup_value(debugger, parsed.lookup, n)
        if value is None:
            return

        if isinstance(value, int):
            display = hex(value)
        else:
            display = repr(value)

        offset = cyclic_find(value, n)
        if offset < 0:
            error(f"Value {display} not found in cyclic pattern (n={n})")
        else:
            success(
                f"Found value {display} at offset "
                f"[bold]{offset}[/bold] (0x{offset:x})"
            )
        return

    # --- Generate mode ---
    if parsed.count is None:
        error("Usage: cyclic <count> | cyclic -l <value>")
        return

    if parsed.count <= 0:
        error("Count must be a positive integer")
        return

    pattern = cyclic(parsed.count, n)
    info(f"Cyclic pattern of {parsed.count} bytes (n={n}):")
    console.print(f"[cyan]{pattern}[/cyan]")
