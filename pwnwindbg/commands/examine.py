"""Memory examination commands: x/bx, x/wx, x/gx, x/s, x/i"""

from ..core.memory import read_memory_safe, read_string
from ..display.formatters import (
    display_hex_bytes, display_hex_dwords, error, banner, console,
)
from ..core.disasm import disassemble_at


def _kd_session():
    """Return active KD session or None."""
    from .kd_cmds import _kd_session as s
    return s if s and s.connected else None


def _read_mem(debugger, addr, size):
    """Read memory from KD session if active, else local process."""
    kd = _kd_session()
    if kd:
        data = kd.read_virtual(addr, size)
        return data if data else None
    return read_memory_safe(debugger.process_handle, addr, size)


def _parse_x_args(args, debugger):
    """Parse x/ command arguments: <address> [count]
    Returns (address, count) or (None, None)."""
    from ..utils.addr_expr import eval_expr
    parts = args.strip().split()
    if not parts:
        error("Usage: x/<fmt> <address> [count]")
        return None, None

    addr_str = parts[0]
    count = int(parts[1]) if len(parts) > 1 else 16

    # For KD mode, try parsing as hex directly if eval_expr fails
    addr = eval_expr(debugger, addr_str)
    if addr is None and _kd_session():
        try:
            addr = int(addr_str, 0)
        except ValueError:
            pass
    if addr is None:
        error(f"Cannot resolve address: {addr_str}")
        return None, None

    return addr, count


def cmd_x_bytes(debugger, args):
    """x/bx <addr> [count] — read bytes, hex display"""
    addr, count = _parse_x_args(args, debugger)
    if addr is None:
        return None

    addr = debugger.track_examine("x/bx", addr, count)

    data = _read_mem(debugger, addr, count)
    if data is None:
        error(f"Cannot read memory at {addr:#x}")
        return None

    display_hex_bytes(addr, data)
    return None


def cmd_x_dwords(debugger, args):
    """x/wx <addr> [count] — read dwords"""
    addr, count = _parse_x_args(args, debugger)
    if addr is None:
        return None

    byte_count = count * 4
    addr = debugger.track_examine("x/wx", addr, byte_count)

    data = _read_mem(debugger, addr, byte_count)
    if data is None:
        error(f"Cannot read memory at {addr:#x}")
        return None

    display_hex_dwords(addr, data, ptr_size=4)
    return None


def cmd_x_qwords(debugger, args):
    """x/gx <addr> [count] — read qwords"""
    addr, count = _parse_x_args(args, debugger)
    if addr is None:
        return None

    byte_count = count * 8
    addr = debugger.track_examine("x/gx", addr, byte_count)

    data = _read_mem(debugger, addr, byte_count)
    if data is None:
        error(f"Cannot read memory at {addr:#x}")
        return None

    display_hex_dwords(addr, data, ptr_size=8)
    return None


def cmd_x_string(debugger, args):
    """x/s <addr> — read string"""
    from ..utils.addr_expr import eval_expr
    parts = args.strip().split()
    if not parts:
        error("Usage: x/s <address>")
        return None

    addr = eval_expr(debugger, parts[0])
    if addr is None and _kd_session():
        try:
            addr = int(parts[0], 0)
        except ValueError:
            pass
    if addr is None:
        error(f"Cannot resolve address: {parts[0]}")
        return None

    kd = _kd_session()
    if kd:
        data = kd.read_virtual(addr, 1024)
        if not data:
            error(f"Cannot read memory at {addr:#x}")
            return None
        # Extract null-terminated string
        end = data.find(b'\x00')
        s = data[:end].decode("utf-8", errors="replace") if end >= 0 else data.decode("utf-8", errors="replace")
    else:
        s = read_string(debugger.process_handle, addr, max_len=1024)
        if s is None:
            error(f"Cannot read memory at {addr:#x}")
            return None

    from rich.text import Text
    text = Text()
    text.append(f"  {addr:#x}: ", style="bright_cyan")
    text.append(f'"{s}"', style="bright_green")
    text.append(f"  (len={len(s)})", style="bright_black")
    console.print(text)
    return None


def cmd_x_instructions(debugger, args):
    """x/i <addr> [count] — disassemble"""
    kd = _kd_session()
    if kd:
        from .kd_cmds import cmd_kddisasm
        return cmd_kddisasm(debugger, args)

    addr, count = _parse_x_args(args, debugger)
    if addr is None:
        return None

    # Estimate block size from instruction count (advance past all shown insns)
    # We'll fix up after disassembly with actual sizes
    addr = debugger.track_examine("x/i", addr, 0)

    insns = debugger.get_disassembly(addr, count)
    if not insns:
        error(f"Cannot disassemble at {addr:#x}")
        return None

    # Fix up next address to be right after the last instruction
    if insns:
        last_addr, last_size, _, _ = insns[-1]
        actual_end = last_addr + last_size
        debugger._examine_next["x/i"] = (debugger._examine_next["x/i"][0], actual_end)

    from ..display.formatters import display_disasm
    display_disasm(insns, addr, symbol_resolver=debugger.symbols.resolve_address, count=count)
    return None


def parse_x_command(cmd_str, debugger):
    """Parse an x/ command and dispatch to the right handler.
    Supports GDB-style: x/10i, x/32bx, x/100gx addr
    Returns the handler function and remaining args, or (None, None)."""
    import re

    if not cmd_str.startswith("x/"):
        return None, None

    # Split on first space: "x/100i" "0x401000"
    parts = cmd_str.split(None, 1)
    spec = parts[0][2:]  # everything after "x/"
    rest = parts[1] if len(parts) > 1 else ""

    # Parse optional count prefix: "100i" -> count=100, fmt="i"
    #                               "bx"  -> count=None, fmt="bx"
    m = re.match(r'^(\d+)?(\D+)$', spec)
    if not m:
        error(f"Unknown format: x/{spec}  (valid: [N]bx, [N]wx, [N]gx, [N]s, [N]i)")
        return None, None

    count_str, fmt = m.group(1), m.group(2)

    handlers = {
        "bx": cmd_x_bytes,
        "b": cmd_x_bytes,
        "wx": cmd_x_dwords,
        "w": cmd_x_dwords,
        "gx": cmd_x_qwords,
        "g": cmd_x_qwords,
        "s": cmd_x_string,
        "i": cmd_x_instructions,
    }

    handler = handlers.get(fmt)
    if not handler:
        error(f"Unknown format: x/{fmt}  (valid: [N]bx, [N]wx, [N]gx, [N]s, [N]i)")
        return None, None

    # Inject count into args if provided in the format spec
    if count_str:
        # rest is just the address, prepend nothing - we pass "addr count"
        # But _parse_x_args expects "addr [count]", so append count
        if rest:
            rest = f"{rest} {count_str}"
        else:
            rest = count_str

    return handler, rest
