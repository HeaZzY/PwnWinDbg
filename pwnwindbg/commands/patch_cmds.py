"""
Memory writing, instruction patching, and register modification commands.
"""

import struct

from ..display.formatters import info, error, success, console
from ..core.memory import write_memory
from ..core.registers import get_context, set_context


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_address(debugger, addr_str):
    """Resolve an address expression (supports arithmetic like addr+0x10)."""
    from ..utils.addr_expr import eval_expr
    result = eval_expr(debugger, addr_str)
    if result is None:
        raise ValueError(f"Cannot resolve: {addr_str}")
    return result


def _parse_hex_bytes(hex_str):
    """Parse a hex string (e.g. '90909090') into bytes."""
    hex_str = hex_str.strip()
    if hex_str.startswith("0x") or hex_str.startswith("0X"):
        hex_str = hex_str[2:]
    if len(hex_str) % 2 != 0:
        raise ValueError(f"Hex string has odd length: {hex_str}")
    return bytes.fromhex(hex_str)


# ---------------------------------------------------------------------------
# patch — write raw bytes / NOPs / int3 / ASCII to memory
# ---------------------------------------------------------------------------

def cmd_patch(debugger, args):
    """Write bytes to memory.

    Usage:
        patch <address> <hex_bytes>       — write raw hex bytes
        patch <address> nop <count>       — write N NOP (0x90) bytes
        patch <address> int3              — write a single INT3 (0xCC)
        patch <address> "string"          — write an ASCII string
    """
    import shlex
    try:
        args = shlex.split(args) if isinstance(args, str) else args
    except ValueError:
        args = args.split() if isinstance(args, str) else args

    if len(args) < 2:
        error("Usage: patch <address> <hex_bytes|nop N|int3|\"string\">")
        return

    try:
        addr = _resolve_address(debugger, args[0])
    except (ValueError, TypeError) as exc:
        error(f"Invalid address '{args[0]}': {exc}")
        return

    second = args[1].lower()

    # --- nop N ---
    if second == "nop":
        count = 1
        if len(args) >= 3:
            try:
                count = int(args[2], 0)
            except ValueError:
                error(f"Invalid NOP count '{args[2]}'")
                return
        data = b"\x90" * count
        info(f"Writing {count} NOP(s) at {addr:#x}")

    # --- int3 ---
    elif second == "int3":
        data = b"\xcc"
        info(f"Writing INT3 at {addr:#x}")

    # --- quoted ASCII string ---
    elif (args[1].startswith('"') and args[-1].endswith('"')) or \
         (args[1].startswith("'") and args[-1].endswith("'")):
        # Rejoin all tokens and strip surrounding quotes
        raw = " ".join(args[1:])
        raw = raw[1:-1]  # strip first and last quote character
        data = raw.encode("utf-8")
        info(f"Writing {len(data)}-byte string at {addr:#x}")

    # --- raw hex bytes ---
    else:
        hex_str = "".join(args[1:])
        try:
            data = _parse_hex_bytes(hex_str)
        except ValueError as exc:
            error(f"Invalid hex bytes: {exc}")
            return
        info(f"Writing {len(data)} byte(s) at {addr:#x}")

    try:
        write_memory(debugger.process_handle, addr, data)
        success(f"Patched {len(data)} byte(s) at {addr:#x}")
    except Exception as exc:
        error(f"Failed to write memory at {addr:#x}: {exc}")


# ---------------------------------------------------------------------------
# set — modify a register value
# ---------------------------------------------------------------------------

# Maps lowercased register names to the capitalised field names used by
# WOW64_CONTEXT (32-bit) and CONTEXT64 (64-bit).
_REG_MAP_32 = {
    "eax": "Eax", "ebx": "Ebx", "ecx": "Ecx", "edx": "Edx",
    "esi": "Esi", "edi": "Edi", "ebp": "Ebp", "esp": "Esp",
    "eip": "Eip", "eflags": "EFlags",
}

_REG_MAP_64 = {
    "rax": "Rax", "rbx": "Rbx", "rcx": "Rcx", "rdx": "Rdx",
    "rsi": "Rsi", "rdi": "Rdi", "rbp": "Rbp", "rsp": "Rsp",
    "rip": "Rip",
    "r8": "R8", "r9": "R9", "r10": "R10", "r11": "R11",
    "r12": "R12", "r13": "R13", "r14": "R14", "r15": "R15",
    "eflags": "EFlags",
}


_GDB_TYPE_MAP = {
    "char": ("<B", 1), "byte": ("<B", 1),
    "short": ("<H", 2), "word": ("<H", 2),
    "int": ("<I", 4), "long": ("<I", 4), "dword": ("<I", 4),
    "long long": ("<Q", 8), "qword": ("<Q", 8),
}

import re
_GDB_SET_RE = re.compile(
    r'^\*\s*\(\s*([a-zA-Z ]+?)\s*\*\s*\)\s*'   # *(type*)
    r'(.+?)\s*=\s*(.+)$'                         # addr = value
)


def cmd_set(debugger, args):
    """Set a register or memory value.

    Usage:
        set <register> <value>
        set *(long*)0x401000 = 0x41414141
        set *(qword*)addr = value
    """
    raw = args.strip() if isinstance(args, str) else " ".join(args)

    # GDB-style: set *(type*)addr = value
    m = _GDB_SET_RE.match(raw)
    if m:
        type_name = m.group(1).strip().lower()
        addr_str = m.group(2).strip()
        val_str = m.group(3).strip()

        type_entry = _GDB_TYPE_MAP.get(type_name)
        if type_entry is None:
            error(f"Unknown type '{type_name}'. Valid: {', '.join(sorted(_GDB_TYPE_MAP.keys()))}")
            return

        fmt, size = type_entry

        from ..utils.addr_expr import eval_expr
        addr = eval_expr(debugger, addr_str)
        if addr is None:
            error(f"Cannot resolve address: {addr_str}")
            return

        try:
            value = int(val_str, 0)
        except ValueError:
            error(f"Invalid value '{val_str}'")
            return

        try:
            data = struct.pack(fmt, value)
        except struct.error as exc:
            error(f"Value {value:#x} doesn't fit in {type_name} ({size} bytes): {exc}")
            return

        try:
            write_memory(debugger.process_handle, addr, data)
            success(f"Wrote {type_name} ({size} bytes) at {addr:#x} = {value:#x}")
        except Exception as exc:
            error(f"Failed to write at {addr:#x}: {exc}")
        return

    # Register mode: set reg value
    parts = raw.split()
    if len(parts) < 2:
        error("Usage: set <register> <value>  or  set *(type*)addr = value")
        return

    reg_name = parts[0].lower()
    try:
        value = int(parts[1], 0)
    except ValueError:
        error(f"Invalid value '{parts[1]}'")
        return

    reg_map = _REG_MAP_32 if debugger.is_wow64 else _REG_MAP_64
    field_name = reg_map.get(reg_name)
    if field_name is None:
        error(f"Unknown register '{reg_name}'. Valid: {', '.join(sorted(reg_map.keys()))}")
        return

    try:
        th = debugger.get_active_thread_handle()
        ctx = get_context(th, debugger.is_wow64)
        setattr(ctx, field_name, value)
        set_context(th, ctx, debugger.is_wow64)
        success(f"{reg_name.upper()} = {value:#x}")
    except Exception as exc:
        error(f"Failed to set {reg_name.upper()}: {exc}")


# ---------------------------------------------------------------------------
# write — write typed values (byte / word / dword / qword / string)
# ---------------------------------------------------------------------------

_TYPE_INFO = {
    "byte":  ("<B", 1),
    "word":  ("<H", 2),
    "dword": ("<I", 4),
    "qword": ("<Q", 8),
}


def cmd_write(debugger, args):
    """Write a typed value to memory.

    Usage:
        write <type> <address> <value>
    Types: byte, word, dword, qword, string
    Examples:
        write dword 0x401000 0x41414141
        write qword 0x401000 0x1234567890
        write byte  0x401000 0x90
        write string 0x401000 "hello"
    """
    import shlex
    try:
        args = shlex.split(args) if isinstance(args, str) else args
    except ValueError:
        args = args.split() if isinstance(args, str) else args

    if len(args) < 3:
        error("Usage: write <byte|word|dword|qword|string> <address> <value>")
        return

    type_name = args[0].lower()
    try:
        addr = _resolve_address(debugger, args[1])
    except (ValueError, TypeError) as exc:
        error(f"Invalid address '{args[1]}': {exc}")
        return

    # --- string type ---
    if type_name == "string":
        raw = " ".join(args[2:])
        # Strip surrounding quotes if present
        if (raw.startswith('"') and raw.endswith('"')) or \
           (raw.startswith("'") and raw.endswith("'")):
            raw = raw[1:-1]
        data = raw.encode("utf-8")
        info(f"Writing {len(data)}-byte string at {addr:#x}")
    else:
        type_entry = _TYPE_INFO.get(type_name)
        if type_entry is None:
            error(f"Unknown type '{type_name}'. Valid: byte, word, dword, qword, string")
            return

        fmt, size = type_entry
        try:
            value = int(args[2], 0)
        except ValueError:
            error(f"Invalid value '{args[2]}'")
            return

        try:
            data = struct.pack(fmt, value)
        except struct.error as exc:
            error(f"Value {value:#x} does not fit in {type_name} ({size} bytes): {exc}")
            return
        info(f"Writing {type_name} ({size} bytes) at {addr:#x}: {value:#x}")

    try:
        write_memory(debugger.process_handle, addr, data)
        success(f"Wrote {len(data)} byte(s) at {addr:#x}")
    except Exception as exc:
        error(f"Failed to write memory at {addr:#x}: {exc}")


# ---------------------------------------------------------------------------
# dump — dump memory region to a file or to stdout
# ---------------------------------------------------------------------------

def cmd_dump(debugger, args):
    """Dump a memory region to a file or display as hex.

    Usage:
        dump <address> <size> [output_file]
    Examples:
        dump 0x401000 0x100 output.bin   — save 256 bytes to file
        dump 0x401000 0x100              — display as hex on stdout
    """
    args = args.split() if isinstance(args, str) else args
    if len(args) < 2:
        error("Usage: dump <address> <size> [output_file]")
        return

    try:
        addr = _resolve_address(debugger, args[0])
    except (ValueError, TypeError) as exc:
        error(f"Invalid address '{args[0]}': {exc}")
        return

    try:
        size = int(args[1], 0)
    except ValueError:
        error(f"Invalid size '{args[1]}'")
        return

    # Read the memory
    try:
        from ..core.memory import read_memory
        data = read_memory(debugger.process_handle, addr, size)
    except Exception as exc:
        error(f"Failed to read {size} bytes at {addr:#x}: {exc}")
        return

    if data is None:
        error(f"Failed to read {size} bytes at {addr:#x}")
        return

    # Write to file or display
    if len(args) >= 3:
        filepath = args[2]
        try:
            with open(filepath, "wb") as f:
                f.write(data)
            success(f"Dumped {len(data)} bytes from {addr:#x} to '{filepath}'")
        except OSError as exc:
            error(f"Failed to write file '{filepath}': {exc}")
    else:
        # Pretty-print hex dump to console
        info(f"Dumping {len(data)} bytes from {addr:#x}:")
        _hexdump(addr, data)


def _hexdump(base_addr, data, width=16):
    """Print a classic hex dump to the console."""
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in chunk)
        # Pad hex part for alignment on the last line
        hex_part = hex_part.ljust(width * 3 - 1)
        console.print(f"  {base_addr + offset:#010x}  {hex_part}  |{ascii_part}|")
