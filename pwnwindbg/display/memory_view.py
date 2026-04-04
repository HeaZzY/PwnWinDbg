"""Memory examination display (x/ commands)."""

import struct
from rich.text import Text

from .common import console, ADDR_COLOR


def display_hex_bytes(address, data, bytes_per_line=16):
    """Display hex bytes like x/bx."""
    for offset in range(0, len(data), bytes_per_line):
        chunk = data[offset:offset + bytes_per_line]
        text = Text()
        text.append(f"  {address + offset:#x}:", style=ADDR_COLOR)
        text.append("  ", style="")

        hex_parts = [f"{b:02x}" for b in chunk]
        text.append(" ".join(hex_parts), style="white")

        text.append("  ", style="")
        ascii_str = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in chunk)
        text.append(ascii_str, style="bright_black")

        console.print(text)


def display_hex_dwords(address, data, ptr_size=4):
    """Display hex dwords/qwords."""
    step = ptr_size
    fmt = "<I" if ptr_size == 4 else "<Q"
    val_fmt = "0x{:08x}" if ptr_size == 4 else "0x{:016x}"

    for offset in range(0, len(data), step * 4):
        text = Text()
        text.append(f"  {address + offset:#x}:", style=ADDR_COLOR)
        text.append("  ", style="")

        for j in range(4):
            pos = offset + j * step
            if pos + step <= len(data):
                val = struct.unpack(fmt, data[pos:pos + step])[0]
                text.append(val_fmt.format(val), style="white")
                text.append(" ", style="")

        console.print(text)
