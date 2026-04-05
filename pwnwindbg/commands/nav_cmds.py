"""
Navigation commands, address info, and utility commands.

Commands:
    nextcall  - Step until next call instruction
    nextret   - Step until next ret instruction
    nextjmp   - Step until next jmp/branch instruction
    xinfo     - Address info lookup
    distance  - Distance between two addresses
    entry     - Break at PE entry point
    hexdump   - Classic hexdump display
"""

import ctypes

from ..core.debugger import DebuggerState
from ..core.memory import read_memory_safe, virtual_query
from ..core.disasm import (
    disassemble_at,
    is_call_instruction,
    is_ret_instruction,
    is_branch_instruction,
)
from ..display.formatters import info, error, success, warn, console, banner
from ..utils.constants import prot_to_str, mem_type_to_str, mem_state_to_str, MEM_COMMIT

from rich.table import Table
from rich.text import Text


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _step_until(debugger, predicate, label, max_steps=10000):
    """Step one instruction at a time until *predicate(mnemonic)* is True."""
    if debugger.state != DebuggerState.STOPPED:
        error("Process is not stopped")
        return None

    for _ in range(max_steps):
        ip = debugger._get_current_ip()
        code = read_memory_safe(debugger.process_handle, ip, 32)
        if code:
            insns = disassemble_at(debugger.disassembler, code, ip, 1)
            if insns:
                addr, raw, mnemonic, op_str = insns[0]
                if predicate(mnemonic):
                    info(f"Hit {label} at {ip:#x}: {mnemonic} {op_str}")
                    return {"reason": "single_step", "address": ip}

        stop = debugger.do_step_into()
        if not stop or stop.get("reason") not in ("single_step",):
            return stop  # breakpoint, exception, exit, etc.

    error(f"Gave up after {max_steps} steps without finding a {label}")
    return {"reason": "single_step", "address": debugger._get_current_ip()}


def _resolve_addr(debugger, token):
    """Resolve an address expression (supports arithmetic like addr+0x10)."""
    from ..utils.addr_expr import eval_expr
    result = eval_expr(debugger, token)
    if result is None:
        error(f"Cannot resolve '{token}' to an address")
    return result


def _mbi_base(mbi):
    """Safely get BaseAddress as an int from an MBI struct."""
    ba = mbi.BaseAddress
    if ba is None:
        return 0
    if hasattr(ba, 'value'):
        return ba.value or 0
    try:
        return ctypes.cast(ba, ctypes.c_void_p).value or 0
    except Exception:
        return int(ba) if ba else 0


def _mbi_alloc_base(mbi):
    """Safely get AllocationBase as an int."""
    ab = mbi.AllocationBase
    if ab is None:
        return 0
    if hasattr(ab, 'value'):
        return ab.value or 0
    try:
        return ctypes.cast(ab, ctypes.c_void_p).value or 0
    except Exception:
        return int(ab) if ab else 0


# ---------------------------------------------------------------------------
# nextcall / nextret / nextjmp
# ---------------------------------------------------------------------------

def cmd_nextcall(debugger, args):
    """Step until the next ``call`` instruction."""
    return _step_until(debugger, is_call_instruction, "call")


def cmd_nextret(debugger, args):
    """Step until the next ``ret`` instruction."""
    return _step_until(debugger, is_ret_instruction, "ret")


def cmd_nextjmp(debugger, args):
    """Step until the next branch (jmp / jcc / loop) instruction."""
    return _step_until(debugger, is_branch_instruction, "branch")


# ---------------------------------------------------------------------------
# xinfo – address information
# ---------------------------------------------------------------------------

def cmd_xinfo(debugger, args):
    """Show detailed information about an address.

    Usage: xinfo <address|register>
    """
    parts = args.strip().split()
    if not parts:
        error("Usage: xinfo <address>")
        return None

    addr = _resolve_addr(debugger, parts[0])
    if addr is None:
        return None

    banner(f"xinfo {addr:#x}")

    # --- Memory region info via VirtualQueryEx ---
    mbi = virtual_query(debugger.process_handle, addr)
    if mbi:
        base = _mbi_base(mbi)
        alloc_base = _mbi_alloc_base(mbi)

        tbl = Table(title="Memory Region", show_header=False, border_style="cyan")
        tbl.add_column("Field", style="bold")
        tbl.add_column("Value")

        tbl.add_row("Address", f"{addr:#x}")
        tbl.add_row("Base Address", f"{base:#x}")
        tbl.add_row("Allocation Base", f"{alloc_base:#x}")
        tbl.add_row("Region Size", f"{mbi.RegionSize:#x} ({mbi.RegionSize} bytes)")
        tbl.add_row("State", mem_state_to_str(mbi.State))
        tbl.add_row("Protect", prot_to_str(mbi.Protect))
        tbl.add_row("Alloc Protect", prot_to_str(mbi.AllocationProtect))
        tbl.add_row("Type", mem_type_to_str(mbi.Type))

        offset_in_region = addr - base
        tbl.add_row("Offset in region", f"{offset_in_region:#x}")

        console.print(tbl)
    else:
        warn("VirtualQueryEx failed for this address")

    # --- Module info ---
    mod = debugger.symbols.get_module_at(addr)
    if mod:
        info(f"Module : {mod.name}")
        info(f"Base   : {mod.base_address:#x}")
        info(f"Offset : +{mod.offset_of(addr):#x}")
    else:
        info("Address does not belong to any known module")

    # --- Symbol resolution ---
    sym = debugger.symbols.resolve_address(addr)
    if sym:
        info(f"Symbol : {sym}")

    # --- Quick classification ---
    if debugger.state == DebuggerState.STOPPED:
        regs, _ = debugger.get_registers()
        sp_key = "Esp" if debugger.is_wow64 else "Rsp"
        sp = regs.get(sp_key, 0) if regs else 0
        if mbi and sp:
            base = _mbi_base(mbi)
            if base <= sp <= base + mbi.RegionSize:
                info("Region contains the stack pointer -> likely [bold]stack[/bold]")

    if mbi and mbi.State == MEM_COMMIT:
        prot_str = prot_to_str(mbi.Protect).lower()
        if "x" in prot_str:
            info("Region is executable -> likely [bold]code[/bold]")
        elif "w" in prot_str and "x" not in prot_str:
            info("Region is RW (no exec) -> likely [bold]heap / data[/bold]")

    return None


# ---------------------------------------------------------------------------
# distance
# ---------------------------------------------------------------------------

def cmd_distance(debugger, args):
    """Show the distance between two addresses.

    Usage: distance <addr1> <addr2>
    """
    parts = args.strip().split()
    if len(parts) < 2:
        error("Usage: distance <addr1> <addr2>")
        return None

    a = _resolve_addr(debugger, parts[0])
    b = _resolve_addr(debugger, parts[1])
    if a is None or b is None:
        return None

    diff = b - a

    tbl = Table(title="Distance", show_header=False, border_style="cyan")
    tbl.add_column("Field", style="bold")
    tbl.add_column("Value")
    tbl.add_row("From", f"{a:#x}")
    tbl.add_row("To", f"{b:#x}")
    tbl.add_row("Offset (hex)", f"{diff:#x}")
    tbl.add_row("Offset (dec)", str(diff))
    tbl.add_row("Abs offset", f"{abs(diff):#x} ({abs(diff)})")
    if diff > 0:
        tbl.add_row("Direction", "forward  ->")
    elif diff < 0:
        tbl.add_row("Direction", "<-  backward")
    else:
        tbl.add_row("Direction", "same address")
    console.print(tbl)
    return None


# ---------------------------------------------------------------------------
# entry – break at PE entry point
# ---------------------------------------------------------------------------

def cmd_entry(debugger, args):
    """Set a breakpoint at the PE entry point and continue.

    Usage: entry
    """
    exe_path = debugger.exe_path
    if not exe_path:
        error("No executable loaded")
        return None

    try:
        import pefile
    except ImportError:
        error("pefile is required: pip install pefile")
        return None

    try:
        pe = pefile.PE(exe_path)
        entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        image_base = pe.OPTIONAL_HEADER.ImageBase
        entry_va = entry_rva + image_base
        pe.close()
    except Exception as exc:
        error(f"Failed to parse PE: {exc}")
        return None

    success(f"Entry point: {entry_va:#x}  (ImageBase {image_base:#x} + RVA {entry_rva:#x})")

    debugger.bp_manager.add(debugger.process_handle, entry_va)
    debugger.bp_manager.save_address(entry_va)
    info(f"Breakpoint set at entry point {entry_va:#x}")

    if debugger.state == DebuggerState.STOPPED:
        return debugger.do_continue()
    return None


# ---------------------------------------------------------------------------
# p / print – resolve and display symbol / expression
# ---------------------------------------------------------------------------

def cmd_print(debugger, args):
    """Resolve a symbol or expression and print its value.

    Usage: p <expr>
    Examples:
        p &WinExec
        p WinExec
        p kernel32!WinExec
        p rax
        p rsp+0x10
    """
    expr = args.strip()
    if not expr:
        error("Usage: p <expression>  (e.g. p &WinExec, p rsp+0x10)")
        return None

    addr = _resolve_addr(debugger, expr)
    if addr is None:
        return None

    # Try to get symbol name for the resolved address
    sym = debugger.symbols.resolve_address(addr)
    text = Text()
    text.append(f"  {addr:#x}", style="bold bright_cyan")
    if sym:
        text.append(f"  <{sym}>", style="bright_yellow")
    console.print(text)
    return None


# ---------------------------------------------------------------------------
# hexdump – classic hex + ASCII dump
# ---------------------------------------------------------------------------

def cmd_hexdump(debugger, args):
    """Classic hexdump (16 bytes per line, hex + ASCII).

    Usage: hexdump <address> [length]
           length defaults to 128
    """
    parts = args.strip().split()
    if not parts:
        error("Usage: hexdump <address> [length]")
        return None

    addr = _resolve_addr(debugger, parts[0])
    if addr is None:
        return None

    length = 128
    if len(parts) > 1:
        try:
            length = int(parts[1], 0)
        except ValueError:
            error(f"Invalid length: {parts[1]}")
            return None

    # Auto-advance on repeat
    addr = debugger.track_examine("hexdump", addr, length)

    data = read_memory_safe(debugger.process_handle, addr, length)
    if not data:
        error(f"Cannot read {length} bytes at {addr:#x}")
        return None

    banner(f"Hexdump at {addr:#x}  ({len(data)} bytes)")

    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]

        hex_parts = []
        for i, byte in enumerate(chunk):
            if i == 8:
                hex_parts.append("")  # extra gap between groups of 8
            hex_parts.append(f"{byte:02x}")
        hex_str = " ".join(hex_parts)

        # Pad if last line is shorter than 16 bytes
        missing = 16 - len(chunk)
        if missing:
            pad = missing * 3
            if len(chunk) <= 8:
                pad += 1
            hex_str += " " * pad

        ascii_str = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in chunk)
        line_addr = addr + offset

        text = Text()
        text.append(f"  {line_addr:08x}  ", style="bright_cyan")
        text.append(hex_str, style="white")
        text.append(f"  |{ascii_str}|", style="bright_green")
        console.print(text)

    return None
