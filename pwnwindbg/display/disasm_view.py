"""Disassembly display rendering."""

import re

from rich.text import Text

from .common import console, banner, ARROW_COLOR, ADDR_COLOR, SYMBOL_COLOR
from ..core.disasm import is_call_instruction, is_branch_instruction, is_ret_instruction, get_branch_target

# Matches hex immediates like 0x41b000 in operands
_HEX_IMM_RE = re.compile(r'\b0x([0-9a-fA-F]{4,})\b')


def display_disasm(instructions, current_ip, symbol_resolver=None, count=10,
                   ret_addr=None, target_insns=None, imm_resolver=None,
                   call_args=None):
    """Display disassembly in pwndbg style.

    imm_resolver:  callable(int) -> str or None
                   Resolves an immediate value to a descriptive annotation
                   (e.g. '"hello"', 'ch72.exe+0x1000', pointer info).
    target_insns:  instructions at the ret/jmp target, shown after a separator.
    call_args:     list of (name, value, annotation) tuples to render under
                   the call instruction at current_ip. None to disable.
    """
    banner("DISASM")

    # If the current IP is a ret/jmp with a known target, split the display
    split_after = None
    if target_insns and instructions:
        for i, (addr, size, mnemonic, op_str) in enumerate(instructions):
            if addr == current_ip and (is_ret_instruction(mnemonic)
                                       or mnemonic == "jmp"):
                split_after = i
                break

    if split_after is not None:
        main_insns = instructions[:split_after + 1]
        after_insns = target_insns
        remaining = count - len(main_insns) - 1
    else:
        main_insns = instructions[:count]
        after_insns = None
        remaining = 0

    for addr, size, mnemonic, op_str in main_insns:
        _print_insn(addr, size, mnemonic, op_str, current_ip,
                    symbol_resolver, ret_addr, imm_resolver)
        if (call_args and addr == current_ip
                and is_call_instruction(mnemonic)):
            _print_call_args(call_args)

    if after_insns and remaining > 0:
        sep = Text()
        sep.append("    \u2193", style="bold bright_red")
        console.print(sep)

        for addr, size, mnemonic, op_str in after_insns[:remaining]:
            _print_insn(addr, size, mnemonic, op_str, 0,
                        symbol_resolver, None, imm_resolver)


def _print_insn(addr, size, mnemonic, op_str, current_ip,
                symbol_resolver, ret_addr, imm_resolver=None):
    """Print a single disassembly line."""
    text = Text()

    # Arrow marker
    if addr == current_ip:
        text.append(" \u25ba ", style=ARROW_COLOR)
    else:
        text.append("   ", style="")

    # Address
    text.append(f"{addr:#x}", style=ADDR_COLOR)
    text.append("    ", style="")

    # Mnemonic coloring
    if is_call_instruction(mnemonic):
        text.append(f"{mnemonic:8s}", style="bold bright_yellow")
    elif is_branch_instruction(mnemonic):
        text.append(f"{mnemonic:8s}", style="bold bright_cyan")
    elif is_ret_instruction(mnemonic):
        text.append(f"{mnemonic:8s}", style="bold bright_red")
    elif mnemonic in ("nop", "int3"):
        text.append(f"{mnemonic:8s}", style="bright_black")
    else:
        text.append(f"{mnemonic:8s}", style="white")

    # Operands
    text.append(f"{op_str}", style="white")

    annotation = None

    # Resolve call/branch targets
    if (is_call_instruction(mnemonic) or is_branch_instruction(mnemonic)) and symbol_resolver:
        target = get_branch_target(op_str)
        if target is not None:
            sym = symbol_resolver(target)
            if sym:
                annotation = (f"  <{sym}>", SYMBOL_COLOR)

    # Show return target for ret at current IP
    elif is_ret_instruction(mnemonic) and addr == current_ip and ret_addr is not None:
        sym = symbol_resolver(ret_addr) if symbol_resolver else None
        if sym:
            annotation = (f"  <{ret_addr:#x} ({sym})>", "bold bright_red")
        else:
            annotation = (f"  <{ret_addr:#x}>", "bold bright_red")

    # For other instructions, try to resolve immediates (push 0x41b000, mov eax, 0x...)
    elif imm_resolver and not is_ret_instruction(mnemonic):
        # Find the largest hex immediate in the operands
        matches = _HEX_IMM_RE.findall(op_str)
        if matches:
            # Take the last (usually the most interesting) immediate
            for hex_val in reversed(matches):
                imm = int(hex_val, 16)
                if imm > 0xFFFF:  # Only resolve plausible addresses
                    desc = imm_resolver(imm)
                    if desc:
                        annotation = (f"  <{desc}>", SYMBOL_COLOR)
                        break

    if annotation:
        text.append(annotation[0], style=annotation[1])

    console.print(text)


def _print_call_args(args):
    """Render `arg name : value (annotation)` lines under the call line.

    Pads the name column to whatever the widest arg name is so prototypes
    with longer names (`lpFileName`, `dwCreationDisposition`) line up.
    """
    if not args:
        return
    name_width = max(len(name) for name, _, _ in args)
    name_width = max(name_width, 5)  # keep at least the legacy 5-char column
    for name, val, ann in args:
        line = Text()
        line.append("        ", style="")
        line.append(f"{name:{name_width}s}", style="bright_yellow")
        line.append(" = ", style="bright_black")
        if val is None:
            line.append("??", style="bright_red")
        else:
            line.append(f"{val:#x}", style="white")
        if ann:
            line.append(f"  {ann}", style=SYMBOL_COLOR)
        console.print(line)
