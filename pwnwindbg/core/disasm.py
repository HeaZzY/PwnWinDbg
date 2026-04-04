"""Disassembly engine using Capstone."""

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CsInsn


def create_disassembler(is_32bit):
    """Create a Capstone disassembler for the given architecture."""
    mode = CS_MODE_32 if is_32bit else CS_MODE_64
    md = Cs(CS_ARCH_X86, mode)
    md.detail = True
    return md


def disassemble_at(md, code_bytes, address, count=10):
    """Disassemble `count` instructions at `address`.
    Returns list of (address, size, mnemonic, op_str) tuples."""
    instructions = []
    for insn in md.disasm(code_bytes, address):
        instructions.append((insn.address, insn.size, insn.mnemonic, insn.op_str))
        if len(instructions) >= count:
            break
    return instructions


def is_call_instruction(mnemonic):
    """Check if instruction is a call."""
    return mnemonic.lower() == "call"


def is_branch_instruction(mnemonic):
    """Check if instruction is a branch (jmp, jcc, etc.)."""
    m = mnemonic.lower()
    return m.startswith("j") or m in ("loop", "loope", "loopne")


def is_ret_instruction(mnemonic):
    """Check if instruction is a return."""
    return mnemonic.lower() in ("ret", "retn", "retf")


def get_branch_target(op_str):
    """Try to parse a branch/call target from op_str. Returns int or None."""
    op = op_str.strip()
    try:
        return int(op, 0)
    except ValueError:
        # Could be a register or memory operand
        if op.startswith("0x") or op.startswith("0X"):
            try:
                return int(op, 16)
            except ValueError:
                pass
    return None
