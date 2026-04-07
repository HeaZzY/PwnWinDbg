"""`asm` — assemble x86/x64 instructions via Keystone.

Two operating modes:

    asm <addr> "instructions"
        Assemble at the given target address (so RIP-relative branches
        compute the right delta) and **patch the bytes into target
        memory** at that address. This is the inverse of `disasm` /
        `u`: round-tripping disasm → asm → patch lets the user fix or
        replace instructions in place without crafting raw hex.

    asm "instructions"
        Assemble at address 0 and just **print** the resulting bytes
        without writing to the target. Useful for shellcode bring-up.

Multiple instructions are separated by `;` (Keystone's native delimiter).
The address argument is optional only when no `;` is required to span
multiple instructions.

If the assembled bytes are longer than the original instruction at
`addr`, the user gets a warning — patching may corrupt the next
instruction. Use `nop` padding or move to a free region first.

Examples:
    asm rip "nop; ret"
    asm 0x401234 "mov rax, 0x4141414141414141; jmp rax"
    asm "syscall; ret"
"""

import shlex

from ..core.disasm import disassemble_at
from ..core.memory import read_memory_safe, write_memory
from ..display.formatters import error, info, success, console
from ..utils.addr_expr import eval_expr


def cmd_asm(debugger, args):
    """Assemble instructions via Keystone and optionally patch them in.

    Usage:
        asm <addr> "<instructions>"   — assemble at addr, write into target
        asm "<instructions>"          — assemble at 0, just print bytes
    """
    if not args.strip():
        error('Usage: asm <addr> "<instructions>"  |  asm "<instructions>"')
        return None

    try:
        ks = _get_ks(debugger.is_wow64)
    except _AsmError as e:
        error(str(e))
        return None

    addr, asm_text = _split_addr_and_asm(debugger, args)
    if asm_text is None:
        return None  # error already printed

    try:
        encoded, count = ks.asm(asm_text, addr or 0)
    except Exception as e:
        error(f"Keystone failed: {e}")
        return None

    if not encoded:
        error("Keystone produced no output (empty assembly?)")
        return None

    data = bytes(encoded)
    hex_str = " ".join(f"{b:02x}" for b in data)
    info(f"Assembled {count} insn(s), {len(data)} byte(s):")
    console.print(f"  [bright_blue]{hex_str}[/]")

    if addr is None:
        return None  # print-only mode

    # Patching mode: warn if we're about to overflow the original
    # instruction at addr.
    _warn_on_overflow(debugger, addr, len(data))

    try:
        write_memory(debugger.process_handle, addr, data)
    except Exception as e:
        error(f"Failed to write at {addr:#x}: {e}")
        return None

    success(f"Patched {len(data)} byte(s) at {addr:#x}")
    info(f"Use `disasm {addr:#x} {max(count + 2, 4)}` to verify")
    return None


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

class _AsmError(Exception):
    pass


def _get_ks(is_wow64):
    """Return a Keystone engine for the right architecture, or raise."""
    try:
        import keystone
    except ImportError:
        raise _AsmError(
            "Keystone is not installed. `pip install keystone-engine`"
        )
    arch = keystone.KS_ARCH_X86
    mode = keystone.KS_MODE_32 if is_wow64 else keystone.KS_MODE_64
    try:
        return keystone.Ks(arch, mode)
    except keystone.KsError as e:
        raise _AsmError(f"Keystone init failed: {e}")


def _split_addr_and_asm(debugger, raw):
    """Parse `asm` arguments into (addr_or_None, asm_text).

    Two shapes:
        addr "asm text"     -> (eval_expr(addr), asm text)
        "asm text"          -> (None, asm text)

    The asm text MUST be quoted (single or double) so we can keep `;`
    separators. Returns (None, None) on parse error.
    """
    raw = raw.strip()
    if not raw:
        error("Empty asm")
        return None, None

    # Find the first quote — everything before it is the (optional) addr.
    q_pos = -1
    for q in ('"', "'"):
        p = raw.find(q)
        if p != -1 and (q_pos == -1 or p < q_pos):
            q_pos = p

    if q_pos == -1:
        error('Quote the assembly text: asm <addr> "mov rax, 1; ret"')
        return None, None

    addr_part = raw[:q_pos].strip()
    quoted = raw[q_pos:]
    try:
        toks = shlex.split(quoted)
    except ValueError as e:
        error(f"Failed to parse quoted asm: {e}")
        return None, None
    if not toks:
        error("Empty quoted asm")
        return None, None
    asm_text = toks[0]

    if not addr_part:
        return None, asm_text

    addr = eval_expr(debugger, addr_part)
    if addr is None:
        error(f"Cannot resolve address: {addr_part}")
        return None, None
    return addr, asm_text


def _warn_on_overflow(debugger, addr, new_len):
    """If the assembled bytes overrun the original instruction at addr,
    warn the user. We disassemble the *original* bytes (which we just
    overwrote in memory? no — we read BEFORE writing) and compare sizes."""
    orig = read_memory_safe(debugger.process_handle, addr, 16)
    if not orig:
        return
    insns = disassemble_at(debugger.disassembler, orig, addr, 1)
    if not insns:
        return
    _, orig_size, _, _ = insns[0]
    if new_len > orig_size:
        info(
            f"  note: new bytes ({new_len}) exceed original instruction "
            f"size ({orig_size}) — next instruction(s) will be partially "
            f"clobbered"
        )
    elif new_len < orig_size:
        info(
            f"  note: new bytes ({new_len}) shorter than original "
            f"({orig_size}) — leftover bytes ({orig_size - new_len}) of "
            f"the old instruction remain; consider padding with NOPs"
        )
