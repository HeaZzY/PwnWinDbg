"""xref — find direct code xrefs (call/jmp) to a target address.

Strategy: pull the target module's code section out of the live process,
sweep for `e8`/`e9`/`0f 8x` opcode bytes, compute the rel32 target, and
keep the candidates whose target equals the address we're hunting. Each
surviving candidate is then disassembled with capstone (5 or 6 bytes
starting at the candidate offset) to filter out byte sequences that
just happen to contain `e8`/`e9` in the middle of an unrelated
instruction encoding.

This finds direct calls/jumps and Jcc rel32. It will NOT find:
    - indirect calls through a register or memory operand
    - calls through an IAT thunk (one extra hop — could be added later
      by also accepting xrefs to the IAT slot)
    - Wow64 / x86 short jcc (rel8) — could be added if useful

Usage:
    xref <addr|symbol>
    xref <addr|symbol> <module>     — search a different module
    xref <addr|symbol> --all        — search every loaded user module

Symbol resolution goes through the standard `eval_expr`, so `xref
ntdll!NtClose` works.
"""

import struct

from rich.text import Text

from ..core.disasm import disassemble_at
from ..core.memory import read_memory_safe, virtual_query
from ..display.formatters import banner, console, error, info, success
from ..utils.addr_expr import eval_expr
from ..utils.constants import MEM_COMMIT


# Opcode bytes we sweep for. Each entry is (opcode_byte, instr_size, kind):
#   call rel32: e8 + 4-byte disp -> 5 bytes total
#   jmp  rel32: e9 + 4-byte disp -> 5 bytes total
# Jcc rel32 (`0f 8x`) is handled separately because it's a 2-byte opcode.
_REL32_OPCODES = {
    0xE8: (5, "call"),
    0xE9: (5, "jmp"),
}


def _scan_section(code, section_va, target):
    """Yield (instr_va, instr_size, opcode) for each rel32 branch in `code`
    whose computed target == `target`. False positives are filtered later
    by capstone-decoding the candidate.
    """
    n = len(code)
    i = 0
    while i < n - 5:
        b = code[i]

        # Single-byte rel32 opcodes (e8 / e9)
        if b in _REL32_OPCODES:
            size, kind = _REL32_OPCODES[b]
            if i + size <= n:
                disp = struct.unpack("<i", code[i + 1:i + 5])[0]
                instr_va = section_va + i
                computed = (instr_va + size + disp) & 0xFFFFFFFFFFFFFFFF
                if computed == target:
                    yield instr_va, size, kind
            i += 1
            continue

        # 2-byte Jcc rel32: 0f 80..0f 8f -> 6-byte total
        if b == 0x0F and i + 6 <= n and 0x80 <= code[i + 1] <= 0x8F:
            disp = struct.unpack("<i", code[i + 2:i + 6])[0]
            instr_va = section_va + i
            computed = (instr_va + 6 + disp) & 0xFFFFFFFFFFFFFFFF
            if computed == target:
                yield instr_va, 6, "jcc"
            i += 1
            continue

        i += 1


def _module_for(debugger, addr):
    """Return the ModuleInfo containing `addr`, or None."""
    if not debugger.symbols:
        return None
    return debugger.symbols.get_module_at(addr)


def _read_text_section(debugger, mod):
    """Read the .text (or any executable) section of `mod` from the live
    process. Returns (section_va, bytes) or (None, None) on failure.

    We avoid pulling the file from disk because the live mapping may be
    patched, hooked, or relocated differently. Walking VirtualQueryEx for
    `MEM_COMMIT + EXECUTE` regions inside the module is the most accurate
    source.
    """
    ph = debugger.process_handle
    if not ph:
        return None, None

    # Find the executable region(s) inside the module via VirtualQuery.
    # On most modules .text is a single contiguous region, so we just take
    # the first executable region we encounter and use its full extent.
    addr = mod.base_address
    end = mod.end_address
    while addr < end:
        mbi = virtual_query(ph, addr)
        if not mbi or mbi.RegionSize == 0:
            break
        prot = mbi.Protect
        is_exec = bool(prot & 0xF0)  # PAGE_EXECUTE_* family
        if mbi.State == MEM_COMMIT and is_exec:
            size = min(mbi.RegionSize, end - addr)
            data = read_memory_safe(ph, addr, size)
            if data:
                return addr, data
        addr += mbi.RegionSize
        if addr == 0:
            break
    return None, None


def cmd_xref(debugger, args):
    """Find direct call/jmp xrefs to an address.

    Usage:
        xref <addr|symbol>
        xref <addr|symbol> <module>
        xref <addr|symbol> --all
    """
    if not debugger.process_handle:
        error("No process attached")
        return None

    raw = args.strip()
    if not raw:
        error("Usage: xref <addr|symbol> [module|--all]")
        return None

    parts = raw.split()
    target_str = parts[0]
    target = eval_expr(debugger, target_str)
    if target is None:
        error(f"Cannot resolve: {target_str}")
        return None

    scan_all = False
    explicit_mod = None
    if len(parts) >= 2:
        if parts[1] in ("--all", "-a", "all"):
            scan_all = True
        else:
            explicit_mod = parts[1]

    if scan_all:
        modules = list(debugger.symbols.modules)
    elif explicit_mod:
        match = None
        ml = explicit_mod.lower()
        for mod in debugger.symbols.modules:
            mn = mod.name.lower()
            stem = mn.rsplit(".", 1)[0] if "." in mn else mn
            if mn == ml or stem == ml:
                match = mod
                break
        if not match:
            error(f"Module not found: {explicit_mod}")
            return None
        modules = [match]
    else:
        mod = _module_for(debugger, target)
        if not mod:
            error(
                f"Address {target:#x} doesn't belong to any loaded module — "
                f"specify a module: xref {target_str} <module>"
            )
            return None
        modules = [mod]

    target_sym = (
        debugger.symbols.resolve_address(target) if debugger.symbols else None
    )
    title = f"xref to {target:#x}"
    if target_sym:
        title += f"  <{target_sym}>"
    banner(title)

    total = 0
    for mod in modules:
        section_va, code = _read_text_section(debugger, mod)
        if not code:
            continue
        # Pre-decode each candidate to confirm it's a real instruction.
        # Most byte-sweep false positives die here.
        confirmed = []
        for instr_va, instr_size, kind in _scan_section(
            code, section_va, target
        ):
            offset = instr_va - section_va
            insns = disassemble_at(
                debugger.disassembler,
                bytes(code[offset:offset + instr_size + 1]),
                instr_va,
                count=1,
            )
            if not insns:
                continue
            d_addr, d_size, mnem, op_str = insns[0]
            if d_size != instr_size:
                continue
            # Make sure capstone agrees this is the right kind. We don't
            # require an exact mnem match for Jcc since there are 16 of
            # them — just check it starts with 'j' or 'call'.
            mnem_l = mnem.lower()
            if kind == "call" and mnem_l != "call":
                continue
            if kind in ("jmp", "jcc") and not mnem_l.startswith("j"):
                continue
            confirmed.append((d_addr, mnem, op_str))

        if not confirmed:
            continue

        console.print(
            f"  [bright_cyan]{mod.name}[/]  "
            f"[bright_black]({len(confirmed)} hit"
            f"{'s' if len(confirmed) != 1 else ''})[/]"
        )
        for addr, mnem, op_str in confirmed:
            sym = (
                debugger.symbols.resolve_address(addr)
                if debugger.symbols else None
            )
            line = Text()
            line.append("    ")
            line.append(f"{addr:#x}", style="bright_yellow")
            line.append("  ")
            line.append(f"{mnem:5s}", style="bright_white")
            line.append(" ")
            line.append(op_str, style="white")
            if sym:
                line.append(f"   <{sym}>", style="bright_black")
            console.print(line)
        total += len(confirmed)

    if total == 0:
        info("No direct call/jmp xrefs found")
    else:
        success(f"Found {total} xref{'s' if total != 1 else ''}")
    return None
