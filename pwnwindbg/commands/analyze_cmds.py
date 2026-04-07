"""`analyze` — WinDbg-style `!analyze -v` for the most recent stop.

The goal is a single command the user can issue right after a crash to
get an at-a-glance triage of *what* went wrong, *where*, and *why*. We
synthesize the answer from data we already have:

* `debugger.last_stop_info` — captured by `run_until_stop`. Tells us the
  reason (access_violation, exception, …), the faulting RIP, and (for
  AVs) the access type and bad address.
* The active thread context — operand registers at the moment of fault.
* `core.disasm` — the faulting instruction.
* `core.symbols.resolve_address` — symbolicate RIP and any pointer
  operands.
* `core.memory.virtual_query` — classify the bad address (unmapped,
  guard page, NULL-region, stack, heap, image, …).
* `core.seh.backtrace_x64` — short backtrace via .pdata unwinder so the
  user sees the calling chain without typing `bt` separately.

Output sections (always in this order):

    EXCEPTION       — code, name, fault rip, faulting function
    INSTRUCTION     — disasm at rip
    REGISTERS       — operand-relevant registers (decoded from the insn)
    ACCESS          — bad addr (AV only) + region classification + bug class
    BACKTRACE       — first ~10 frames symbolicated

A bug class hint is emitted when we can recognize the pattern:

    * NULL_DEREF       — fault address < 0x10000
    * WILD_POINTER     — uninit-pattern bytes (cdcdcdcd / baadf00d / …)
    * USER_CONTROLLED  — fault matches a cyclic pattern offset
    * STACK_OVERFLOW   — STATUS_STACK_OVERFLOW or fault sits on guard page
    * HEAP_CORRUPTION  — STATUS_HEAP_CORRUPTION or fault inside heap meta
    * EXEC_NX          — execute access into a non-executable region

This is intentionally a *summarizer*, not a debugger script — it never
modifies process state.
"""

from ..core.disasm import disassemble_at
from ..core.memory import read_memory_safe, virtual_query
from ..core.registers import get_context, get_ip
from ..display.common import banner, console
from ..display.formatters import error, info
from ..utils.constants import (
    EXCEPTION_ACCESS_VIOLATION,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS,
    MEM_FREE, MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE,
)
from .catch_cmds import EXCEPTION_NAMES


# Reverse the EXCEPTION_NAMES table for code -> name lookup. We pick
# the *first* canonical name (`av`, `cpp`, `divzero`, …) over the
# secondary aliases (`accessviolation`, `msvc`, …) by tracking which
# code we've already seen.
_PRIMARY_NAMES = {}
for _name, _code in EXCEPTION_NAMES.items():
    if _code not in _PRIMARY_NAMES:
        _PRIMARY_NAMES[_code] = _name


# Common uninit / poison patterns to flag as "wild pointer". Both 32-
# and 64-bit forms (the high half is the same byte for the dword codes
# so the QWORD form just tiles the same DWORD twice).
_POISON_PATTERNS = {
    0xCDCDCDCD: "uninitialized heap (CRT debug)",
    0xCDCDCDCDCDCDCDCD: "uninitialized heap (CRT debug)",
    0xBAADF00D: "uninitialized HeapAlloc",
    0xBAADF00DBAADF00D: "uninitialized HeapAlloc",
    0xFEEEFEEE: "freed heap (CRT debug)",
    0xFEEEFEEEFEEEFEEE: "freed heap (CRT debug)",
    0xABABABAB: "guard bytes after heap alloc",
    0xABABABABABABABAB: "guard bytes after heap alloc",
    0xDDDDDDDD: "freed heap",
    0xDDDDDDDDDDDDDDDD: "freed heap",
    0xCCCCCCCC: "uninit stack (int 3 fill)",
    0xCCCCCCCCCCCCCCCC: "uninit stack (int 3 fill)",
    0xC0C0C0C0: "stale TLS",
    0xC0C0C0C0C0C0C0C0: "stale TLS",
}


def cmd_analyze(debugger, args):
    """Triage the most recent stop. Usage: analyze [-v]"""
    if not debugger.process_handle:
        error("No process attached")
        return None

    stop = getattr(debugger, "last_stop_info", None)
    if stop is None:
        error("No prior stop to analyze")
        info("Run the target until it hits a BP / exception, then re-run `analyze`")
        return None

    verbose = "-v" in args.split() or "verbose" in args.split()

    th = debugger.get_active_thread_handle()
    if th is None:
        error("No active thread")
        return None
    ctx = get_context(th, debugger.is_wow64)
    rip = get_ip(ctx, debugger.is_wow64)

    _print_exception_section(debugger, stop, rip)
    insn = _print_instruction_section(debugger, rip)
    _print_register_section(debugger, ctx, insn)
    if stop.get("reason") == "access_violation":
        _print_access_section(debugger, stop, ctx, insn)
    _print_backtrace_section(debugger, ctx, max_frames=12 if verbose else 8)
    return None


# ---------------------------------------------------------------------------
# EXCEPTION
# ---------------------------------------------------------------------------

def _print_exception_section(debugger, stop, rip):
    banner("EXCEPTION")
    reason = stop.get("reason", "unknown")
    code = stop.get("code") or debugger.last_exception_code
    name = _PRIMARY_NAMES.get(code, None) if code else None

    if reason == "access_violation":
        code = EXCEPTION_ACCESS_VIOLATION
        name = "ACCESS_VIOLATION"
    elif reason == "catch_exception":
        name = stop.get("name") or name
    elif reason == "breakpoint":
        name = "BREAKPOINT"
    elif reason == "single_step":
        name = "SINGLE_STEP"
    elif reason == "watchpoint":
        name = "WATCHPOINT"

    line_code = f"{code:#010x}" if code else "?"
    line_name = name or "(unknown)"
    console.print(f"  reason     : [bright_yellow]{reason}[/]")
    console.print(f"  code       : [bright_cyan]{line_code}[/]  [bright_white]{line_name}[/]")
    console.print(f"  rip        : [bright_blue]{rip:#x}[/]  {_sym_or_blank(debugger, rip)}")
    if "first_chance" in stop:
        chance = "first-chance" if stop["first_chance"] else "second-chance"
        console.print(f"  delivery   : [bright_white]{chance}[/]")
    tid = stop.get("tid") or debugger.active_thread_id
    if tid:
        console.print(f"  thread     : [bright_white]TID={tid}[/]")


# ---------------------------------------------------------------------------
# INSTRUCTION
# ---------------------------------------------------------------------------

def _print_instruction_section(debugger, rip):
    """Disassemble the instruction at RIP. Returns (mnemonic, op_str, size)
    or None if the bytes were unreadable / undecodable."""
    banner("INSTRUCTION")
    code_bytes = read_memory_safe(debugger.process_handle, rip, 16)
    if not code_bytes:
        console.print(f"  [bright_red]<unreadable @ {rip:#x}>[/]")
        return None
    insns = disassemble_at(debugger.disassembler, code_bytes, rip, 1)
    if not insns:
        console.print(f"  [bright_red]<undecodable @ {rip:#x}>[/]")
        return None
    addr, size, mnemonic, op_str = insns[0]
    raw = " ".join(f"{b:02x}" for b in code_bytes[:size])
    # Escape brackets so Rich doesn't treat `[rsp+0x10]` as markup.
    safe_op = op_str.replace("[", r"\[")
    console.print(
        f"  [bright_blue]{addr:#x}[/]  "
        f"[bright_black]{raw:<24}[/] "
        f"[bright_white]{mnemonic} {safe_op}[/]"
    )
    return (mnemonic, op_str, size)


# ---------------------------------------------------------------------------
# REGISTERS
# ---------------------------------------------------------------------------

# x64 register name -> CONTEXT field name. Lowercase for case-insensitive
# matching against capstone op_str tokens.
_X64_REG_FIELD = {
    "rax": "Rax", "rbx": "Rbx", "rcx": "Rcx", "rdx": "Rdx",
    "rsi": "Rsi", "rdi": "Rdi", "rbp": "Rbp", "rsp": "Rsp",
    "r8": "R8",   "r9": "R9",   "r10": "R10", "r11": "R11",
    "r12": "R12", "r13": "R13", "r14": "R14", "r15": "R15",
    "rip": "Rip",
}
_X86_REG_FIELD = {
    "eax": "Eax", "ebx": "Ebx", "ecx": "Ecx", "edx": "Edx",
    "esi": "Esi", "edi": "Edi", "ebp": "Ebp", "esp": "Esp",
    "eip": "Eip",
}
# Sub-register aliases collapse onto their parent (rcx, ecx, cx, cl, ch).
_X64_SUBREGS = {
    "eax": "rax", "ax": "rax", "al": "rax", "ah": "rax",
    "ebx": "rbx", "bx": "rbx", "bl": "rbx", "bh": "rbx",
    "ecx": "rcx", "cx": "rcx", "cl": "rcx", "ch": "rcx",
    "edx": "rdx", "dx": "rdx", "dl": "rdx", "dh": "rdx",
    "esi": "rsi", "si": "rsi", "sil": "rsi",
    "edi": "rdi", "di": "rdi", "dil": "rdi",
    "ebp": "rbp", "bp": "rbp", "bpl": "rbp",
    "esp": "rsp", "sp": "rsp", "spl": "rsp",
    "r8d": "r8", "r8w": "r8", "r8b": "r8",
    "r9d": "r9", "r9w": "r9", "r9b": "r9",
    "r10d": "r10", "r10w": "r10", "r10b": "r10",
    "r11d": "r11", "r11w": "r11", "r11b": "r11",
    "r12d": "r12", "r12w": "r12", "r12b": "r12",
    "r13d": "r13", "r13w": "r13", "r13b": "r13",
    "r14d": "r14", "r14w": "r14", "r14b": "r14",
    "r15d": "r15", "r15w": "r15", "r15b": "r15",
}


def _extract_regs(insn, is_wow64):
    """Pull every register name referenced by the instruction operands.
    `insn` is the (mnemonic, op_str, size) tuple from
    `_print_instruction_section`."""
    if insn is None:
        return []
    op_str = (insn[1] or "").lower()
    found = []
    seen = set()
    field_table = _X86_REG_FIELD if is_wow64 else _X64_REG_FIELD
    # Tokenize: capstone op_str uses ", " between operands, "[ … ]" for
    # mem refs, and "+ - * scale" inside mem refs. We just look for any
    # alpha-numeric run that resolves to a known register.
    import re
    for tok in re.findall(r"[a-z0-9]+", op_str):
        canonical = _X64_SUBREGS.get(tok, tok) if not is_wow64 else tok
        if canonical in field_table and canonical not in seen:
            seen.add(canonical)
            found.append(canonical)
    return found


def _print_register_section(debugger, ctx, insn):
    banner("REGISTERS")
    regs = _extract_regs(insn, debugger.is_wow64)
    if not regs:
        console.print("  [bright_black](no register operands)[/]")
        return
    field_table = _X86_REG_FIELD if debugger.is_wow64 else _X64_REG_FIELD
    for reg in regs:
        field = field_table[reg]
        val = getattr(ctx, field, None)
        if val is None:
            continue
        annotation = _annotate_pointer(debugger, val)
        line = f"  [bright_yellow]{reg:>4s}[/] = [bright_blue]{val:#018x}[/]" \
               if not debugger.is_wow64 \
               else f"  [bright_yellow]{reg:>4s}[/] = [bright_blue]{val:#010x}[/]"
        if annotation:
            line += f"  {annotation}"
        console.print(line)


# ---------------------------------------------------------------------------
# ACCESS  (AV-only)
# ---------------------------------------------------------------------------

_PROT_NAMES = {
    PAGE_NOACCESS: "NOACCESS",
    PAGE_EXECUTE: "X",
    PAGE_EXECUTE_READ: "RX",
    PAGE_EXECUTE_READWRITE: "RWX",
    PAGE_EXECUTE_WRITECOPY: "RXC",
    0x01: "NA",   # PAGE_NOACCESS (alt)
    0x02: "R",    # PAGE_READONLY
    0x04: "RW",   # PAGE_READWRITE
    0x08: "RC",   # PAGE_WRITECOPY
}


def _print_access_section(debugger, stop, ctx, insn):
    banner("ACCESS")
    fault = stop.get("fault_address", 0)
    access = stop.get("access_type", "?")
    console.print(
        f"  fault addr : [bright_blue]{fault:#x}[/]  "
        f"[bright_white]{access.upper()}[/]"
    )

    region = _classify_region(debugger, fault)
    console.print(f"  region     : [bright_white]{region}[/]")

    bug_class, detail = _classify_bug(debugger, fault, access, ctx, insn, stop)
    if bug_class:
        console.print(
            f"  bug class  : [bright_red]{bug_class}[/]"
            + (f"  [bright_black]({detail})[/]" if detail else "")
        )


def _classify_region(debugger, addr):
    """Return a one-line description of the memory region at addr."""
    if addr < 0x10000:
        return "NULL-region (first 64 KiB, never mapped)"
    mbi = virtual_query(debugger.process_handle, addr)
    if mbi is None:
        return "<VirtualQueryEx failed>"
    state = mbi.State
    if state == MEM_FREE:
        return "FREE / unmapped"
    prot = mbi.Protect & 0xFF
    prot_name = _PROT_NAMES.get(prot, f"prot={prot:#x}")
    if mbi.Protect & PAGE_GUARD:
        prot_name += "+GUARD"
    type_name = "image" if mbi.Type == MEM_IMAGE else \
                "mapped" if mbi.Type == MEM_MAPPED else \
                "private" if mbi.Type == MEM_PRIVATE else \
                "?"
    # Try to identify which loaded module if MEM_IMAGE
    mod_hint = ""
    if mbi.Type == MEM_IMAGE and debugger.symbols:
        mod = debugger.symbols.get_module_at(addr)
        if mod:
            mod_hint = f" {mod.name}+{mod.offset_of(addr):#x}"
    return f"{type_name} {prot_name}{mod_hint}"


def _classify_bug(debugger, fault, access, ctx, insn, stop):
    """Heuristic bug-class hint. Returns (label, detail) or (None, None)."""
    code = stop.get("code") or debugger.last_exception_code

    # Stack overflow has its own status code.
    if code == 0xC00000FD:
        return ("STACK_OVERFLOW", "STATUS_STACK_OVERFLOW")

    # Heap corruption.
    if code == 0xC0000374:
        return ("HEAP_CORRUPTION", "STATUS_HEAP_CORRUPTION")

    # NULL deref — most specific, win over EXEC_NX so the user sees the
    # root cause first. WinDbg's !analyze emits NULL_POINTER_{READ,WRITE,
    # EXEC} for this; we follow the same shape.
    if fault < 0x10000:
        verb = access.upper() if access else "DEREF"
        return ("NULL_DEREF", f"NULL_POINTER_{verb} at {fault:#x}")

    # Execute access into a non-X region.
    if access == "execute":
        mbi = virtual_query(debugger.process_handle, fault)
        if mbi:
            prot = mbi.Protect & 0xFF
            if prot not in (PAGE_EXECUTE, PAGE_EXECUTE_READ,
                            PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY):
                return ("EXEC_NX", f"jumped to non-X page (prot={prot:#x})")

    # Wild pointer / uninit pattern check on the fault address itself
    # AND on the bad-input register if we can find one.
    label = _check_poison(fault)
    if label:
        return ("WILD_POINTER", label)

    # Check whether one of the operand registers carries an obvious
    # poison pattern (e.g. mov rcx, [rdi]; rdi=0xfeeefeeefeeefeee).
    regs = _extract_regs(insn, debugger.is_wow64)
    field_table = _X86_REG_FIELD if debugger.is_wow64 else _X64_REG_FIELD
    for reg in regs:
        val = getattr(ctx, field_table.get(reg, ""), None)
        if val is None:
            continue
        label = _check_poison(val)
        if label:
            return ("WILD_POINTER", f"{reg}={val:#x} ({label})")

    # Cyclic-pattern user-controlled detection. Check both the fault
    # address and any operand register against the De Bruijn alphabet
    # (4-byte ASCII windows on x86, 8-byte on x64).
    try:
        from .cyclic_cmds import cyclic_find
        n = 4 if debugger.is_wow64 else 8
        for cand in [fault] + [getattr(ctx, field_table.get(r, ""), None) for r in regs]:
            if cand is None or cand == 0:
                continue
            off = cyclic_find(cand, n)
            if off >= 0:
                return ("USER_CONTROLLED",
                        f"value {cand:#x} matches cyclic offset {off}")
    except Exception:
        pass

    return (None, None)


def _check_poison(value):
    """If `value` matches a known uninit/freed pattern, return its label."""
    if value in _POISON_PATTERNS:
        return _POISON_PATTERNS[value]
    # Sometimes the upper bits get masked, leave the low DWORD intact.
    low = value & 0xFFFFFFFF
    if low in _POISON_PATTERNS and value != 0:
        return _POISON_PATTERNS[low]
    return None


# ---------------------------------------------------------------------------
# BACKTRACE
# ---------------------------------------------------------------------------

def _print_backtrace_section(debugger, ctx, max_frames=8):
    banner("BACKTRACE")
    if debugger.is_wow64:
        console.print("  [bright_black](.pdata unwinder is x64-only — use `bt`)[/]")
        return
    if not debugger.symbols or not debugger.symbols.modules:
        console.print("  [bright_black](no modules loaded)[/]")
        return

    from ..core.seh import backtrace_x64

    def _read(addr, size):
        return read_memory_safe(debugger.process_handle, addr, size)

    rip = ctx.Rip
    rsp = ctx.Rsp
    frames = backtrace_x64(_read, debugger.symbols.modules, rip, rsp, max_frames=max_frames)
    if not frames:
        console.print("  [bright_black](unwind failed)[/]")
        return
    for idx, addr in frames:
        sym = _sym_or_blank(debugger, addr)
        console.print(f"  [bright_white]#{idx:<2d}[/] [bright_blue]{addr:#x}[/]  {sym}")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _sym_or_blank(debugger, addr):
    if not debugger.symbols:
        return ""
    sym = debugger.symbols.resolve_address(addr)
    return f"[bright_green]{sym}[/]" if sym else ""


def _annotate_pointer(debugger, value):
    """Quick one-line annotation for a register value: NULL, region, or
    pointer-into-module."""
    if value is None:
        return ""
    if value == 0:
        return "[bright_red]NULL[/]"
    if value < 0x10000:
        return f"[bright_red]NULL+{value:#x}[/]"
    # Poison?
    label = _check_poison(value)
    if label:
        return f"[bright_red]POISON[/] [bright_black]({label})[/]"
    mbi = virtual_query(debugger.process_handle, value)
    if mbi is None or mbi.State == MEM_FREE:
        return "[bright_red]<unmapped>[/]"
    if debugger.symbols:
        mod = debugger.symbols.get_module_at(value)
        if mod:
            sym = debugger.symbols.resolve_address(value)
            return f"[bright_green]{sym or f'{mod.name}+{mod.offset_of(value):#x}'}[/]"
    prot = mbi.Protect & 0xFF
    prot_name = _PROT_NAMES.get(prot, f"prot={prot:#x}")
    return f"[bright_black]→ {prot_name}[/]"
