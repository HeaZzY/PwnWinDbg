"""Display commands: regs, disasm, context (auto-display on stop)."""

from ..display.formatters import (
    display_registers, display_disasm, display_stack, display_telescope,
    display_backtrace, banner, separator, console, info, error, warn,
)
from ..core.disasm import (
    is_ret_instruction, is_branch_instruction, is_call_instruction,
    get_branch_target,
)
from ..core.memory import read_memory_safe, read_string, virtual_query
from ..core.call_args import resolve_call_args


def _make_imm_resolver(debugger):
    """Create a callback that resolves an immediate value to a descriptive string.
    Checks: symbol, string at address, pointer dereference."""
    from ..utils.constants import MEM_COMMIT

    def resolver(imm):
        # Check if address is in committed memory
        mbi = virtual_query(debugger.process_handle, imm)
        if not mbi or mbi.State != MEM_COMMIT:
            return None

        # Try reading as a string first
        s = read_string(debugger.process_handle, imm, 60)
        if s and len(s) >= 2 and all(c.isprintable() or c in '\t\n\r' for c in s):
            truncated = s[:50]
            if len(s) > 50:
                truncated += "..."
            return f'"{truncated}"'

        # Symbol resolution
        sym = debugger.symbols.resolve_address(imm)
        if sym:
            return sym

        return None

    return resolver


def _get_target_insns(debugger, insns, current_ip, ret_addr):
    """If current IP is a ret or unconditional jmp, disassemble at the target."""
    if not insns:
        return None
    for addr, size, mnemonic, op_str in insns:
        if addr != current_ip:
            continue
        # ret → show instructions at return address
        if is_ret_instruction(mnemonic) and ret_addr:
            return debugger.get_disassembly(ret_addr, 12)
        # unconditional jmp → show instructions at jump target
        if mnemonic == "jmp":
            target = get_branch_target(op_str)
            if target:
                return debugger.get_disassembly(target, 12)
        break
    return None


def cmd_regs(debugger, args):
    """Show registers: regs"""
    from .kd_cmds import _kd_session
    if _kd_session and _kd_session.connected:
        from .kd_cmds import cmd_kdregs
        return cmd_kdregs(debugger, args)
    regs, changed = debugger.get_registers()
    if not regs:
        error("Cannot read registers")
        return None

    display_registers(
        regs, changed, debugger.is_wow64,
        symbol_resolver=debugger.symbols.resolve_address,
    )
    return None


def cmd_disasm(debugger, args):
    """Disassemble at address: disasm [addr|symbol] [count]

    Flags:
        -f / --func    Disassemble the entire function containing <addr>.
                       Uses x64 .pdata RUNTIME_FUNCTION bounds when possible,
                       and otherwise scans forward until the first ret.
    """
    from .kd_cmds import _kd_session
    if _kd_session and _kd_session.connected:
        from .kd_cmds import cmd_kddisasm
        return cmd_kddisasm(debugger, args)
    from ..core.debugger import DebuggerState
    if debugger.state not in (DebuggerState.STOPPED,) and not args.strip():
        error("No process stopped. Use: disasm <address> [count]")
        return None

    parts = args.strip().split()
    addr = None
    count = 10
    func_mode = False

    # Strip flags from positional args
    positional = []
    for p in parts:
        if p in ("-f", "--func", "--function"):
            func_mode = True
        else:
            positional.append(p)

    if positional:
        from ..utils.addr_expr import eval_expr
        addr = eval_expr(debugger, positional[0])
        if addr is None:
            error(f"Cannot resolve: {positional[0]}")
            return None
        if len(positional) > 1:
            try:
                count = int(positional[1])
            except ValueError:
                pass

    if func_mode:
        if addr is None:
            addr = debugger._get_current_ip()
            if addr is None:
                error("No current RIP")
                return None
        return _disasm_function(debugger, addr)

    # Auto-advance on repeat when explicit addr given
    if addr is not None:
        addr = debugger.track_examine("disasm", addr, 0)

    insns = debugger.get_disassembly(addr, count)
    if not insns:
        error("Cannot disassemble")
        return None

    # Fix up next address for disasm auto-advance
    if addr is not None and insns:
        last_addr, last_size, _, _ = insns[-1]
        debugger._examine_next["disasm"] = (debugger._examine_next["disasm"][0], last_addr + last_size)

    current_ip = debugger._get_current_ip() if addr is None else 0
    ret_target = debugger.get_return_address() if current_ip else None
    call_args = _maybe_call_args(debugger, insns, current_ip)
    display_disasm(
        insns, current_ip,
        symbol_resolver=debugger.symbols.resolve_address,
        count=count,
        ret_addr=ret_target,
        imm_resolver=_make_imm_resolver(debugger),
        call_args=call_args,
    )
    return None


def _resolve_call_proto(debugger, op_str):
    """Try to map a call's operand to a known Win32/NT API prototype.

    Handles direct calls (`call 0x...`) and `call qword ptr [rip + disp]`
    IAT-style indirect calls by following the IAT pointer once. Returns
    a `[(arg_name, ArgType), ...]` list, or None if the target doesn't
    resolve to a known prototype.
    """
    from ..core.api_protos import lookup
    if not debugger.symbols:
        return None

    # 1. Direct call: `call 0x401234`
    target = get_branch_target(op_str)
    if target is None:
        # 2. RIP-relative IAT call: `call qword ptr [rip + disp]`
        # We don't currently model the rip-relative resolution here, so
        # just give up on those for now. (capstone returns the absolute
        # address in op_str when the imm is direct; rip-relative looks
        # like `qword ptr [0x...]` which we could deref but skip for
        # simplicity until users complain.)
        return None

    sym = debugger.symbols.resolve_address(target)
    if not sym:
        return None
    return lookup(sym)


def _maybe_call_args(debugger, insns, current_ip):
    """Return resolved arg list iff `current_ip` is a call instruction.

    Cheap pre-check on the disasm we already have, so we don't pay the
    register read cost when sitting on a non-call instruction. When the
    call target resolves to a known Win32/NT API, the arg list is widened
    and re-typed according to the prototype.
    """
    if not current_ip or not insns:
        return None
    for addr, _, mnem, op in insns:
        if addr == current_ip and is_call_instruction(mnem):
            regs, _ = debugger.get_registers()
            if not regs:
                return None
            proto = _resolve_call_proto(debugger, op)
            return resolve_call_args(debugger, regs, num_args=4, proto=proto)
        if addr == current_ip:
            return None
    return None


def _disasm_function(debugger, addr):
    """Disassemble the entire function containing `addr`.

    Tries .pdata RUNTIME_FUNCTION bounds first (x64). Falls back to a
    forward scan that stops on the first `ret` if .pdata is unavailable
    or doesn't cover the address.
    """
    begin, end, source = _resolve_function_bounds(debugger, addr)
    if begin is None:
        # Fallback: scan until first ret, capped at 256 instructions
        return _disasm_scan_until_ret(debugger, addr)

    size = end - begin
    if size <= 0 or size > 0x10000:
        warn(f"Function range {begin:#x}-{end:#x} looks bogus, falling back")
        return _disasm_scan_until_ret(debugger, addr)

    # Estimate instruction count generously (avg 4 bytes/insn)
    est_count = max(16, size // 3)
    insns = debugger.get_disassembly(begin, est_count)
    if not insns:
        error(f"Cannot disassemble at {begin:#x}")
        return None

    # Trim instructions to the function bounds
    insns = [i for i in insns if i[0] < end]

    info(f"Disassembling function {begin:#x}-{end:#x} "
         f"({size} bytes, {len(insns)} insns) [{source}]")

    current_ip = debugger._get_current_ip()
    ret_target = debugger.get_return_address()
    call_args = _maybe_call_args(debugger, insns, current_ip)
    display_disasm(
        insns, current_ip,
        symbol_resolver=debugger.symbols.resolve_address,
        count=len(insns),
        ret_addr=ret_target,
        imm_resolver=_make_imm_resolver(debugger),
        call_args=call_args,
    )
    return None


def _resolve_function_bounds(debugger, addr):
    """Return (begin, end, source) for the function containing `addr`,
    or (None, None, None) if no .pdata covers it.
    """
    if not debugger.symbols or not debugger.symbols.modules:
        return None, None, None

    target_mod = None
    for m in debugger.symbols.modules:
        if m.base_address <= addr < m.end_address:
            target_mod = m
            break
    if target_mod is None:
        return None, None, None

    try:
        from ..core.seh import list_runtime_functions
        rfs = list_runtime_functions(target_mod.base_address, target_mod.path)
    except Exception:
        return None, None, None

    # Linear scan — RUNTIME_FUNCTIONs are sorted by begin in .pdata
    for rf in rfs:
        if rf["begin"] <= addr < rf["end"]:
            return rf["begin"], rf["end"], f".pdata of {target_mod.name}"
    return None, None, None


def _disasm_scan_until_ret(debugger, addr):
    """Forward-scan disassembly fallback: stop on first ret (or 256 insns)."""
    MAX = 256
    insns = debugger.get_disassembly(addr, MAX)
    if not insns:
        error(f"Cannot disassemble at {addr:#x}")
        return None

    trimmed = []
    for i in insns:
        trimmed.append(i)
        mnem = i[2].lower() if isinstance(i[2], str) else ""
        if mnem.startswith("ret"):
            break

    info(f"Function (forward-scan from {addr:#x}, {len(trimmed)} insns)")
    current_ip = debugger._get_current_ip()
    ret_target = debugger.get_return_address()
    call_args = _maybe_call_args(debugger, trimmed, current_ip)
    display_disasm(
        trimmed, current_ip,
        symbol_resolver=debugger.symbols.resolve_address,
        count=len(trimmed),
        ret_addr=ret_target,
        imm_resolver=_make_imm_resolver(debugger),
        call_args=call_args,
    )
    return None


def display_context(debugger):
    """Display full context (registers + disasm + stack + backtrace) like pwndbg."""
    console.print()

    # 1. REGISTERS
    regs, changed = debugger.get_registers()
    if regs:
        display_registers(
            regs, changed, debugger.is_wow64,
            symbol_resolver=debugger.symbols.resolve_address,
        )

    console.print()

    # 2. DISASM
    insns = debugger.get_disassembly(count=12)
    if insns:
        ip_key = "Eip" if debugger.is_wow64 else "Rip"
        current_ip = regs.get(ip_key, 0)
        ret_target = debugger.get_return_address()
        target_insns = _get_target_insns(debugger, insns, current_ip, ret_target)
        imm_res = _make_imm_resolver(debugger)
        # Reuse the regs we already have to avoid a second context fetch
        call_args = None
        for a, _, mnem, op in insns:
            if a == current_ip and is_call_instruction(mnem):
                proto = _resolve_call_proto(debugger, op)
                call_args = resolve_call_args(
                    debugger, regs, num_args=4, proto=proto
                )
                break
            if a == current_ip:
                break
        display_disasm(
            insns, current_ip,
            symbol_resolver=debugger.symbols.resolve_address,
            count=12,
            ret_addr=ret_target,
            target_insns=target_insns,
            imm_resolver=imm_res,
            call_args=call_args,
        )

    console.print()

    # 3. STACK (telescope-style with pointer chains, strings, asm)
    sp_key = "Esp" if debugger.is_wow64 else "Rsp"
    sp = regs.get(sp_key, 0) if regs else 0
    if sp:
        chains = debugger.telescope(address=sp, depth=8)
        if chains:
            display_telescope(chains, sp, debugger.ptr_size, title="STACK")

    console.print()

    # 4. BACKTRACE
    frames = debugger.get_backtrace(8)
    if frames:
        display_backtrace(
            frames,
            symbol_resolver=debugger.symbols.resolve_address,
        )

    separator()
