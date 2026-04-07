"""Kernel debugging commands: kdconnect, kd-regs, kd-mem, kd-bp, kd-continue, etc."""

import struct

from ..core.kd.kd_session import KdSession
from ..core.kd.transport import KdnetTransport, PipeTransport
from ..core.kd.gdb_transport import GdbSession
from ..core.kd.kd_structs import KD_MACH_AMD64, KD_MACH_I386
from ..display.formatters import (
    info, error, success, warn, console, banner, separator,
    display_registers, display_disasm,
)

from rich.table import Table
from rich.text import Text

# Global KD session — one kernel debug session at a time
_kd_session = None

# Cached kernel base address (persists across lm calls)
_cached_kernel_base = 0
_cached_ps_list_ptr = 0
_cached_modules = None  # list of (dll_base, size, entry_point, base_name, full_name)


def _get_session():
    """Get the active KD session or show an error."""
    global _kd_session
    if _kd_session is None or not _kd_session.connected:
        error("No active kernel debug session. Use: kdconnect <target>")
        return None
    return _kd_session


def is_kd_active():
    """Return True if a kernel debug session is currently connected.

    Used by the dispatcher to route bare commands (regs, c, si, bp, ...)
    to their kernel equivalents when the user is in a KD session.
    """
    return _kd_session is not None and _kd_session.connected


# ---------------------------------------------------------------------------
# kdconnect — connect to kernel debug target
# ---------------------------------------------------------------------------

def cmd_kdconnect(debugger, args):
    """Connect to a kernel debug target.

    Usage:
        kdconnect gdb:<ip>:<port>              — QEMU GDB stub over TCP
        kdconnect net:<ip>:<port> <key>        — KDNET over UDP
        kdconnect pipe:<path>                  — Named pipe (VM)

    Examples:
        kdconnect gdb:54.37.158.126:1234
        kdconnect net:192.168.1.100:50000 1.2.3.4
        kdconnect pipe:\\\\.\\pipe\\vbox_kd
    """
    global _kd_session

    parts = args.strip().split()
    if not parts:
        error("Usage: kdconnect gdb:<ip>:<port>  |  kdconnect net:<ip>:<port> <key>  |  kdconnect pipe:<path>")
        return None

    target_spec = parts[0]

    # Close any existing session
    if _kd_session and _kd_session.connected:
        _kd_session.disconnect()

    if target_spec.startswith("gdb:"):
        # Parse gdb:<ip>:<port>
        gdb_part = target_spec[4:]
        last_colon = gdb_part.rfind(":")
        if last_colon < 0:
            error("Format: gdb:<ip>:<port>")
            return None
        ip = gdb_part[:last_colon]
        try:
            port = int(gdb_part[last_colon + 1:])
        except ValueError:
            error(f"Invalid port: {gdb_part[last_colon + 1:]}")
            return None

        info(f"Connecting via GDB stub to {ip}:{port} ...")
        session = GdbSession(ip, port)
        try:
            ok, msg = session.connect()
        except Exception as e:
            error(f"Connection failed: {e}")
            return None

        if not ok:
            error(f"Connection failed: {msg}")
            return None

        _kd_session = session
        success("Connected via QEMU GDB stub!")

        ver = session.get_version()
        if ver:
            mach_name = {0x8664: "AMD64", 0x014c: "i386"}.get(
                ver["machine"], f"unknown({ver['machine']:#x})"
            )
            info(f"Target: {ver['os_version']}  Machine: {mach_name}  "
                 f"Protocol: {ver['proto']}  64-bit: {ver['is_64bit']}")

        display_kd_context(session)
        return {"reason": "kd_handled"}

    elif target_spec.startswith("net:"):
        net_part = target_spec[4:]
        last_colon = net_part.rfind(":")
        if last_colon < 0:
            error("Format: net:<ip>:<port>")
            return None
        ip = net_part[:last_colon]
        try:
            port = int(net_part[last_colon + 1:])
        except ValueError:
            error(f"Invalid port: {net_part[last_colon + 1:]}")
            return None

        if len(parts) < 2:
            error("KDNET requires a key: kdconnect net:<ip>:<port> <key>")
            return None
        key = parts[1]

        info(f"Connecting via KDNET to {ip}:{port} ...")
        transport = KdnetTransport(ip, port, key)

    elif target_spec.startswith("pipe:"):
        pipe_path = target_spec[5:]
        if not pipe_path:
            error("Format: pipe:<path>  (e.g. pipe:\\\\.\\pipe\\kd_pipe)")
            return None

        server_mode = len(parts) > 1 and parts[1].lower() == "server"
        if server_mode:
            info(f"Creating pipe server: {pipe_path}")
            info("Waiting for VM to connect... (start/reboot the VM now)")
        else:
            info(f"Connecting to pipe: {pipe_path} ...")
        transport = PipeTransport(pipe_path, server=server_mode)

    else:
        error("Unknown transport. Use gdb:, net:, or pipe:")
        return None

    session = KdSession(transport)
    try:
        ok, msg = session.connect()
    except Exception as e:
        error(f"Connection failed: {e}")
        return None

    if not ok:
        error(f"Connection failed: {msg}")
        return None

    _kd_session = session
    success("Connected to kernel debug target!")

    ver = session.get_version()
    if ver:
        mach_name = {KD_MACH_AMD64: "AMD64", KD_MACH_I386: "i386"}.get(
            ver["machine"], f"unknown({ver['machine']:#x})"
        )
        info(f"OS: Windows {ver['os_version']}  Machine: {mach_name}  "
             f"Protocol: {ver['proto']}  64-bit: {ver['is_64bit']}")
        if ver["kernel_base"]:
            info(f"Kernel base: {ver['kernel_base']:#x}")
        if ver["ps_loaded_module_list"]:
            info(f"PsLoadedModuleList: {ver['ps_loaded_module_list']:#x}")
    else:
        warn("Could not query target version info")

    info(f"Stopped at PC: {session.current_pc:#x}  CPU #{session.current_cpu}  "
         f"({session.cpu_count} processors)")
    return None


# ---------------------------------------------------------------------------
# kddisconnect — disconnect
# ---------------------------------------------------------------------------

def cmd_kddisconnect(debugger, args):
    """Disconnect from the kernel debug target."""
    global _kd_session, _cached_kernel_base, _cached_ps_list_ptr, _cached_modules
    session = _get_session()
    if session is None:
        return None
    session.disconnect()
    _kd_session = None
    _cached_kernel_base = 0
    _cached_ps_list_ptr = 0
    _cached_modules = None

    # Clear caches in sibling kd_* command modules
    try:
        from .kd_ps_cmds import invalidate_ps_cache
        invalidate_ps_cache()
    except ImportError:
        pass

    success("Disconnected from kernel debug target")
    return None


# ---------------------------------------------------------------------------
# KD context — previous register cache for change highlighting
# ---------------------------------------------------------------------------

_prev_kd_regs = {}
_prev_reg_annotations = {}  # cached annotations: reg_name -> (kind, label, detail)


def _annotate_register(name, val, modules, fmt, ptr_size, md, read_fn):
    """Build annotation for a single register value. Pure local (no network).

    read_fn(addr, size) must return bytes from the session page cache.
    Returns (kind, label, detail) or None.
    """
    # Check if value is in a known module
    mod_label = ""
    is_code = False
    for dll_base, size, ep, bname, fpath in modules:
        if dll_base <= val < dll_base + size:
            offset = val - dll_base
            mod_label = f"{bname}+{offset:#x}"
            is_code = True
            break

    # Read data at the pointer
    deref = read_fn(val, 128)
    if not deref or len(deref) < ptr_size:
        if mod_label:
            return ("module", mod_label, "")
        return None

    # Code pointers: disassemble first (skip string detection --
    # x86 opcodes often look like valid UTF-16)
    if is_code and md:
        for insn in md.disasm(deref[:16], val):
            asm = f"{insn.mnemonic} {insn.op_str}".strip()
            return ("code", mod_label, asm)
        return ("module", mod_label, "")

    # Data pointers: try string detection (ASCII then UTF-16)
    str_val = ""
    null_pos = deref.find(b'\x00')
    if null_pos > 3:
        try:
            s = deref[:null_pos].decode("ascii")
            if all(c.isprintable() or c in '\t\n\r' for c in s):
                str_val = s[:60]
        except (UnicodeDecodeError, ValueError):
            pass
    if not str_val and len(deref) >= 4:
        for j in range(0, min(len(deref) - 1, 128), 2):
            if deref[j] == 0 and deref[j + 1] == 0:
                if j >= 4:
                    try:
                        s = deref[:j].decode("utf-16-le")
                        if all(c.isprintable() or c in '\t\n\r' for c in s):
                            str_val = s[:60]
                    except (UnicodeDecodeError, ValueError):
                        pass
                break

    if str_val:
        return ("string", mod_label, str_val)

    # Data pointer -- show dereferenced value + follow 1 level
    deref_val = struct.unpack_from(fmt, deref, 0)[0]
    # Check if deref points to a module
    deref_label = ""
    for dll_base, size, ep, bname, fpath in modules:
        if dll_base <= deref_val < dll_base + size:
            deref_label = f"{bname}+{deref_val - dll_base:#x}"
            break
    if mod_label:
        return ("data", mod_label, f"{deref_val:#x}")
    elif deref_label:
        return ("deref_mod", deref_label, f"{deref_val:#x}")
    else:
        return ("data", "", f"{deref_val:#x}")


def _fast_stack_telescope(session, sp, depth):
    """Minimal-RTT stack telescope for context display.

    Uses direct reads (not page cache) to minimize RTTs:
      - 1 read for all stack slot values (64 bytes)
      - 1 read per plausible pointer dereference (128 bytes each)
    Total: ~1 + N_plausible reads instead of page-cache approach
    which fetches 4KB pages (2 reads each with 2KB max_chunk).
    """
    ptr_size = session.ptr_size
    fmt = "<Q" if ptr_size == 8 else "<I"
    max_addr = 0xffff_ffff_ffff_ffff if ptr_size == 8 else 0xffff_ffff

    def _is_ptr(v):
        if v <= 0x1000 or v > max_addr:
            return False
        if ptr_size == 8:
            return (0xFFFF800000000000 <= v) or (0x10000 <= v <= 0x7FFFFFFFFFFF)
        return v >= 0x10000

    # Read all stack slots at once (1 RTT)
    bulk = session.read_virtual(sp, ptr_size * depth)
    if not bulk:
        return []

    chains = []
    for i in range(depth):
        off = i * ptr_size
        if off + ptr_size > len(bulk):
            chains.append((i * ptr_size, [(None, "", "", False, "", "")]))
            continue

        val = struct.unpack_from(fmt, bulk, off)[0]
        if not _is_ptr(val):
            chains.append((i * ptr_size, [(val, "", "", False, "", "")]))
            continue

        # Check module for permission coloring
        perm = ""
        modules = _cached_modules or []
        for dll_base, size, ep, bname, _ in modules:
            if dll_base <= val < dll_base + size:
                perm = "r-x"
                break
        if not perm and ptr_size == 8 and val >= 0xFFFF800000000000:
            perm = "rw-"

        # Direct read for dereference (1 RTT, 128 bytes)
        deref = session.read_virtual(val, 128)
        if not deref or len(deref) < ptr_size:
            chains.append((i * ptr_size, [(val, "", perm, False, "", "")]))
            continue

        # String detection
        is_str = False
        str_val = ""
        null_pos = deref.find(b'\x00')
        if null_pos > 3:
            try:
                s = deref[:null_pos].decode("ascii")
                if all(c.isprintable() or c in '\t\n\r' for c in s):
                    is_str, str_val = True, s[:60]
            except (UnicodeDecodeError, ValueError):
                pass
        if not is_str and len(deref) >= 4:
            for j in range(0, min(len(deref) - 1, 128), 2):
                if deref[j] == 0 and deref[j + 1] == 0:
                    if j >= 4:
                        try:
                            s = deref[:j].decode("utf-16-le")
                            if all(c.isprintable() or c in '\t\n\r' for c in s):
                                is_str, str_val = True, s[:60]
                        except (UnicodeDecodeError, ValueError):
                            pass
                    break

        if is_str:
            chains.append((i * ptr_size, [(val, "", perm, True, str_val, "")]))
            continue

        # Disassembly for code pointers
        asm_str = ""
        if perm and "x" in perm:
            try:
                from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
                mode = CS_MODE_64 if session.is_64bit else CS_MODE_32
                md = Cs(CS_ARCH_X86, mode)
                for insn in md.disasm(deref[:16], val):
                    asm_str = f"{insn.mnemonic} {insn.op_str}".strip()
                    break
            except ImportError:
                pass

        # Build chain: value -> dereferenced value
        deref_val = struct.unpack_from(fmt, deref, 0)[0]
        chain = [(val, "", perm, False, "", asm_str)]
        if _is_ptr(deref_val) and deref_val != val:
            chain.append((deref_val, "", "", False, "", ""))
        else:
            chain.append((deref_val, "", "", False, "", ""))
        chains.append((i * ptr_size, chain))

    return chains


def display_kd_context(session=None):
    """Display full context (regs + disasm + stack) for the active KD session.

    Strategy: ONE combined prefetch for all needed pages, then parse locally.

    New flow (3-5 RTTs total):
      1. Read registers via 'g' command (1 RTT, or cached from wait_break)
      2. Collect ALL needed pages: RIP code, RSP stack, register pointer targets
      3. ONE combined session.prefetch_pages() call (2-4 RTTs merged)
      4. Parse everything from local cache -- zero additional RTTs
    """
    global _prev_kd_regs, _prev_reg_annotations
    if session is None:
        session = _get_session()
    if session is None or not session.stopped:
        return

    from .memory_cmds import _kd_telescope
    from ..display.formatters import display_telescope
    from ..display.common import (
        banner, SYMBOL_COLOR, STRING_COLOR, CHAIN_ARROW_COLOR,
        REG_COLOR_IP, REG_COLOR_SP, REG_COLOR_BP, REG_COLOR_FLAGS,
        REG_COLOR_GENERAL, REG_COLOR_CHANGED, REG_COLOR_SEG,
    )
    from ..core.registers import REGS_64_GENERAL, REGS_64_FRAME

    has_page_cache = hasattr(session, 'prefetch_pages')

    # ===== PHASE 1: REGISTERS (1 RTT, or cached from wait_break) =====

    regs = session.get_context()
    rip = session.current_pc
    sp_key = "Rsp" if session.is_64bit else "Esp"
    sp = regs.get(sp_key, 0) if regs else 0
    ptr_size = session.ptr_size

    # ===== PHASE 2: FETCH DATA WITH MINIMAL RTTs =====
    # With 2KB max reads (QEMU PacketSize=4096), page-based prefetch
    # wastes RTTs (each 4KB page = 2 reads). Instead, do targeted reads:
    # - Code bytes: 1 read (180 bytes, or 0 if cached)
    # - Stack slots: 1 read (64 bytes)
    # - Changed register targets: 1 read each (128 bytes)
    # Total: ~3-8 RTTs instead of ~14 RTTs from page prefetch.

    if has_page_cache and regs:
        # Mark code pages for persistent caching across steps
        if rip:
            code_pages = set()
            for off in range(0, 12 * 15, 0x1000):
                code_pages.add((rip + off) & ~0xFFF)
            session.mark_code_pages(code_pages)

            # Check if code is already cached (0 RTTs after first step)
            rip_page = rip & ~0xFFF
            if rip_page in session._page_cache:
                code_bytes = session.read_cached(rip, 12 * 15)
            else:
                # First time: prefetch code pages, then read from cache
                session.prefetch_pages(code_pages)
                code_bytes = session.read_cached(rip, 12 * 15)
        else:
            code_bytes = b""

        # Stack: fast inline telescope (fewer RTTs than full _kd_telescope)
        # Direct reads avoid 4KB page fetches (2 RTTs each). Instead:
        # 1 read for 64 bytes of stack data + 1 read per plausible deref
        stack_chains = _fast_stack_telescope(session, sp, 8) if sp else []

        # Register annotations: only read changed values
        modules = _cached_modules or []
        reg_ptrs = {}
        reg_annotations = {}
        fmt = "<Q" if ptr_size == 8 else "<I"
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
            mode = CS_MODE_64 if session.is_64bit else CS_MODE_32
            md = Cs(CS_ARCH_X86, mode)
        except ImportError:
            md = None

        for name in list(REGS_64_GENERAL) + list(REGS_64_FRAME):
            if name not in regs or name in ("EFlags",):
                continue
            val = regs[name]
            if val > 0x1000 and (val >= 0xFFFF800000000000 or val <= 0x7FFFFFFFFFFF):
                reg_ptrs[name] = val

        for name, val in reg_ptrs.items():
            # Reuse cached annotation if register value didn't change
            if (val == _prev_kd_regs.get(name)
                    and name in _prev_reg_annotations):
                reg_annotations[name] = _prev_reg_annotations[name]
                continue
            ann = _annotate_register(
                name, val, modules, fmt, ptr_size, md,
                session.read_cached,
            )
            if ann:
                reg_annotations[name] = ann

        _prev_reg_annotations = dict(reg_annotations)

    else:
        # Fallback for sessions without page cache (KdSession, etc.)
        code_bytes = session.read_virtual(rip, 12 * 15) if rip else b""
        stack_chains = _kd_telescope(session, sp, 8, chain_depth=1) if sp else []

        # Build annotations the old way (individual reads)
        reg_annotations = {}
        if regs:
            fmt = "<Q" if ptr_size == 8 else "<I"
            modules = _cached_modules or []

            reg_ptrs = {}
            for name in list(REGS_64_GENERAL) + list(REGS_64_FRAME):
                if name not in regs or name in ("EFlags",):
                    continue
                val = regs[name]
                if val > 0x1000 and (val >= 0xFFFF800000000000 or val <= 0x7FFFFFFFFFFF):
                    reg_ptrs[name] = val

            # Batch-read all register pointer targets (pages)
            pages_needed = set()
            for val in reg_ptrs.values():
                pages_needed.add(val & ~0xFFF)
                pages_needed.add((val + 127) & ~0xFFF)

            page_cache = {}
            pages_sorted = sorted(pages_needed)
            i = 0
            while i < len(pages_sorted):
                start = pages_sorted[i]
                end = start + 0x1000
                while i + 1 < len(pages_sorted) and pages_sorted[i + 1] == end and end - start < 0x10000:
                    i += 1
                    end = pages_sorted[i] + 0x1000
                data = session.read_virtual(start, end - start)
                if data:
                    for off in range(0, len(data), 0x1000):
                        pg = start + off
                        if off + 0x1000 <= len(data):
                            page_cache[pg] = data[off:off + 0x1000]
                i += 1

            def _pcache_read(addr, sz):
                result = b""
                cur, rem = addr, sz
                while rem > 0:
                    pg = cur & ~0xFFF
                    d = page_cache.get(pg)
                    if not d:
                        break
                    off = cur - pg
                    n = min(rem, len(d) - off)
                    if n <= 0:
                        break
                    result += d[off:off + n]
                    cur += n
                    rem -= n
                return result if len(result) >= sz else None

            try:
                from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
                mode = CS_MODE_64 if session.is_64bit else CS_MODE_32
                md = Cs(CS_ARCH_X86, mode)
            except ImportError:
                md = None

            for name, val in reg_ptrs.items():
                ann = _annotate_register(
                    name, val, modules, fmt, ptr_size, md,
                    _pcache_read,
                )
                if ann:
                    reg_annotations[name] = ann

    # ===== PHASE 2: DISPLAY EVERYTHING AT ONCE =====

    console.print()

    # 2a. REGISTERS with annotations
    if regs:
        changed = {k for k in regs if regs[k] != _prev_kd_regs.get(k)}
        _prev_kd_regs = dict(regs)

        banner("REGISTERS")
        ptr_fmt = "0x{:016x}" if session.is_64bit else "0x{:08x}"

        def _reg_color(name, is_changed):
            if is_changed:
                return REG_COLOR_CHANGED
            lo = name.lower()
            if lo in ("rip", "eip"):
                return REG_COLOR_IP
            if lo in ("rsp", "esp"):
                return REG_COLOR_SP
            if lo in ("rbp", "ebp"):
                return REG_COLOR_BP
            return REG_COLOR_GENERAL

        for name in list(REGS_64_GENERAL) + list(REGS_64_FRAME):
            if name not in regs:
                continue
            val = regs[name]
            color = _reg_color(name, name in changed)

            text = Text()
            text.append(f" {name:6s}", style=color)
            text.append(" ")
            text.append(ptr_fmt.format(val), style=color)

            # Annotation
            ann = reg_annotations.get(name)
            if ann:
                kind, label, detail = ann
                if kind == "code":
                    if label:
                        text.append(f" ({label})", style=SYMBOL_COLOR)
                    if detail:
                        text.append(f" \u25c2 {detail}", style="bright_yellow")
                elif kind == "module":
                    if label:
                        text.append(f" ({label})", style=SYMBOL_COLOR)
                elif kind == "string":
                    if label:
                        text.append(f" ({label})", style=SYMBOL_COLOR)
                    text.append(f' "{detail}"', style=STRING_COLOR)
                elif kind == "data":
                    if label:
                        text.append(f" ({label})", style=SYMBOL_COLOR)
                    if detail:
                        text.append(f" \u2014\u2014\u25b8 ", style=CHAIN_ARROW_COLOR)
                        text.append(detail, style="white")
                elif kind == "deref_mod":
                    text.append(f" \u2014\u2014\u25b8 ", style=CHAIN_ARROW_COLOR)
                    text.append(f"{detail} ({label})", style=SYMBOL_COLOR)

            console.print(text)

        # EFlags
        if "EFlags" in regs:
            eflags = regs["EFlags"]
            color = _reg_color("EFlags", "EFlags" in changed)
            flag_defs = [
                (0, "CF"), (2, "PF"), (4, "AF"), (6, "ZF"), (7, "SF"),
                (8, "TF"), (9, "IF"), (10, "DF"), (11, "OF"),
            ]
            flags = [n for bit, n in flag_defs if eflags & (1 << bit)]
            text = Text()
            text.append(f" {'EFlags':6s}", style=color)
            text.append(f" 0x{eflags:08x}", style=color)
            text.append(f"  [{' '.join(flags)}]", style="bright_black")
            console.print(text)

        # Segments
        seg_names = ["SegCs", "SegDs", "SegEs", "SegFs", "SegGs", "SegSs"]
        seg_vals = [f"{s[3:].lower()}={regs[s]:#06x}" for s in seg_names if s in regs]
        if seg_vals:
            text = Text()
            text.append("  " + "  ".join(seg_vals), style=REG_COLOR_SEG)
            console.print(text)

    console.print()

    # 2b. DISASSEMBLY
    if code_bytes:
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
            mode = CS_MODE_64 if session.is_64bit else CS_MODE_32
            md2 = Cs(CS_ARCH_X86, mode)
            insns = []
            for insn in md2.disasm(code_bytes, rip):
                insns.append((insn.address, insn.size, insn.mnemonic, insn.op_str))
                if len(insns) >= 12:
                    break
            if insns:
                display_disasm(insns, rip, count=12)
        except ImportError:
            error("capstone required for disassembly")

    console.print()

    # 2c. STACK
    if stack_chains:
        display_telescope(stack_chains, sp, session.ptr_size, title="STACK")


# ---------------------------------------------------------------------------
# kdregs — show kernel registers
# ---------------------------------------------------------------------------

def cmd_kdregs(debugger, args):
    """Show kernel-mode registers of the current CPU."""
    session = _get_session()
    if session is None:
        return None
    if not session.stopped:
        error("Target is running. Break first.")
        return None

    regs = session.get_context()
    if not regs:
        error("Failed to read context")
        return None

    changed = {k for k in regs if regs[k] != _prev_kd_regs.get(k)}
    display_registers(regs, changed, is_wow64=not session.is_64bit)
    return None


# ---------------------------------------------------------------------------
# kdmem — read kernel memory
# ---------------------------------------------------------------------------

def cmd_kdmem(debugger, args):
    """Read kernel virtual memory.

    Usage: kdmem <address|module+offset> [size]
    Default size: 128 bytes (hexdump format).
    """
    session = _get_session()
    if session is None:
        return None

    parts = args.strip().split()
    if not parts:
        error("Usage: kdmem <address> [size]")
        return None

    addr = _kd_eval_expr(parts[0], session)
    if addr is None:
        error(f"Cannot resolve: {parts[0]}")
        return None

    size = 128
    if len(parts) > 1:
        try:
            size = int(parts[1], 0)
        except ValueError:
            error(f"Invalid size: {parts[1]}")
            return None

    data = session.read_virtual(addr, size)
    if not data:
        error(f"Failed to read {size} bytes at {addr:#x}")
        return None

    banner(f"Kernel memory at {addr:#x}  ({len(data)} bytes)")
    _hexdump(addr, data)
    return None


def _hexdump(addr, data):
    """Display a classic hexdump."""
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        hex_parts = []
        for i, b in enumerate(chunk):
            if i == 8:
                hex_parts.append("")
            hex_parts.append(f"{b:02x}")
        hex_str = " ".join(hex_parts)

        missing = 16 - len(chunk)
        if missing:
            pad = missing * 3
            if len(chunk) <= 8:
                pad += 1
            hex_str += " " * pad

        ascii_str = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in chunk)
        line_addr = addr + offset

        text = Text()
        text.append(f"  {line_addr:016x}  ", style="bright_cyan")
        text.append(hex_str, style="white")
        text.append(f"  |{ascii_str}|", style="bright_green")
        console.print(text)


# ---------------------------------------------------------------------------
# kdwrite — write kernel memory
# ---------------------------------------------------------------------------

def cmd_kdwrite(debugger, args):
    """Write to kernel virtual memory.

    Usage: kdwrite <address> <hex_bytes>
    Example: kdwrite 0xfffff80012345000 cc
    """
    session = _get_session()
    if session is None:
        return None

    parts = args.strip().split(None, 1)
    if len(parts) < 2:
        error("Usage: kdwrite <address> <hex_bytes>")
        return None

    addr = _kd_eval_expr(parts[0], session)
    if addr is None:
        error(f"Cannot resolve: {parts[0]}")
        return None

    hex_str = parts[1].replace(" ", "")
    try:
        data = bytes.fromhex(hex_str)
    except ValueError:
        error(f"Invalid hex: {parts[1]}")
        return None

    if session.write_virtual(addr, data):
        success(f"Wrote {len(data)} bytes at {addr:#x}")
    else:
        error(f"Failed to write at {addr:#x}")
    return None


# ---------------------------------------------------------------------------
# Kernel address expression evaluator
# ---------------------------------------------------------------------------

def _kd_eval_expr(expr_str, session=None):
    """Evaluate a kernel address expression.

    Supports:
      0xfffff80412340000          — hex literal
      HIDCLASS.SYS+0x10          — module + offset
      HIDCLASS+0x10              — module name (with or without .sys)
      ntoskrnl+0x1000            — module + offset
      *0xaddr                    — strip leading * (GDB compat)
      rip, rsp, rax, ...         — register names
      <expr> + <offset>          — addition
      <expr> - <offset>          — subtraction

    Returns int address or None on failure.
    """
    if session is None:
        session = _get_session()
    if session is None:
        return None

    s = expr_str.strip()
    # Strip leading * (GDB-style dereference marker for bp addresses)
    if s.startswith("*"):
        s = s[1:].strip()

    # Split on + or - for offset arithmetic
    import re
    parts = re.split(r'(?=[+-])', s, maxsplit=1)
    base_str = parts[0].strip()
    offset = 0
    if len(parts) > 1:
        off_str = parts[1].strip()  # e.g. "+0x10" or "-0x10"
        try:
            offset = int(off_str, 0)  # handles "+0x10" → 16, "-0x10" → -16
        except ValueError:
            # Try without sign prefix
            sign = -1 if off_str.startswith('-') else 1
            raw = off_str.lstrip('+-').strip()
            try:
                offset = sign * int(raw, 16)
            except ValueError:
                pass

    # Try as hex/decimal literal
    try:
        return int(base_str, 0) + offset
    except ValueError:
        pass

    # Try as register name
    if session and session._context_regs:
        reg_map = {
            "rax": "Rax", "rbx": "Rbx", "rcx": "Rcx", "rdx": "Rdx",
            "rsi": "Rsi", "rdi": "Rdi", "rbp": "Rbp", "rsp": "Rsp",
            "r8": "R8", "r9": "R9", "r10": "R10", "r11": "R11",
            "r12": "R12", "r13": "R13", "r14": "R14", "r15": "R15",
            "rip": "Rip",
        }
        kd_name = reg_map.get(base_str.lower())
        if kd_name and kd_name in session._context_regs:
            return session._context_regs[kd_name] + offset

    # Try as module name (from cached module list)
    if _cached_modules:
        base_lower = base_str.lower()
        # WinDbg-style aliases for ntoskrnl
        if base_lower in ("nt", "ntkrnl", "ntkrnlmp", "ntkrnlpa", "ntkrpamp"):
            base_lower = "ntoskrnl"
        for dll_base, size, ep, bname, fpath in _cached_modules:
            # Match by base name (with or without extension)
            bname_lower = bname.lower()
            if base_lower == bname_lower or base_lower == bname_lower.rsplit('.', 1)[0]:
                return dll_base + offset
            # Match by full path
            if fpath and base_lower == fpath.lower():
                return dll_base + offset

    return None


# ---------------------------------------------------------------------------
# kdbp / kdbpd — kernel breakpoints
# ---------------------------------------------------------------------------

_kd_breakpoints = {}  # addr -> handle


def cmd_kdbp(debugger, args):
    """Set a kernel breakpoint.

    Usage: kdbp <address|module+offset|register+offset>
    Examples: kdbp 0xfffff80412340000
              kdbp HIDCLASS.SYS+0x10
              kdbp ntoskrnl+0x1000
    """
    session = _get_session()
    if session is None:
        return None

    expr = args.strip()
    if not expr:
        error("Usage: kdbp <address|module+offset>")
        return None

    addr = _kd_eval_expr(expr, session)
    if addr is None:
        error(f"Cannot resolve: {expr}")
        return None

    handle = session.set_breakpoint(addr)
    if handle >= 0:
        _kd_breakpoints[addr] = handle
        entry = session._breakpoints.get(handle)
        bp_type = "hardware" if entry and entry[1] else "software"
        success(f"Kernel breakpoint set at {addr:#x} ({bp_type}, handle={handle})")
    else:
        error(f"Failed to set breakpoint at {addr:#x}")
    return None


def cmd_kdbpd(debugger, args):
    """Remove a kernel breakpoint.

    Usage: kdbpd <address|module+offset>
    """
    session = _get_session()
    if session is None:
        return None

    expr = args.strip()
    if not expr:
        error("Usage: kdbpd <address|module+offset>")
        return None

    addr = _kd_eval_expr(expr, session)
    if addr is None:
        error(f"Cannot resolve: {expr}")
        return None

    if addr not in _kd_breakpoints:
        error(f"No breakpoint at {addr:#x}")
        return None

    handle = _kd_breakpoints[addr]
    if session.remove_breakpoint(handle):
        del _kd_breakpoints[addr]
        success(f"Breakpoint removed at {addr:#x}")
    else:
        error(f"Failed to remove breakpoint at {addr:#x}")
    return None


# ---------------------------------------------------------------------------
# kdcontinue / kdstep — execution control
# ---------------------------------------------------------------------------

def cmd_kdcontinue(debugger, args):
    """Continue kernel execution.

    Usage: kdc
    """
    session = _get_session()
    if session is None:
        return None

    info("Continuing... (Ctrl+C to break)")
    session.do_continue()

    try:
        result = session.wait_break(timeout=120.0)
    except KeyboardInterrupt:
        # Ctrl+C — send break to halt the target
        info("Interrupting target...")
        session.do_break()
        result = session.wait_break(timeout=10.0)

    if result is None:
        warn("Timeout waiting for target to break")
        return None

    display_kd_context(session)
    return {"reason": "kd_handled"}


def cmd_kdstep(debugger, args):
    """Single-step one instruction in kernel.

    Usage: kdsi
    """
    session = _get_session()
    if session is None:
        return None

    session.do_step()
    result = session.wait_break(timeout=30.0)
    if result is None:
        warn("Timeout waiting for single-step break")
        return None

    display_kd_context(session)
    return {"reason": "kd_handled"}


def cmd_kdstepover(debugger, args):
    """Step over one instruction in kernel (skips calls).

    Usage: kdni
    If current instruction is a call, sets a temp breakpoint on the
    next instruction and continues. Otherwise, single-steps.
    """
    session = _get_session()
    if session is None:
        return None

    rip = session.current_pc
    code = session.read_virtual(rip, 16)
    is_call = False
    next_addr = 0

    if code:
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
            mode = CS_MODE_64 if session.is_64bit else CS_MODE_32
            md = Cs(CS_ARCH_X86, mode)
            for insn in md.disasm(code, rip):
                if insn.mnemonic == "call":
                    is_call = True
                    next_addr = rip + insn.size
                break
        except ImportError:
            pass

    if is_call and next_addr:
        # Set temp breakpoint after the call, continue, then remove it
        resp = session._transport.command(f"Z0,{next_addr:x},1")
        session.do_continue()
        result = session.wait_break(timeout=60.0)
        session._transport.command(f"z0,{next_addr:x},1")
    else:
        session.do_step()
        result = session.wait_break(timeout=30.0)

    if result is None:
        warn("Timeout waiting for step-over break")
        return None

    display_kd_context(session)
    return {"reason": "kd_handled"}


# ---------------------------------------------------------------------------
# kdbreak — interrupt running kernel
# ---------------------------------------------------------------------------

def cmd_kdbreak(debugger, args):
    """Send break-in to interrupt the running kernel."""
    session = _get_session()
    if session is None:
        return None

    info("Sending break-in...")
    session.do_break()
    result = session.wait_break(timeout=30.0)
    if result is None:
        warn("Timeout — target may not have responded to break")
        return None

    display_kd_context(session)
    return {"reason": "kd_handled"}


# ---------------------------------------------------------------------------
# kddisasm — disassemble kernel code
# ---------------------------------------------------------------------------

def cmd_kddisasm(debugger, args):
    """Disassemble kernel code at address.

    Usage: kddisasm [address] [count]
    Default: current PC, 16 instructions.
    """
    session = _get_session()
    if session is None:
        return None

    parts = args.strip().split()
    addr = session.current_pc
    count = 16

    if parts:
        resolved = _kd_eval_expr(parts[0], session)
        if resolved is not None:
            addr = resolved
        else:
            error(f"Cannot resolve: {parts[0]}")
            return None
    if len(parts) > 1:
        try:
            count = int(parts[1], 0)
        except ValueError:
            pass

    # Read enough bytes for disassembly
    code = session.read_virtual(addr, count * 15)
    if not code:
        error(f"Cannot read memory at {addr:#x}")
        return None

    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
        mode = CS_MODE_64 if session.is_64bit else CS_MODE_32
        md = Cs(CS_ARCH_X86, mode)
        banner(f"Kernel disassembly at {addr:#x}")
        n = 0
        for insn in md.disasm(code, addr):
            prefix = " ► " if insn.address == session.current_pc else "   "
            text = Text()
            text.append(prefix, style="bold bright_red" if prefix.strip() else "")
            text.append(f"{insn.address:#018x}  ", style="bright_cyan")
            raw_hex = insn.bytes.hex()
            text.append(f"{raw_hex:24s} ", style="bright_black")
            text.append(f"{insn.mnemonic:8s}", style="bold bright_white")
            text.append(f" {insn.op_str}", style="white")
            console.print(text)
            n += 1
            if n >= count:
                break
    except ImportError:
        error("capstone is required for disassembly")
    return None


# ---------------------------------------------------------------------------
# kdversion — show target version info
# ---------------------------------------------------------------------------

def cmd_kdversion(debugger, args):
    """Show kernel debug target version info."""
    session = _get_session()
    if session is None:
        return None

    ver = session.get_version()
    if not ver:
        error("Failed to query version")
        return None

    banner("KERNEL TARGET INFO")
    mach = {KD_MACH_AMD64: "AMD64", KD_MACH_I386: "i386"}.get(
        ver["machine"], f"unknown ({ver['machine']:#x})"
    )

    tbl = Table(show_header=False, border_style="cyan")
    tbl.add_column("Field", style="bold")
    tbl.add_column("Value")
    tbl.add_row("OS Version", f"Windows {ver['os_version']}")
    tbl.add_row("Machine", mach)
    tbl.add_row("64-bit", str(ver["is_64bit"]))
    tbl.add_row("Protocol", ver["proto"])
    tbl.add_row("Kernel Base", f"{ver['kernel_base']:#x}")
    tbl.add_row("PsLoadedModuleList", f"{ver['ps_loaded_module_list']:#x}")
    tbl.add_row("CPUs", str(session.cpu_count))
    tbl.add_row("Current CPU", str(session.current_cpu))
    tbl.add_row("Current PC", f"{session.current_pc:#x}")
    console.print(tbl)
    return None


# ---------------------------------------------------------------------------
# lm / kdlm — list loaded kernel modules
# ---------------------------------------------------------------------------

def _pe_export_name(session, addr):
    """Read the export DLL name of a PE image at addr. Returns str or ''."""
    lfanew_data = session.read_virtual(addr + 0x3C, 4)
    if not lfanew_data:
        return ""
    lfanew = struct.unpack_from("<I", lfanew_data, 0)[0]
    exp_data = session.read_virtual(addr + lfanew + 0x88, 8)
    if not exp_data:
        return ""
    exp_rva = struct.unpack_from("<I", exp_data, 0)[0]
    if not exp_rva:
        return ""
    exp_dir = session.read_virtual(addr + exp_rva, 16)
    if not exp_dir or len(exp_dir) < 16:
        return ""
    name_rva = struct.unpack_from("<I", exp_dir, 12)[0]
    if not name_rva:
        return ""
    name_data = session.read_virtual(addr + name_rva, 64)
    if not name_data:
        return ""
    return name_data.split(b'\x00')[0].decode("ascii", errors="replace")


def _probe_mz_pe(session, addr):
    """Quick MZ + PE signature check at addr (2 RTTs max)."""
    mz = session.read_virtual(addr, 0x40)
    if not mz or mz[:2] != b'MZ':
        return False
    lfanew = struct.unpack_from("<I", mz, 0x3C)[0]
    if not (0 < lfanew < 0x1000):
        return False
    pe_sig = session.read_virtual(addr + lfanew, 4)
    return pe_sig == b'PE\x00\x00'


def _extract_isr(entry_data, offset=0):
    """Extract ISR address from a 16-byte IDT entry."""
    lo = struct.unpack_from("<H", entry_data, offset)[0]
    mid = struct.unpack_from("<H", entry_data, offset + 6)[0]
    hi = struct.unpack_from("<I", entry_data, offset + 8)[0]
    return lo | (mid << 16) | (hi << 32)


def _find_kernel_base_via_idt(session):
    """Find ntoskrnl via IDT -> ISR addresses -> pipelined MZ scan.

    1. Read IDT base from QEMU monitor (1 RTT)
    2. Bulk-read 128 IDT entries = 2KB (1 RTT) to find lowest ISR
    3. Pipelined backward MZ scan from lowest ISR (~0.5s for 2MB)
    """
    if not hasattr(session, 'read_idt_base'):
        return 0

    idt_base = session.read_idt_base()
    if not idt_base or idt_base < 0xFFFF800000000000:
        return 0

    idt_data = session.read_virtual(idt_base, 2048)
    if not idt_data or len(idt_data) < 16:
        return 0

    min_isr = 0xFFFFFFFFFFFFFFFF
    for i in range(0, min(len(idt_data), 2048) - 15, 16):
        isr = _extract_isr(idt_data, i)
        if 0xFFFF800000000000 <= isr < min_isr:
            min_isr = isr

    if min_isr == 0xFFFFFFFFFFFFFFFF:
        return 0

    info(f"IDT min ISR: {min_isr:#x}")
    page = min_isr & ~0xFFF
    return _pipelined_mz_scan(session, page, -1, 0x2000)  # 32MB back


def _pipelined_mz_scan(session, start_page, direction, max_pages):
    """Scan for MZ headers using pipelined reads (50x faster than sequential).

    Sends batches of 2-byte reads via pipeline, checks for MZ, then
    verifies PE + export name on hits.

    Args:
        start_page: page-aligned start address
        direction: -1 (backward) or +1 (forward)
        max_pages: maximum pages to scan
    Returns: kernel base address or 0
    """
    BATCH = 200  # pages per pipeline batch
    has_pipeline = hasattr(session, 'batch_probe_mz')

    for batch_start in range(0, max_pages, BATCH):
        batch_end = min(batch_start + BATCH, max_pages)
        addrs = []
        for i in range(batch_start, batch_end):
            addr = start_page + direction * i * 0x1000
            if addr <= 0:
                continue
            addrs.append(addr)
        if not addrs:
            break

        if has_pipeline:
            # Pipeline: send all 2-byte reads at once (~45ms per 200 pages)
            hit = session.batch_probe_mz(addrs)
            if hit and _probe_mz_pe(session, hit):
                name = _pe_export_name(session, hit)
                if "ntoskrnl" in name.lower():
                    return hit
        else:
            # Fallback: sequential
            for addr in addrs:
                mz = session.read_virtual(addr, 2)
                if mz == b'MZ' and _probe_mz_pe(session, addr):
                    name = _pe_export_name(session, addr)
                    if "ntoskrnl" in name.lower():
                        return addr
    return 0


def _find_kernel_base(session):
    """Find ntoskrnl base address.

    Uses pipelined MZ scanning (~50x faster than sequential).
    Strategy:
      1. IDT -> min ISR -> pipelined backward scan (~0.5s)
      2. Pipelined scan from RIP in both directions (fallback)
    """
    global _cached_kernel_base
    if _cached_kernel_base:
        return _cached_kernel_base

    # Strategy 1: IDT-based — get min ISR, scan backwards
    addr = _find_kernel_base_via_idt(session)
    if addr:
        _cached_kernel_base = addr
        return addr

    # Strategy 2: pipelined scan from RIP in both directions
    rip_page = session.current_pc & ~0xFFF

    # Backward first (most common — kernel base is usually below RIP)
    addr = _pipelined_mz_scan(session, rip_page, -1, 0x2000)  # 32MB back
    if addr:
        _cached_kernel_base = addr
        return addr

    # Forward
    addr = _pipelined_mz_scan(session, rip_page, +1, 0x2000)  # 32MB forward
    if addr:
        _cached_kernel_base = addr
        return addr

    return 0

def _find_export(session, base, name_to_find):
    """Find an exported symbol RVA by name in a PE at base.

    Optimized for low-RTT: bulk-reads the entire name string region
    so the binary search runs locally with zero additional RTTs.

    RTT breakdown:
      - 1 RTT: PE header (lfanew + export dir RVA)
      - 1 RTT: export directory
      - 1-3 RTTs: name pointers + ordinals + function addresses (bulk)
      - 1-3 RTTs: entire name string region (bulk, typically 50-200KB)
      - 0 RTTs: binary search (pure local)
    Total: ~4-8 RTTs instead of 4 + O(log n) = ~16 RTTs.
    """
    lfanew_data = session.read_virtual(base + 0x3C, 4)
    if not lfanew_data:
        return 0
    lfanew = struct.unpack_from("<I", lfanew_data, 0)[0]

    # Export dir RVA at PE + 0x88 (PE64 optional header data_dir[0])
    exp_dir_data = session.read_virtual(base + lfanew + 0x88, 8)
    if not exp_dir_data:
        return 0
    exp_rva = struct.unpack_from("<I", exp_dir_data, 0)[0]
    if exp_rva == 0:
        return 0

    exp_dir = session.read_virtual(base + exp_rva, 40)
    if not exp_dir or len(exp_dir) < 40:
        return 0

    num_functions = struct.unpack_from("<I", exp_dir, 20)[0]
    num_names = struct.unpack_from("<I", exp_dir, 24)[0]
    addr_table_rva = struct.unpack_from("<I", exp_dir, 28)[0]
    name_ptr_rva = struct.unpack_from("<I", exp_dir, 32)[0]
    ordinal_table_rva = struct.unpack_from("<I", exp_dir, 36)[0]
    if num_names == 0:
        return 0

    # Bulk read name ptrs, ordinals, function addrs — pipelined
    use_pipeline = hasattr(session, 'read_virtual_pipelined')
    _rv = session.read_virtual_pipelined if use_pipeline else session.read_virtual
    name_ptrs = _rv(base + name_ptr_rva, num_names * 4)
    ordinals = _rv(base + ordinal_table_rva, num_names * 2)
    func_addrs = _rv(base + addr_table_rva, num_functions * 4)
    if not name_ptrs or not ordinals or not func_addrs:
        return 0

    # Bulk-read the ENTIRE name string region at once (pipelined).
    min_rva = 0xFFFFFFFF
    max_rva = 0
    for i in range(num_names):
        nrva = struct.unpack_from("<I", name_ptrs, i * 4)[0]
        if nrva < min_rva:
            min_rva = nrva
        if nrva > max_rva:
            max_rva = nrva

    name_region_start = base + min_rva
    name_region_size = (max_rva - min_rva) + 256
    name_region_data = _rv(name_region_start, name_region_size)

    def _read_name_local(nrva):
        """Read a name string from the bulk-fetched name region, with fallback."""
        offset = (base + nrva) - name_region_start
        if name_region_data and 0 <= offset < len(name_region_data):
            end = name_region_data.find(b'\x00', offset)
            if end >= 0:
                return name_region_data[offset:end]
            return name_region_data[offset:offset + 256].split(b'\x00')[0]
        # Fallback for out-of-range (shouldn't happen)
        data = session.read_virtual(base + nrva, 256)
        if data:
            null = data.find(b'\x00')
            return data[:null] if null >= 0 else data
        return b""

    target = name_to_find.encode("ascii")

    # Binary search — export names are sorted alphabetically (zero RTTs)
    lo, hi = 0, num_names - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        nrva = struct.unpack_from("<I", name_ptrs, mid * 4)[0]
        name = _read_name_local(nrva)
        if not name:
            break
        if name == target:
            ordinal = struct.unpack_from("<H", ordinals, mid * 2)[0]
            return struct.unpack_from("<I", func_addrs, ordinal * 4)[0]
        elif name < target:
            lo = mid + 1
        else:
            hi = mid - 1
    return 0


def _walk_module_list(session):
    """Walk PsLoadedModuleList and return list of kernel modules.

    Returns list of (dll_base, size_of_image, entry_point, base_name, full_name).
    Uses cache: first call is slow (network), subsequent calls are instant.
    """
    global _cached_kernel_base, _cached_ps_list_ptr, _cached_modules
    if _cached_modules is not None:
        return _cached_modules

    # 1. Find kernel base
    info("Scanning for kernel base...")
    kbase = _find_kernel_base(session)
    if not kbase:
        error("Could not find kernel base (MZ header)")
        return None
    info(f"Kernel base: {kbase:#x}")

    # 2. Find PsLoadedModuleList (cached after first resolution)
    if not _cached_ps_list_ptr:
        info("Resolving PsLoadedModuleList...")
        rva = _find_export(session, kbase, "PsLoadedModuleList")
        if not rva:
            error("Could not find PsLoadedModuleList export")
            return None
        _cached_ps_list_ptr = kbase + rva

    ps_list_ptr = _cached_ps_list_ptr
    head_data = session.read_virtual(ps_list_ptr, 8)
    if not head_data:
        error(f"Cannot read PsLoadedModuleList at {ps_list_ptr:#x}")
        return None
    list_head = struct.unpack_from("<Q", head_data, 0)[0]

    # 3. Walk linked list with aggressive prefetch optimization
    #    _KLDR_DATA_TABLE_ENTRY (x64, Win10/11):
    #    +0x00: InLoadOrderLinks (LIST_ENTRY: Flink 8, Blink 8)
    #    +0x30: DllBase (8)         +0x38: EntryPoint (8)
    #    +0x40: SizeOfImage (4, padded to 8)
    #    +0x48: FullDllName  (UNICODE_STRING: Len 2, MaxLen 2, pad 4, Buffer 8)
    #    +0x58: BaseDllName  (UNICODE_STRING)
    #
    # Strategy: prefetch large memory blocks around list entries so that
    # most entries + name strings can be parsed from local buffers.
    # Kernel pool allocations are often clustered nearby.
    #
    # Optimization: speculative 256KB read around first entry address,
    # since kernel pool entries are typically within a few hundred KB.
    # After first pass, batch-prefetch all name string pages at once.

    ENTRY_SIZE = 0x70
    use_pipeline = hasattr(session, 'read_virtual_pipelined')

    # Helper: read from local buffer, returning slice or None
    buf_blocks = {}  # base_addr -> bytes

    def _buf_read(addr, size):
        for bbase, bdata in buf_blocks.items():
            off = addr - bbase
            if 0 <= off and off + size <= len(bdata):
                return bdata[off:off + size]
        return None

    # Speculative prefetch: 256KB around list head (pipelined = ~0.2s)
    spec_base = list_head & ~0xFFFF
    if use_pipeline:
        spec_data = session.read_virtual_pipelined(spec_base, 0x40000)
    else:
        spec_data = session.read_virtual(spec_base, 0x40000)
    if spec_data:
        buf_blocks[spec_base] = spec_data

    # Walk linked list — entries are mostly in the speculative buffer
    entries_raw = []
    entry = list_head
    visited = set()

    for _ in range(512):
        if entry in visited or entry == 0 or entry == ps_list_ptr:
            break
        visited.add(entry)

        entry_data = _buf_read(entry, ENTRY_SIZE)
        if entry_data is None:
            # Cache miss — small read for this entry
            entry_data = session.read_virtual(entry, ENTRY_SIZE)
        if not entry_data or len(entry_data) < ENTRY_SIZE:
            break

        flink = struct.unpack_from("<Q", entry_data, 0)[0]
        dll_base = struct.unpack_from("<Q", entry_data, 0x30)[0]
        entry_point = struct.unpack_from("<Q", entry_data, 0x38)[0]
        size_of_image = struct.unpack_from("<I", entry_data, 0x40)[0]

        bname_len = struct.unpack_from("<H", entry_data, 0x58)[0]
        bname_buf = struct.unpack_from("<Q", entry_data, 0x58 + 8)[0]
        fname_len = struct.unpack_from("<H", entry_data, 0x48)[0]
        fname_buf = struct.unpack_from("<Q", entry_data, 0x48 + 8)[0]

        entries_raw.append((dll_base, size_of_image, entry_point,
                            bname_len, bname_buf, fname_len, fname_buf))
        entry = flink

    # Resolve names via pipeline — collect all reads, send at once
    name_reads = []  # (index, field, addr, size)
    for idx, (_, _, _, bl, bb, fl, fb) in enumerate(entries_raw):
        if bl > 0 and bb > 0x1000:
            # Check local buffer first
            if _buf_read(bb, min(bl, 512)) is None:
                name_reads.append((idx, 'base', bb, min(bl, 512)))
        if fl > 0 and fb > 0x1000 and fb != bb:
            if _buf_read(fb, min(fl, 1024)) is None:
                name_reads.append((idx, 'full', fb, min(fl, 1024)))

    # Pipeline all name reads at once
    if name_reads and use_pipeline:
        pipe_reads = [(addr, sz) for _, _, addr, sz in name_reads]
        pipe_results = session.pipeline_read(pipe_reads)
        for (idx, field, addr, sz), data in zip(name_reads, pipe_results):
            if data:
                buf_blocks[addr] = data
    elif name_reads:
        for idx, field, addr, sz in name_reads:
            data = session.read_virtual(addr, sz)
            if data:
                buf_blocks[addr] = data

    # Build module list from buffered data
    modules = []
    for dll_base, size, ep, bl, bb, fl, fb in entries_raw:
        base_name = ""
        if bl > 0 and bb > 0x1000:
            raw = _buf_read(bb, min(bl, 512))
            if raw:
                try:
                    base_name = raw.decode("utf-16-le").rstrip('\x00')
                except UnicodeDecodeError:
                    pass

        full_name = ""
        if fl > 0 and fb > 0x1000 and fb != bb:
            raw = _buf_read(fb, min(fl, 1024))
            if raw:
                try:
                    full_name = raw.decode("utf-16-le").rstrip('\x00')
                except UnicodeDecodeError:
                    pass

        if dll_base and base_name:
            modules.append((dll_base, size, ep, base_name, full_name))

    if modules:
        modules.sort(key=lambda m: m[0])
        _cached_modules = modules

    return modules


def cmd_kdlm(debugger, args):
    """List loaded kernel modules.

    Usage: lm [-r] [filter]
           lm m <pattern>       — WinDbg-style module filter
           -r  force refresh (bypass cache)
    Examples: lm ntoskrnl
              lm m nt*
              lm m ch79
    """
    global _cached_modules
    session = _get_session()
    if session is None:
        return None
    if not session.stopped:
        error("Target is running. Break first.")
        return None

    parts = args.strip().split()
    if "-r" in parts:
        _cached_modules = None
        parts.remove("-r")
    # WinDbg compat: "lm m <pattern>" — strip the 'm' keyword
    if parts and parts[0].lower() == "m":
        parts = parts[1:]
    filter_str = " ".join(parts).lower()

    modules = _walk_module_list(session)
    if not modules:
        warn("No modules found")
        return None

    # Apply filter (supports substring match and WinDbg wildcards: nt*, *drv)
    if filter_str:
        import fnmatch
        if '*' in filter_str or '?' in filter_str:
            pat = filter_str
            modules = [m for m in modules
                       if fnmatch.fnmatch(m[3].lower(), pat)
                       or fnmatch.fnmatch(m[4].lower(), pat)]
        else:
            modules = [m for m in modules
                       if filter_str in m[3].lower()
                       or filter_str in m[4].lower()]
        if not modules:
            warn(f"No modules matching '{filter_str}'")
            return None

    banner(f"LOADED KERNEL MODULES ({len(modules)})")

    for dll_base, size, ep, base_name, full_name in modules:
        end_addr = dll_base + size
        line = Text()
        line.append(f"  {dll_base:#018x}", style="bright_cyan")
        line.append(f"  {end_addr:#018x}", style="bright_cyan")
        line.append(f"  {size:#010x}", style="white")
        line.append(f"  {base_name}", style="bold bright_green")
        if full_name and full_name.lower() != base_name.lower():
            line.append(f"  ({full_name})", style="bright_black")
        console.print(line)
    return None


# ---------------------------------------------------------------------------
# kddbgprint — show kernel DbgPrint log
# ---------------------------------------------------------------------------

def cmd_kddbgprint(debugger, args):
    """Show captured DbgPrint output from the kernel."""
    session = _get_session()
    if session is None:
        return None

    if not session.dbgprint_log:
        info("No DbgPrint output captured")
        return None

    banner("DbgPrint Log")
    for line in session.dbgprint_log:
        console.print(f"  {line}")
    return None


# ---------------------------------------------------------------------------
# kdchecksec — show VM/kernel security features
# ---------------------------------------------------------------------------

def cmd_kdchecksec(debugger, args):
    """Show kernel security features and CPU mitigations.

    Reads CR0, CR4, EFER, and KUSER_SHARED_DATA to detect:
      SMEP, SMAP, NX/DEP, KASLR, KPTI, CET, VBS/HVCI, etc.

    Usage: kdchecksec
    """
    session = _get_session()
    if session is None:
        return None
    if not session.stopped:
        error("Target is running. Break first.")
        return None

    has_raw_reg = hasattr(session, '_read_raw_register')
    if not has_raw_reg:
        error("Not supported for this session type")
        return None

    # Read control registers
    cr0 = session._read_raw_register(27)
    cr4 = session._read_raw_register(30)
    efer = session._read_raw_register(32)

    # Read KUSER_SHARED_DATA
    kuser = 0xFFFFF78000000000
    kuser_data = session.read_virtual(kuser + 0x260, 32)
    build_num = 0
    if kuser_data and len(kuser_data) >= 4:
        build_num = struct.unpack_from('<I', kuser_data, 0)[0] & 0x7FFF

    kva_byte = 0
    kva_data = session.read_virtual(kuser + 0x283, 1)
    if kva_data:
        kva_byte = kva_data[0]

    # Kernel base (cached from lm)
    kbase = _cached_kernel_base

    banner("KERNEL SECURITY FEATURES")

    def _row(name, enabled, detail=""):
        mark = Text()
        if enabled:
            mark.append(" [+] ", style="bold bright_green")
        else:
            mark.append(" [-] ", style="bold bright_red")
        mark.append(f"{name:20s}", style="bold white")
        if detail:
            mark.append(f"  {detail}", style="bright_black")
        console.print(mark)

    # --- CPU mitigations (CR4) ---
    console.print(Text(f"  CR0={cr0:#018x}  CR4={cr4:#018x}  EFER={efer:#018x}",
                       style="bright_black"))
    if build_num:
        console.print(Text(f"  Windows Build {build_num}", style="bright_black"))
    console.print()

    _row("SMEP",
         bool(cr4 & (1 << 20)),
         "Supervisor Mode Execution Prevention (CR4.SMEP)")

    _row("SMAP",
         bool(cr4 & (1 << 21)),
         "Supervisor Mode Access Prevention (CR4.SMAP)")

    _row("NX / DEP",
         bool(efer & (1 << 11)),
         "No-Execute / Data Execution Prevention (EFER.NXE)")

    _row("WP",
         bool(cr0 & (1 << 16)),
         "Write Protect — kernel can't write RO pages (CR0.WP)")

    _row("UMIP",
         bool(cr4 & (1 << 11)),
         "User-Mode Instruction Prevention (CR4.UMIP)")

    _row("CET",
         bool(cr4 & (1 << 23)),
         "Control-flow Enforcement Technology (CR4.CET)")

    _row("PCIDE",
         bool(cr4 & (1 << 17)),
         "Process Context Identifiers (CR4.PCID)")

    _row("PKE",
         bool(cr4 & (1 << 22)),
         "Protection Keys for User pages (CR4.PKE)")

    _row("FSGSBASE",
         bool(cr4 & (1 << 16)),
         "RDFSBASE/WRFSBASE instructions (CR4.FSGSBASE)")

    console.print()

    # --- Kernel mitigations ---
    _row("KASLR",
         kbase != 0 and (kbase & 0xFFF00000) != 0x00100000,
         f"Kernel base: {kbase:#x}" if kbase else "kernel base unknown")

    _row("KPTI",
         bool(kva_byte & 1),
         "Kernel Page Table Isolation / KVA Shadow")

    _row("VMXE",
         bool(cr4 & (1 << 13)),
         "VMX Enable — VT-x / Hyper-V (CR4.VMXE)")

    # Check VBS via KUSER_SHARED_DATA
    # +0x2EC: VirtualizationFlags on some builds
    vbs_data = session.read_virtual(kuser + 0x2EC, 4)
    vbs_flags = 0
    if vbs_data and len(vbs_data) >= 4:
        vbs_flags = struct.unpack_from('<I', vbs_data, 0)[0]
    _row("VBS / HVCI",
         bool(vbs_flags & 0x1),
         "Virtualization Based Security")

    return None
