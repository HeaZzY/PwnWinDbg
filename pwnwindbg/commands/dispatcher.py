"""Command dispatcher: maps user input to command handlers."""

from .execution import (
    cmd_run, cmd_attach, cmd_continue, cmd_step_into, cmd_step_over,
    cmd_finish, cmd_bp, cmd_bl, cmd_bd, cmd_detach, cmd_kill, cmd_retbreak,
)
from .examine import parse_x_command
from .info_cmds import (
    cmd_info, cmd_checksec, cmd_iat, cmd_vmmap, cmd_modules, cmd_functions,
)
from .memory_cmds import cmd_stack, cmd_telescope, cmd_p2p
from .display_cmds import cmd_regs, cmd_disasm, display_context
from .cyclic_cmds import cmd_cyclic
from .search_cmds import cmd_search
from .patch_cmds import cmd_patch, cmd_set, cmd_write, cmd_dump
from .nav_cmds import (
    cmd_nextcall, cmd_nextret, cmd_nextjmp,
    cmd_xinfo, cmd_distance, cmd_entry, cmd_hexdump, cmd_print,
)
from .rop_cmds import cmd_rop
from .kd_cmds import (
    cmd_kdconnect, cmd_kddisconnect, cmd_kdregs, cmd_kdmem, cmd_kdwrite,
    cmd_kdbp, cmd_kdbpd, cmd_kdcontinue, cmd_kdstep, cmd_kdstepover,
    cmd_kdbreak, cmd_kddisasm, cmd_kdversion, cmd_kddbgprint, cmd_kdlm,
    cmd_kdchecksec, is_kd_active,
)
from .kd_ps_cmds import cmd_kdps, cmd_kdthreads, cmd_kdtoken
from .kd_nav_cmds import cmd_kdbt, cmd_kdxinfo
from .kd_search_cmds import cmd_kdsearch
from .kd_pte_cmds import cmd_kdpte
from .kd_dt_cmds import cmd_kddt
from ..display.formatters import error, info, console


# Command table: name -> (handler_func, help_text)
COMMANDS = {
    # Execution
    "run":          (cmd_run,       "Spawn a process: run <exe> [args] [< stdin_file]"),
    "r":            (cmd_run,       "Alias for run"),
    "attach":       (cmd_attach,    "Attach to process: attach <pid>"),
    "continue":     (cmd_continue,  "Continue execution"),
    "c":            (cmd_continue,  "Alias for continue"),
    "si":           (cmd_step_into, "Step into (single instruction)"),
    "s":            (cmd_step_into, "Alias for si"),
    "ni":           (cmd_step_over, "Step over (next instruction)"),
    "n":            (cmd_step_over, "Alias for ni"),
    "finish":       (cmd_finish,    "Run until function returns"),
    "fin":          (cmd_finish,    "Alias for finish"),
    "nextcall":     (cmd_nextcall,  "Step until next call instruction"),
    "nc":           (cmd_nextcall,  "Alias for nextcall"),
    "nextret":      (cmd_nextret,   "Step until next ret instruction"),
    "nr":           (cmd_nextret,   "Alias for nextret"),
    "nextjmp":      (cmd_nextjmp,   "Step until next jmp/branch"),
    "nj":           (cmd_nextjmp,   "Alias for nextjmp"),
    "entry":        (cmd_entry,     "Break at PE entry point"),

    # Breakpoints (multiple aliases for GDB/pwndbg compat)
    "bp":           (cmd_bp,        "Set breakpoint: bp <addr|symbol>"),
    "b":            (cmd_bp,        "Alias for bp"),
    "break":        (cmd_bp,        "Alias for bp"),
    "bl":           (cmd_bl,        "List breakpoints"),
    "info breakpoints": (cmd_bl,    "Alias for bl"),
    "i b":              (cmd_bl,    "Alias for bl (short)"),
    "info b":           (cmd_bl,    "Alias for bl"),
    "i breakpoints":    (cmd_bl,    "Alias for bl"),
    "bd":           (cmd_bd,        "Delete breakpoint: bd <id>"),
    "del":          (cmd_bd,        "Alias for bd"),
    "delete":       (cmd_bd,        "Alias for bd"),
    "retbreak":     (cmd_retbreak,  "Break on all ret in current function, then continue"),
    "rb":           (cmd_retbreak,  "Alias for retbreak"),
    "detach":       (cmd_detach,    "Detach from process"),
    "kill":         (cmd_kill,      "Kill the debugged process"),

    # Display
    "regs":         (cmd_regs,      "Show registers"),
    "registers":    (cmd_regs,      "Alias for regs"),
    "disasm":       (cmd_disasm,    "Disassemble: disasm [addr] [count]"),
    "disass":       (cmd_disasm,    "Alias for disasm"),
    "disassemble":  (cmd_disasm,    "Alias for disasm"),
    "u":            (cmd_disasm,    "Alias for disasm (WinDbg style)"),
    "context":      (lambda d, a: (display_context(d), None)[1], "Show full context display"),
    "ctx":          (lambda d, a: (display_context(d), None)[1], "Alias for context"),
    "hexdump":      (cmd_hexdump,   "Hex + ASCII dump: hexdump <addr> [size]"),
    "hd":           (cmd_hexdump,   "Alias for hexdump"),

    # Memory
    "stack":        (cmd_stack,     "Show stack: stack [count]"),
    "tel":          (cmd_telescope, "Telescope: tel [addr] [depth]"),
    "telescope":    (cmd_telescope, "Alias for tel"),
    "p2p":          (cmd_p2p,       "Pointer to pointer chain: p2p <addr>"),
    "search":       (cmd_search,    "Search memory: search -s str | -x hex | -p ptr"),
    "find":         (cmd_search,    "Alias for search"),
    "patch":        (cmd_patch,     "Patch memory: patch <addr> <hex|nop N|\"str\">"),
    "set":          (cmd_set,       "Set register: set <reg> <value>"),
    "write":        (cmd_write,     "Write typed value: write <type> <addr> <val>"),
    "dump":         (cmd_dump,      "Dump memory: dump <addr> <size> [file]"),

    # Exploit
    "cyclic":       (cmd_cyclic,    "De Bruijn pattern: cyclic <len> | cyclic -l <val>"),
    "pattern":      (cmd_cyclic,    "Alias for cyclic"),
    "rop":          (cmd_rop,       "Find ROP gadgets: rop [--module M] [--search S]"),
    "p":            (cmd_print,     "Print/resolve: p <symbol|expr>  (e.g. p &WinExec)"),
    "print":        (cmd_print,     "Alias for p"),
    "xinfo":        (cmd_xinfo,     "Address info: xinfo <addr>"),
    "distance":     (cmd_distance,  "Distance: distance <addr1> <addr2>"),

    # Info
    "info":         (cmd_info,      "Info commands: info <proc|maps|modules|functions>"),
    "vmmap":        (cmd_vmmap,     "Memory map: vmmap"),
    "checksec":     (cmd_checksec,  "PE mitigations: checksec [path]"),
    "iat":          (cmd_iat,       "Import Address Table: iat [path]"),
    "got":          (cmd_iat,       "Alias for iat"),
    "modules":      (cmd_modules,   "List loaded modules"),
    "functions":    (cmd_functions, "List functions: functions [filter]"),
    "funcs":        (cmd_functions, "Alias for functions"),

    # Kernel debugging
    "kdconnect":    (cmd_kdconnect,     "Connect to kernel target: kdconnect gdb:|net:|pipe: ..."),
    "kddisconnect": (cmd_kddisconnect, "Disconnect from kernel target"),
    "kdregs":       (cmd_kdregs,        "Show kernel registers"),
    "kdmem":        (cmd_kdmem,         "Read kernel memory: kdmem <addr> [size]"),
    "kdwrite":      (cmd_kdwrite,       "Write kernel memory: kdwrite <addr> <hex>"),
    "kdbp":         (cmd_kdbp,          "Set kernel breakpoint: kdbp <addr>"),
    "kdbpd":        (cmd_kdbpd,         "Remove kernel breakpoint: kdbpd <addr>"),
    "kdc":          (cmd_kdcontinue,    "Continue kernel execution"),
    "kdcontinue":   (cmd_kdcontinue,    "Alias for kdc"),
    "kdsi":         (cmd_kdstep,        "Kernel single-step (step into)"),
    "kdstep":       (cmd_kdstep,        "Alias for kdsi"),
    "kdni":         (cmd_kdstepover,    "Kernel step-over (skip calls)"),
    "kdbreak":      (cmd_kdbreak,       "Interrupt running kernel"),
    "kddisasm":     (cmd_kddisasm,      "Kernel disassembly: kddisasm [addr] [count]"),
    "kdu":          (cmd_kddisasm,      "Alias for kddisasm"),
    "kdversion":    (cmd_kdversion,     "Show kernel target info"),
    "kddbgprint":   (cmd_kddbgprint,    "Show captured DbgPrint output"),
    "kdchecksec":   (cmd_kdchecksec,    "Show kernel security features (SMEP/SMAP/NX/KPTI/...)"),
    "kdlm":         (cmd_kdlm,          "List kernel modules: kdlm [-r] [m] [filter]"),
    "lm":           (cmd_modules,       "List modules (kernel modules when in KD session)"),

    # Kernel: process / thread / token
    "kdps":         (cmd_kdps,          "List processes (walks ActiveProcessLinks)"),
    "kdthreads":    (cmd_kdthreads,     "List threads of a process: kdthreads <pid|name>"),
    "kdtoken":      (cmd_kdtoken,       "Token list / steal / shellcode: kdtoken [steal s d|shellcode variant]"),

    # Kernel: navigation
    "kdbt":         (cmd_kdbt,          "Kernel backtrace (heuristic stack scan)"),
    "kdxinfo":      (cmd_kdxinfo,       "Address info: kdxinfo <addr>"),

    # Kernel: search / page tables / type display
    "kdsearch":     (cmd_kdsearch,      "Search kernel memory: kdsearch -s|-x|-p [--module M]"),
    "kdfind":       (cmd_kdsearch,      "Alias for kdsearch"),
    "kdpte":        (cmd_kdpte,         "Walk page tables for a virtual address: kdpte <addr>"),
    "kddt":         (cmd_kddt,          "Display struct: kddt _EPROCESS [addr]"),
    "dt":           (cmd_kddt,          "Alias for kddt (WinDbg-style)"),
}


# When a kernel debug session is active, these userland commands are
# transparently routed to their `kd*` equivalent so the user doesn't have to
# type the `kd` prefix on every command. The explicit `kd*` aliases keep
# working in both modes for users who prefer to be unambiguous.
KD_AUTO_ROUTE = {
    # execution
    "c":           "kdc",
    "continue":    "kdc",
    "si":          "kdsi",
    "s":           "kdsi",
    "step":        "kdsi",
    "ni":          "kdni",
    "n":           "kdni",
    # registers / disasm / memory
    "regs":        "kdregs",
    "registers":   "kdregs",
    "disasm":      "kddisasm",
    "disass":      "kddisasm",
    "disassemble": "kddisasm",
    "u":           "kddisasm",
    "mem":         "kdmem",
    "hexdump":     "kdmem",
    "hd":          "kdmem",
    # breakpoints
    "bp":          "kdbp",
    "b":           "kdbp",
    "break":       "kdbp",
    "bd":          "kdbpd",
    "del":         "kdbpd",
    "delete":      "kdbpd",
    # navigation / analysis
    "bt":          "kdbt",
    "backtrace":   "kdbt",
    "xinfo":       "kdxinfo",
    "search":      "kdsearch",
    "find":        "kdsearch",
    "pte":         "kdpte",
    "modules":     "kdlm",
    "lm":          "kdlm",
    "checksec":    "kdchecksec",
    # process / token
    "ps":          "kdps",
    "threads":     "kdthreads",
    "token":       "kdtoken",
    "tokens":      "kdtoken",
    # info
    "version":     "kdversion",
    "dbgprint":    "kddbgprint",
    "write":       "kdwrite",
}


def dispatch(debugger, user_input):
    """Parse and execute a command. Returns stop_info or None."""
    line = user_input.strip()
    if not line:
        return None

    # Handle x/ commands specially
    if line.startswith("x/"):
        handler, rest = parse_x_command(line, debugger)
        if handler:
            return handler(debugger, rest)
        return None

    # Split command and args
    parts = line.split(None, 1)
    cmd = parts[0].lower()
    args = parts[1] if len(parts) > 1 else ""

    # Help
    if cmd in ("help", "h", "?"):
        _show_help()
        return None

    # Quit
    if cmd in ("quit", "q", "exit"):
        return {"reason": "quit"}

    # Context-aware routing: when a kernel debug session is active, transparently
    # rewrite bare commands (regs, c, si, bp, lm, ps, ...) to their kd-prefixed
    # variants so the user doesn't have to type `kd` on every command.
    if is_kd_active() and cmd in KD_AUTO_ROUTE:
        cmd = KD_AUTO_ROUTE[cmd]

    # Try two-word commands first (e.g. "info breakpoints")
    if args:
        two_word = f"{cmd} {args.split()[0].lower()}"
        if two_word in COMMANDS:
            handler, _ = COMMANDS[two_word]
            rest_args = args.split(None, 1)[1] if len(args.split()) > 1 else ""
            return handler(debugger, rest_args)

    # Single-word lookup
    if cmd in COMMANDS:
        handler, _ = COMMANDS[cmd]
        return handler(debugger, args)

    error(f"Unknown command: {cmd}  (type 'help' for commands)")
    return None


_USERLAND_HELP = {
    "Execution": [
        ("run / r <exe> [args]",  "Spawn a process (use `< stdin_file` for stdin)"),
        ("attach <pid>",          "Attach to a running process"),
        ("c / continue",          "Continue execution"),
        ("si / s",                "Step into (single instruction)"),
        ("ni / n",                "Step over (skip call)"),
        ("finish / fin",          "Run until current function returns"),
        ("nextcall / nc",         "Step until next call"),
        ("nextret / nr",          "Step until next ret"),
        ("nextjmp / nj",          "Step until next jmp / branch"),
        ("retbreak / rb",         "BP on every ret in current function, continue"),
        ("entry",                 "Break at PE entry point"),
        ("kill / detach",         "Terminate / detach process"),
    ],
    "Breakpoints": [
        ("bp / b / break <addr>", "Set software breakpoint (supports *addr)"),
        ("bl / i b",              "List breakpoints"),
        ("bd / del <id>",         "Delete breakpoint"),
    ],
    "Display / context": [
        ("context / ctx",         "Full pwndbg-style context (regs+disasm+stack+bt)"),
        ("regs",                  "Show registers (highlights changes)"),
        ("disasm / u [addr] [n]", "Disassemble N instructions"),
        ("hexdump / hd <addr>",   "Hex + ASCII dump"),
        ("stack [count]",         "Telescope-style stack view"),
        ("tel [addr] [depth]",    "Recursive pointer dereference (telescope)"),
    ],
    "Memory examine (GDB-style)": [
        ("x/[N]bx <addr>",        "Examine bytes"),
        ("x/[N]wx <addr>",        "Examine dwords"),
        ("x/[N]gx <addr>",        "Examine qwords"),
        ("x/s <addr>",            "Examine string"),
        ("x/[N]i <addr>",         "Disassemble"),
    ],
    "Search / patch": [
        ("search -s|-x|-p|-b",    "Search string / hex / pointer / raw bytes"),
        ("patch <addr> <hex>",    "Patch memory  (nop N | \"str\" | hex bytes)"),
        ("set <reg> <val>",       "Set register / `set *(qword*)addr=val`"),
        ("write <type> <addr> v", "Write typed value (byte/word/dword/qword/str)"),
        ("dump <addr> <size>",    "Dump memory to file or hex"),
    ],
    "Exploit dev": [
        ("cyclic <len>",          "Generate De Bruijn pattern"),
        ("cyclic -l <value>",     "Find offset of value in pattern"),
        ("rop [--module M]",      "Find ROP gadgets [--search S] [--depth N]"),
        ("p / print <expr>",      "Resolve symbol or expression (p &WinExec)"),
        ("p2p <addr>",            "Deep pointer chain"),
        ("xinfo <addr>",          "Detailed address info (region/module/perms)"),
        ("distance <a> <b>",      "Offset between two addresses"),
    ],
    "Info": [
        ("info proc",             "Process info (PID, path, arch)"),
        ("vmmap / info maps",     "Memory map with protections"),
        ("modules / info modules","List loaded modules"),
        ("funcs / info functions","List exports/imports"),
        ("checksec [path]",       "PE mitigations (ASLR/DEP/CFG/SEH/...)"),
        ("iat / got [path]",      "Import Address Table"),
    ],
}


_KERNEL_HELP = {
    "Connection / control": [
        ("kdconnect gdb:host:port",   "Connect to QEMU GDB stub (only working transport)"),
        ("kdconnect net:host:port k", "[stub] KDNET over UDP — not implemented"),
        ("kdconnect pipe:path",       "[stub] Named pipe — not implemented"),
        ("kddisconnect",              "Disconnect from kernel target"),
        ("version",                   "Target version + build (KUSER_SHARED_DATA)"),
        ("kdbreak",                   "Interrupt a running kernel"),
        ("c  /  si  /  ni",           "Continue / step into / step over"),
    ],
    "Memory / regs / breakpoints": [
        ("regs",                      "Show kernel registers (with telescope)"),
        ("mem / hexdump <addr>",      "Read kernel memory"),
        ("write <addr> <hex>",        "Write kernel memory"),
        ("disasm / u [addr] [n]",     "Disassemble kernel code"),
        ("bp / bd <addr>",            "Set / clear kernel breakpoint"),
        ("dbgprint",                  "Show captured DbgPrint output"),
        ("checksec",                  "SMEP/SMAP/NX/KPTI/CET/KVA shadow status"),
    ],
    "Modules / process / token": [
        ("lm [m] [filter]",           "List loaded drivers (PsLoadedModuleList)"),
        ("ps [filter]",               "Walk ActiveProcessLinks, list processes"),
        ("threads <pid|name>",        "List threads of a process"),
        ("token",                     "List process tokens (raw EX_FAST_REF + addr)"),
        ("token steal <src> <dst>",   "Copy token from src process to dst (4 = SYSTEM)"),
        ("token shellcode",           "Print x64 token-stealing shellcode template"),
    ],
    "Navigation / analysis": [
        ("bt [max] [scan]",           "Heuristic kernel backtrace (call-validated)"),
        ("xinfo <addr>",              "Classify address (module/pool/KUSER/...)"),
        ("search -s|-x|-p",           "Search kernel memory  [--module M]"),
        ("pte <vaddr>",               "Walk page tables (PML4→PDPT→PD→PT)"),
        ("dt <_STRUCT> [addr]",       "WinDbg-style struct view (currently _EPROCESS)"),
    ],
}


def _show_help():
    """Display available commands. Context-aware: shows kernel commands
    first when a KD session is active.
    """
    from ..display.formatters import banner
    kd_active = is_kd_active()

    banner("COMMANDS — KERNEL MODE" if kd_active else "COMMANDS")

    if kd_active:
        console.print(
            "\n  [bright_black]Kernel session active. Bare commands "
            "(regs, c, si, ni, bp, lm, bt, ps, …) are auto-routed to their\n"
            "  kd* equivalents. Use the explicit `kd*` form anywhere if you "
            "want to be unambiguous.[/]"
        )
        sections = list(_KERNEL_HELP.items()) + [("─── Userland (still available) ───",
                                                  _flatten_user_short())]
    else:
        console.print(
            "\n  [bright_black]Tip: `kdconnect gdb:host:port` to enter kernel "
            "mode. In KD mode, bare commands (regs, c, si, bp, ps, lm, bt, …)\n"
            "  auto-route to their kernel equivalents.[/]"
        )
        sections = list(_USERLAND_HELP.items()) + [("─── Kernel debug ───",
                                                    _flatten_kd_short())]

    from rich.markup import escape
    for cat_name, entries in sections:
        console.print(f"\n  [bold bright_cyan]{escape(cat_name)}[/]")
        for cmd, desc in entries:
            cmd_padded = f"{cmd:28s}"
            console.print(
                f"    [bright_white]{escape(cmd_padded)}[/]  {escape(desc)}"
            )

    console.print(
        "\n  [bright_black]Ctrl+C to interrupt — quit / q / exit to quit[/]"
    )


def _flatten_user_short():
    """One-liner overview of userland features for the kernel-mode help."""
    return [
        ("run / attach",          "Spawn or attach to a Windows process"),
        ("vmmap / modules / iat", "Userland memory map / loaded DLLs / IAT"),
        ("rop / cyclic",          "ROP gadget search / De Bruijn patterns"),
    ]


def _flatten_kd_short():
    """One-liner overview of kernel features for the userland-mode help."""
    return [
        ("kdconnect gdb:host:port",   "Enter kernel mode via QEMU GDB stub"),
        ("kdps / kdthreads / kdtoken","Process / thread / token enumeration"),
        ("kdtoken steal <src> <dst>", "Token stealing primitive (4 = SYSTEM)"),
        ("kdtoken shellcode [variant]", "Generate shellcode: minimal/irp/sysret"),
        ("kdpte <vaddr>",             "Page table walker"),
        ("kdbt / kdxinfo / kdsearch", "Backtrace / address classification / search"),
        ("kddt _EPROCESS",            "WinDbg-style struct view"),
    ]
