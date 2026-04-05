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


def _show_help():
    """Display available commands."""
    from ..display.formatters import banner
    banner("COMMANDS")

    categories = {
        "Execution": [
            ("run / r", "run <exe> [args] [< stdin]  — spawn process"),
            ("attach", "attach <pid>  — attach to running process"),
            ("c / continue", "Continue execution"),
            ("si / s", "Step into (single instruction)"),
            ("ni / n", "Step over (next instruction)"),
            ("finish / fin", "Run until function returns"),
            ("nextcall / nc", "Step until next call"),
            ("nextret / nr", "Step until next ret"),
            ("nextjmp / nj", "Step until next jmp/branch"),
            ("retbreak / rb", "BP on all ret in function, continue"),
            ("entry", "Break at PE entry point"),
        ],
        "Breakpoints": [
            ("bp / b / break", "Set breakpoint: bp <addr>  (supports *addr)"),
            ("bl / i b", "List breakpoints"),
            ("bd / del", "Delete breakpoint: bd <id>"),
        ],
        "Display": [
            ("regs", "Show registers"),
            ("disasm / disass / u", "Disassemble: disasm [addr] [count]"),
            ("context / ctx", "Show full context display"),
            ("hexdump / hd", "Hex+ASCII: hexdump <addr> [size]"),
        ],
        "Memory": [
            ("x/[N]bx addr", "Examine bytes (N=count)"),
            ("x/[N]wx addr", "Examine dwords"),
            ("x/[N]gx addr", "Examine qwords"),
            ("x/s addr", "Examine string"),
            ("x/[N]i addr", "Disassemble N instructions"),
            ("stack [count]", "Show stack entries"),
            ("tel [addr] [depth]", "Telescope / pointer chains"),
            ("p2p <addr>", "Deep pointer chain"),
            ("search -s|-x|-p", "Search memory for pattern/string/ptr"),
            ("patch <addr> <hex>", "Patch memory bytes / nop / string"),
            ("set <reg> <val>", "Set register value"),
            ("write <type> <addr>", "Write byte/dword/qword/string"),
            ("dump <addr> <sz>", "Dump memory to file or hex"),
        ],
        "Exploit": [
            ("cyclic / pattern", "cyclic 200 | cyclic -l 0x41414141"),
            ("rop", "rop [--module M] [--search S] [--depth N]"),
            ("p / print <expr>", "Resolve symbol/expr (p &WinExec, p rax+8)"),
            ("xinfo <addr>", "Detailed address info (region, module, perms)"),
            ("distance <a> <b>", "Distance between two addresses"),
        ],
        "Info": [
            ("info proc", "Process info (PID, path, arch)"),
            ("info maps / vmmap", "Memory map with perms"),
            ("info modules / modules", "Loaded modules list"),
            ("info functions / funcs", "List functions [filter]"),
            ("checksec [path]", "PE mitigations (ASLR, DEP, CFG...)"),
            ("iat / got [path]", "Import Address Table"),
        ],
    }

    for cat_name, entries in categories.items():
        console.print(f"\n  [bold bright_cyan]{cat_name}[/]")
        for cmd, desc in entries:
            console.print(f"    [bright_white]{cmd:24s}[/]  {desc}")

    console.print(f"\n  [bright_black]Ctrl+C to interrupt — quit / q / exit to quit[/]")
