<img width="1024" height="339" alt="image" src="https://github.com/user-attachments/assets/5df678f6-94ae-433d-860e-76b1cbb47f93" />


# pwnWinDbg


<img width="1580" height="948" alt="image" src="https://github.com/user-attachments/assets/a1e217c5-747b-4596-a174-b5674c1a1e73" />


**A pwndbg-style debugger for Windows userland**, built from scratch on the Windows Debug API.

pwnWinDbg brings the UX and workflow of [pwndbg](https://github.com/pwndbg/pwndbg) to Windows — color-coded context display, GDB-style commands, pointer chain analysis, ROP gadget search, and exploit development utilities, all in a native Windows CLI.

## Features

- **pwndbg-style context** — registers, disassembly, stack, and backtrace in a single view
- **GDB-compatible commands** — `x/`, `si`, `ni`, `bp`, `set`, `finish`, etc.
- **Telescope / pointer chains** — dereference pointers recursively, annotate strings and executable addresses
- **ROP gadget finder** — backward scan from `ret` instructions across executable regions
- **De Bruijn cyclic patterns** — generate and look up offsets for exploit development
- **Memory search** — find strings, hex patterns, pointers, raw bytes across all regions
- **PE analysis** — checksec (ASLR, DEP, CFG, SEH...), IAT dump, section info
- **Address expressions** — use `rax+0x10`, `ntdll+0x1000`, `rsp-8` anywhere an address is expected
- **Persistent breakpoints** — survive re-run and re-attach
- **WoW64 support** — debug 32-bit processes on 64-bit Windows

## Requirements

- **Windows 10/11** (x64)
- **Python 3.10+**

## Installation

```bash
git clone https://github.com/heazzy/pwnWinDbg.git
cd pwnWinDbg
pip install -r requirements.txt
```

## Usage

```bash
# Launch a process
python -m pwnwindbg target.exe
python -m pwnwindbg target.exe --args "arg1 arg2"
python -m pwnwindbg target.exe --stdin payload.bin

# Attach to a running process
python -m pwnwindbg --attach <pid>

# Or use the wrapper
python main.py target.exe
```

## Commands

### Execution

| Command | Aliases | Description |
|---------|---------|-------------|
| `run <exe> [args]` | `r` | Spawn a process |
| `attach <pid>` | | Attach to a running process |
| `continue` | `c` | Resume execution |
| `si` | `s` | Step into (single instruction) |
| `ni` | `n` | Step over |
| `finish` | `fin` | Run until current function returns |
| `nextcall` | `nc` | Step until next `call` |
| `nextret` | `nr` | Step until next `ret` |
| `nextjmp` | `nj` | Step until next branch |
| `entry` | | Break at PE entry point |
| `kill` | | Terminate the process |
| `detach` | | Detach from the process |

### Breakpoints

| Command | Aliases | Description |
|---------|---------|-------------|
| `bp <addr>` | `b`, `break` | Set a breakpoint |
| `bl` | `i b`, `info breakpoints` | List breakpoints |
| `bd <id>` | `del`, `delete` | Delete a breakpoint |
| `retbreak` | `rb` | Break on all `ret` in current function |

### Display

| Command | Aliases | Description |
|---------|---------|-------------|
| `context` | `ctx` | Full pwndbg-style context |
| `regs` | `registers` | Show registers (highlights changes) |
| `disasm [addr] [n]` | `u`, `disass` | Disassemble instructions |
| `hexdump <addr> [len]` | `hd` | Classic hex dump |
| `stack [count]` | | Telescope-style stack view |
| `telescope [addr] [depth]` | `tel` | Pointer chain dereferencing |

### Memory Examination (GDB-style)

| Command | Description |
|---------|-------------|
| `x/bx <addr> [n]` | Read bytes |
| `x/wx <addr> [n]` | Read dwords |
| `x/gx <addr> [n]` | Read qwords |
| `x/s <addr>` | Read string |
| `x/i <addr> [n]` | Disassemble |

### Memory Search

| Command | Description |
|---------|-------------|
| `search -s "string"` | Search ASCII string |
| `search -x "4141"` | Search hex pattern |
| `search -p <addr>` | Search pointer value |
| `search -b "\x90\x90"` | Search raw bytes |

### Patching

| Command | Description |
|---------|-------------|
| `patch <addr> <hex>` | Write hex bytes |
| `patch <addr> nop <n>` | Write NOP sled |
| `set <reg> <value>` | Set register value |
| `set *(type*)addr = val` | GDB-style memory write |
| `write <type> <addr> <val>` | Write typed value (byte/word/dword/qword/string) |
| `dump <addr> <size> [file]` | Dump memory to file |

### Exploit Development

| Command | Description |
|---------|-------------|
| `cyclic <len>` | Generate De Bruijn pattern |
| `cyclic -l <value>` | Find pattern offset |
| `rop [--module M]` | Find ROP gadgets |
| `p2p <src> <tgt>` | Find pointers from source into target region |

### Information

| Command | Aliases | Description |
|---------|---------|-------------|
| `vmmap` | `info maps` | Memory map with protections |
| `modules` | `info modules` | List loaded modules |
| `info functions [filter]` | `funcs` | List exports/imports |
| `info proc` | | Process info |
| `checksec [path]` | | PE security mitigations |
| `iat [path]` | `got` | Import Address Table |
| `xinfo <addr>` | | Detailed address info |
| `distance <a> <b>` | | Offset between two addresses |

### Address Expressions

All commands accepting addresses support arithmetic expressions:

```
tel rsp+0x20
bp ntdll+0x1000
disasm rax-1
x/gx rsp+8
set *(qword*)rsp+0x10 = 0xdeadbeef
```

## Dependencies

| Package | Purpose |
|---------|---------|
| [pywin32](https://pypi.org/project/pywin32/) | Windows API bindings |
| [capstone](https://www.capstone-engine.org/) | Disassembly engine |
| [pefile](https://pypi.org/project/pefile/) | PE file parsing |
| [rich](https://github.com/Textualize/rich) | Terminal colors and formatting |

## Project Structure

```
pwnwindbg/
├── __main__.py              # REPL entry point
├── commands/
│   ├── dispatcher.py        # Command routing & help
│   ├── execution.py         # run, attach, step, breakpoints
│   ├── display_cmds.py      # regs, disasm, context
│   ├── examine.py           # x/ memory examination
│   ├── memory_cmds.py       # stack, telescope, p2p
│   ├── search_cmds.py       # Pattern search
│   ├── patch_cmds.py        # Memory/register writes
│   ├── cyclic_cmds.py       # De Bruijn patterns
│   ├── rop_cmds.py          # ROP gadget finder
│   ├── info_cmds.py         # Process/module info
│   └── nav_cmds.py          # xinfo, distance, entry
├── core/
│   ├── debugger.py          # Debug API engine
│   ├── breakpoints.py       # INT3 breakpoint manager
│   ├── memory.py            # Read/Write/Query memory
│   ├── registers.py         # Thread context handling
│   ├── symbols.py           # DbgHelp symbol resolution
│   └── disasm.py            # Capstone wrapper
├── display/
│   ├── common.py            # Console, banners, colors
│   ├── formatters.py        # Display facade
│   ├── registers.py         # Register formatting
│   ├── disasm_view.py       # Disassembly view
│   ├── telescope_view.py    # Pointer chain display
│   ├── vmmap_view.py        # Memory map display
│   ├── checksec_view.py     # Checksec & IAT display
│   └── ...
├── analysis/
│   └── pe_info.py           # PE analysis (checksec, IAT)
└── utils/
    ├── addr_expr.py         # Address expression evaluator
    └── constants.py         # Win32 API constants & bindings
```

## License

MIT
