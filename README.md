

<img width="1792" height="592" alt="Gemini_Generated_Image_jn39e5jn39e5jn39" src="https://github.com/user-attachments/assets/78351db2-ef7b-467e-9ad7-7c32dae75a05" />


# pwnWinDbg


<img width="1580" height="948" alt="image" src="https://github.com/user-attachments/assets/a1e217c5-747b-4596-a174-b5674c1a1e73" />


**A pwndbg-style debugger for Windows userland**, built from scratch on the Windows Debug API.

pwnWinDbg brings the UX and workflow of [pwndbg](https://github.com/pwndbg/pwndbg) to Windows — color-coded context display, GDB-style commands, pointer chain analysis, ROP gadget search, and exploit development utilities, all in a native Windows CLI.

## Features

### Userland
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

### Kernel mode (x64)
- **QEMU GDB stub transport** — connect to a Windows VM running under QEMU/KVM with `-s`/`-gdb tcp:...`
- **Process / thread / token enumeration** — walks `PsActiveProcessHead` and `EPROCESS.ThreadListHead` to list processes, threads and tokens (PID, PPID, name, EPROCESS, Token, DTB)
- **Token stealing primitive** — `kdtoken steal <src> <dst>` patches `EPROCESS.Token` to elevate a target process; `kdtoken shellcode` emits a self-contained x64 stealer
- **Dynamic struct offset extraction** — disassembles stable `nt!Ps*` exports (`PsGetProcessId`, `PsGetProcessImageFileName`, `PsGetCurrentProcessId`, `PsGetCurrentThreadId`) at runtime to recover EPROCESS / KTHREAD / ETHREAD field offsets, no per-build hardcoded tables
- **Page-table walker** — `kdpte <vaddr>` follows PML4 → PDPT → PD → PT, detects 1 GB / 2 MB large pages, prints physical address
- **Kernel region classifier** — `kdxinfo` tags any kernel address as `ntoskrnl`, `pool`, `KUSER_SHARED_DATA`, etc.
- **Heuristic stack backtrace** — `kdbt` scans `RSP` for `call`-validated return addresses and resolves them to module+offset
- **WinDbg-style struct view** — `kddt _EPROCESS [addr]` prints field layout, populated dynamically from extracted offsets
- **Kernel memory search** — `kdsearch -s|-x|-p [--module M]` across loaded driver images
- **Kernel `lm`** — list loaded drivers via `PsLoadedModuleList`, with name/regex filter
- **Kernel breakpoints, single-step, register dump, mem read/write** via the GDB RSP backend
- **Kernel `checksec`** — reports SMEP / SMAP / NX / KPTI / kernel CET / KVA shadow status from `CR0`/`CR4`/`EFER`

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

### Userland

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

### Kernel debugging (QEMU GDB stub only — for now)

> **Status:** Only the **QEMU GDB stub** transport is implemented and tested today.
> The KDNET (UDP) and named-pipe (`kdcom`) backends listed in the help are stubs and **do not work yet**.

Boot a Windows VM under QEMU/KVM with the GDB stub enabled:

```bash
qemu-system-x86_64 \
    -m 4G -smp 2 -enable-kvm \
    -drive file=win10.qcow2,if=virtio \
    -s                       # equivalent to: -gdb tcp::1234
    # ...or pick your own port:
    # -gdb tcp::10000
```

Then attach pwnWinDbg from the host:

```bash
python -m pwnwindbg
pwnWinDbg> kdconnect gdb:localhost:10000
pwnWinDbg> lm                       # list loaded drivers
pwnWinDbg> kdps                     # walk processes
pwnWinDbg> kdthreads 4              # threads of System
pwnWinDbg> kdtoken                  # list tokens
pwnWinDbg> kdtoken steal 4 1234     # copy SYSTEM token to PID 1234
pwnWinDbg> kdpte 0xfffff80206ea3000 # walk page tables
pwnWinDbg> kddt _EPROCESS           # show struct layout
pwnWinDbg> kdc                      # continue
pwnWinDbg> kddisconnect
```

Physical-memory reads (used by `kdpte`) require QEMU's monitor to be reachable
on the same TCP socket — pwnWinDbg multiplexes `xp /Nbx` requests over the
QEMU GDB RSP `qRcmd` channel, so no extra `-monitor` flag is needed.

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

### Kernel Debugging

> Currently only `kdconnect gdb:host:port` is functional. The `net:` and `pipe:` forms are placeholders.

#### Connection / control

| Command | Description |
|---------|-------------|
| `kdconnect gdb:host:port` | Connect to a QEMU GDB stub (e.g. `gdb:localhost:10000`) |
| `kddisconnect` | Disconnect from the kernel target |
| `kdversion` | Target version, build number (from `KUSER_SHARED_DATA`), bitness |
| `kdbreak` | Interrupt a running kernel |
| `kdc` / `kdcontinue` | Resume kernel execution |
| `kdsi` / `kdstep` | Single-step (step into) |
| `kdni` | Step over (skip `call`) |

#### Memory / registers / breakpoints

| Command | Description |
|---------|-------------|
| `kdregs` | Show kernel registers (with telescope) |
| `kdmem <addr> [size]` | Hex dump of kernel memory |
| `kdwrite <addr> <hex>` | Write kernel memory |
| `kddisasm [addr] [n]` / `kdu` | Disassemble kernel code |
| `kdbp <addr>` / `kdbpd <addr>` | Set / clear kernel breakpoint |
| `kddbgprint` | Show captured `DbgPrint` output |
| `kdchecksec` / `checksec` | SMEP / SMAP / NX / KPTI / CET / KVA-shadow status |

#### Modules / processes / tokens

| Command | Description |
|---------|-------------|
| `lm` / `kdlm [m] [filter]` | List loaded drivers (`PsLoadedModuleList`) |
| `kdps [filter]` | Walk `ActiveProcessLinks`, list processes |
| `kdthreads <pid\|name>` | List threads of a process |
| `kdtoken` | List process tokens (raw `EX_FAST_REF` + addr + refcnt) |
| `kdtoken steal <src> <dst>` | Copy a token from src process to dst (4 = SYSTEM) |
| `kdtoken shellcode` | Print x64 token-stealing shellcode template |

#### Navigation / analysis

| Command | Description |
|---------|-------------|
| `kdbt [max] [scan]` | Heuristic kernel backtrace (call-validated stack scan) |
| `kdxinfo <addr>` | Classify a kernel address (module / pool / KUSER_SHARED_DATA / …) |
| `kdsearch -s\|-x\|-p [--module M]` | Search kernel memory for a string / hex pattern / pointer |
| `kdpte <vaddr>` | Walk page tables (PML4 → PDPT → PD → PT), print physical address |
| `kddt <_STRUCT> [addr]` / `dt` | WinDbg-style struct view (currently `_EPROCESS`) |

Both `kdconnect ... gdb:` accepts the WinDbg `nt`/`ntkrnl`/`ntkrnlmp` aliases in
expressions (e.g. `kdxinfo nt+0x1000`).

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
│   ├── nav_cmds.py          # xinfo, distance, entry
│   ├── kd_cmds.py           # kdconnect / kdregs / kdmem / kdbp / kddisasm / kdlm / kdchecksec
│   ├── kd_ps_cmds.py        # kdps / kdthreads / kdtoken (steal + shellcode)
│   ├── kd_nav_cmds.py       # kdbt (heuristic backtrace) / kdxinfo
│   ├── kd_search_cmds.py    # kdsearch -s/-x/-p [--module M]
│   ├── kd_pte_cmds.py       # kdpte page-table walker
│   └── kd_dt_cmds.py        # kddt / dt (WinDbg-style struct view)
├── core/
│   ├── debugger.py          # Debug API engine
│   ├── breakpoints.py       # INT3 breakpoint manager
│   ├── memory.py            # Read/Write/Query memory
│   ├── registers.py         # Thread context handling
│   ├── symbols.py           # DbgHelp symbol resolution
│   ├── disasm.py            # Capstone wrapper
│   └── kd/                  # Kernel debugging backend
│       ├── transport.py         # Abstract transport (recv/send/connect)
│       ├── gdb_transport.py     # QEMU GDB stub (RSP) transport + qRcmd monitor bridge
│       ├── protocol.py          # KD packet helpers (placeholder for KDNET/pipe)
│       ├── kd_session.py        # High-level session: regs, mem, bp, step, continue
│       ├── kd_structs.py        # KD protocol structures (placeholder)
│       ├── win_structs.py       # EPROCESS / KTHREAD / ETHREAD / KPCR offsets (mutated at runtime)
│       ├── offset_extractor.py  # Disasm Ps* exports → recover struct offsets dynamically
│       ├── ps_walker.py         # Walk ActiveProcessLinks + ThreadListHead
│       ├── stack_walker.py      # Heuristic backtrace (call-validated frame scan)
│       └── kernel_regions.py    # Classify kernel addresses (module/pool/KUSER/...)
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
