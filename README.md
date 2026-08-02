

<img width="1792" height="592" alt="Gemini_Generated_Image_jn39e5jn39e5jn39" src="https://github.com/user-attachments/assets/78351db2-ef7b-467e-9ad7-7c32dae75a05" />


# pwnWinDbg


<img width="1882" height="936" alt="image" src="https://github.com/user-attachments/assets/104858fc-b9c0-4b37-bfba-c8655966f91d" />



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
- **Autonomous AI agent** — `ai "<task>"` drives the debugger for you: runs commands, writes & runs exploit scripts, reads/writes memory & registers, and talks to the debuggee over a tube (see [AI agent](#ai-agent))

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
| `run -i <exe> [args]` | | Spawn with an interactive I/O tube (for the AI agent / scripts) |
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

### AI Agent

See [AI agent](#ai-agent) for the full write-up.

| Command | Description |
|---------|-------------|
| `ai "<task>"` | Run the autonomous AI agent on a one-shot task |
| `ai status` | Show provider / model / key-present / config path |
| `ai config [path]` | Print effective config (or just its path) |
| `ai config set <dotted> <value>` | Set any config key (e.g. `openai.model foo`) |
| `ai use <provider>` | Switch backend: `claude_code` \| `openai` \| `anthropic` |
| `ai model <name>` | Set the current provider's model |
| `ai key <provider> <value>` | Store an API key for a provider |

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

## AI agent

pwnWinDbg ships an **autonomous, agentic AI** that drives the debugger for you.
Give it a one-shot task and it reasons, runs debugger commands, writes and runs
Python exploit scripts, reads/writes memory & registers, and interacts with the
debuggee's stdin/stdout — all with a live view of its thinking in the terminal.

```
pwnWinDbg> ai "find the buffer overflow offset in this binary and get me a shell"
pwnWinDbg> ai "single-step to main, dump the first 5 args, and explain what it does"
```

### How it works

The AI acts through two kinds of fenced action blocks:

- ` ```dbg ` — one debugger command per line (run via the normal dispatcher).
- ` ```python ` — arbitrary Python that runs in an **isolated child process** and
  talks back to the debugger over a loopback-socket RPC. Only `print()` output is
  returned to the model (Hermes-style). Available helpers include `dbg("cmd")`,
  `read/write` memory, `regs/getreg/setreg`, `send/sendline/recv/recvuntil/recvline`
  (to the **debuggee**), `eval_addr`, `state`, `log`, `sh`, `read_file/write_file/patch_file`,
  `p8..p64/u8..u64`, `cyclic/cyclic_find`, and **pwntools** (`from pwn import *`) if installed.

Code execution can be disabled entirely by setting `code_exec` to `false` in the config.

### Interactive tube — `run -i`

To let the AI (or your own scripts) `send()`/`recv()` to the target, spawn it with
an I/O tube:

```
pwnWinDbg> run -i target.exe          # wires child stdin/stdout to a tube
pwnWinDbg> ai "send a cyclic pattern, find the crash offset, then exploit it"
```

Without `-i`, the process runs with a normal console and no tube is attached
(tube-backed calls like `send`/`recv` will report *"no interactive tube"*).

### Providers

Select the LLM backend with `ai use <provider>`:

| Provider | Backend |
|----------|---------|
| `claude_code` *(default)* | The Claude Code CLI as the brain (no API key needed if the `claude` binary is on PATH) |
| `openai` | Any OpenAI-compatible `/chat/completions` endpoint (Kimi/Moonshot, DeepSeek, OpenRouter, local servers) |
| `anthropic` | Native Anthropic Messages API |

### Config

Config lives at `%LOCALAPPDATA%\pwnWinDbg\ai_config.json` (created with defaults on
first use). Manage it from inside the debugger:

```
pwnWinDbg> ai status                          # provider / model / key / config path
pwnWinDbg> ai config                          # print effective config (+ path)
pwnWinDbg> ai config path                     # just the file path
pwnWinDbg> ai use openai                       # switch provider
pwnWinDbg> ai model kimi-k2-0711-preview       # set the current provider's model
pwnWinDbg> ai key openai sk-...                # store an API key
pwnWinDbg> ai config set max_steps 40          # set any dotted config key
pwnWinDbg> ai config set openai.base_url https://api.moonshot.ai/v1
```

API keys may also be supplied via environment variables (`MOONSHOT_API_KEY`,
`ANTHROPIC_API_KEY`, or the generic `OPENAI_API_KEY` / `ANTHROPIC_API_KEY`), which
take precedence over a stored `api_key`.

### Steering (Ctrl+C)

While the agent is working, press **Ctrl+C** to steer it:

- If the debuggee is running, Ctrl+C interrupts it (like a normal break).
- Otherwise the agent pauses and prompts you: type guidance to redirect it, press
  Enter to resume, or type `stop` to end the run.

The agent stops on its own once the task is done (a reply with no action block), or
after `max_steps` iterations.

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
│   ├── kd_dt_cmds.py        # kddt / dt (WinDbg-style struct view)
│   └── ai_cmds.py           # ai command (agent + config subcommands)
├── ai/                      # Autonomous in-debugger AI agent
│   ├── agent.py             # Agent loop (stream, parse blocks, execute, steer)
│   ├── config.py            # ai_config.json load/save + key resolution
│   ├── tools.py             # DebugTools: parent-side RPC method implementations
│   ├── rpc.py               # Loopback-socket RPC transport (parent <-> child)
│   ├── rpc_server.py        # Parent RPC server (one code-exec child at a time)
│   ├── child_runner.py      # Isolated child entrypoint for python blocks
│   ├── agent_runtime.py     # Child runtime namespace (dbg/read/send/pwntools/...)
│   ├── system_prompt.py     # System prompt + command cheat-sheet builder
│   └── providers/           # LLM backends: claude_code / openai / anthropic
├── core/
│   ├── debugger.py          # Debug API engine
│   ├── proc_io.py           # ProcTube: pwntools-style stdin/stdout pipe (run -i)
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
│   ├── ai_view.py           # Live AI agent display (reasoning / tool output)
│   └── ...
├── analysis/
│   └── pe_info.py           # PE analysis (checksec, IAT)
└── utils/
    ├── addr_expr.py         # Address expression evaluator
    └── constants.py         # Win32 API constants & bindings
```

## License

MIT
