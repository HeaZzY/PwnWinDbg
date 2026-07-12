"""Native AI-powered decompiler for PwnWinDbg (full native, no IDA).

The decompiler works entirely off OUR debugger's own disassembly: it extracts
the x86/x64 machine code of a single function with Capstone (``debugger.disassembler``)
and asks the configured LLM (the same providers the AI agent uses) to produce
clean, per-line-annotated pseudo-C. Results are cached PER FUNCTION in memory and
on disk so subsequent stops in the same function are instant (just re-highlight).

Design notes
------------
* Auto-mode (``decompile_function(debugger, addr)`` with ``force=False``) skips
  anything that is not inside the MAIN executable image, so we never spam the
  LLM on ntdll/kernel32/... code. On-demand (``force=True``) decompiles anyway.
* Every LLM call is wrapped: any provider/transport error degrades to ``None``
  and the failure is remembered briefly (short in-memory TTL, never persisted)
  so the live context does not hammer the model on every step.

Pure logic; all optional imports are guarded so this module imports on any OS.
"""

import os
import re
import json
import time
import hashlib

# --- Guarded reuse of existing interfaces (importable in isolation) ----------
try:
    from .disasm import disassemble_at, get_branch_target
except Exception:  # pragma: no cover - defensive
    disassemble_at = None
    get_branch_target = None

try:
    from .memory import read_memory_safe
except Exception:  # pragma: no cover
    read_memory_safe = None

try:
    from ..ai import config as ai_config
except Exception:  # pragma: no cover
    ai_config = None

try:
    from ..ai.providers.base import create_session
except Exception:  # pragma: no cover
    create_session = None


# --- Constants ---------------------------------------------------------------

DECOMPILE_SYSTEM = (
    "You are an expert x86/x64 reverse engineer acting as a decompiler. You are "
    "given the disassembly of ONE function (Intel syntax, one instruction per "
    "line, each line prefixed with its address as `0xADDR:`; call/jmp targets may "
    "carry a `; module!symbol` comment). Reconstruct clean, readable, "
    "compilable-looking pseudo-C for that single function.\n"
    "\n"
    "Requirements:\n"
    "- Recover stack locals as typed local variables (int, unsigned, char buf[N], "
    "pointers, etc.) and give the function a plausible signature with typed "
    "parameters based on the calling convention and how arguments are used.\n"
    "- Reconstruct control flow: if/else, while/for loops, switch, early returns.\n"
    "- Resolve calls to their symbol when the disassembly annotates it, and pass "
    "recognizable string/const arguments inline (e.g. printf(\"%d\", x)).\n"
    "- NAMING: for calls to internal `sub_XXXX` helpers, if the surrounding usage "
    "clearly identifies a standard C-runtime function (gets, fgets, scanf, printf, "
    "puts, putchar, getchar, strcpy, strncpy, strcat, strcmp, strlen, memcpy, "
    "memset, malloc, free, atoi, toupper, tolower, system, exit, ...) or an obvious "
    "purpose (e.g. read_line, print_msg), CALL IT BY THAT INFERRED NAME and keep "
    "the original address in the trailing comment, e.g. `gets(buf); // sub_4040DB "
    "@0x401040`. When the purpose is unclear, keep the `sub_XXXX` name. Prefer "
    "recognizing input readers (gets/fgets/scanf) and output (printf/puts) — they "
    "matter most for exploitation.\n"
    "- Infer simple structs/arrays where the access pattern makes them evident.\n"
    "\n"
    "CRUCIAL output contract (used to drive a live highlighted view):\n"
    "- Output ONLY C. No prose, no explanations, no markdown code fences.\n"
    "- Emit EXACTLY ONE function. Do NOT provide alternate versions, do NOT "
    "revise or correct yourself, and never write commentary such as 'wait' or "
    "'let me correct'. Commit to a single answer.\n"
    "- END EACH C line that is derived from machine code with a trailing comment "
    "`// @0xADDR` giving the address of the primary instruction that line comes "
    "from (best effort). Omit the annotation on purely structural lines such as a "
    "lone `{`, `}`, blank lines, or variable declarations that map to no single "
    "instruction.\n"
    "- Prefer the annotated addresses to be non-decreasing as you go down the "
    "function so the live cursor tracks correctly."
)

# Cap the span we ever read/disassemble/annotate for one function.
_MAX_SPAN_BYTES = 4096
_DEFAULT_MAX_INSNS = 400

# Short TTL (seconds) for remembering a failed decompile so auto-mode does not
# re-hit the LLM on every single step while a provider is down.
_FAIL_TTL = 20.0

# Annotation regex: `// @0xADDR` (the `@` is optional, and any `//` comment that
# contains a hex address counts).
_ADDR_RE = re.compile(r"//\s*@?(0x[0-9A-Fa-f]+)")

# In-memory caches.
_MEM_CACHE = {}          # key -> result dict
_FAIL_CACHE = {}         # key -> expiry (time.monotonic)


# --- Low-level helpers -------------------------------------------------------

def _read(debugger, addr, size):
    """Read target memory, returning bytes or None. Never raises."""
    if read_memory_safe is None:
        return None
    ph = getattr(debugger, "process_handle", None)
    if ph is None or not size or size <= 0:
        return None
    try:
        return read_memory_safe(ph, addr, int(size))
    except Exception:
        return None


def _disasm_range(debugger, start, size, count):
    """Disassemble up to `count` instructions from a fresh read of `size` bytes.
    Returns a list of (address, size, mnemonic, op_str) tuples (possibly empty).
    """
    md = getattr(debugger, "disassembler", None)
    if md is None or disassemble_at is None:
        return []
    code = _read(debugger, start, size)
    if not code:
        return []
    try:
        return disassemble_at(md, code, start, count)
    except Exception:
        return []


def _pe_size_of_image(path):
    """Read PE OPTIONAL_HEADER.SizeOfImage, or None on any failure."""
    if not path:
        return None
    try:
        import pefile
        pe = pefile.PE(path, fast_load=True)
        try:
            return int(pe.OPTIONAL_HEADER.SizeOfImage)
        finally:
            pe.close()
    except Exception:
        return None


def _main_image_range(debugger):
    """Return (start, end) load range of the MAIN executable, or None.

    Prefers the tracked module at ``debugger.image_base``; falls back to the PE
    SizeOfImage on ``debugger.exe_path`` (using image_base as the load base).
    """
    base = getattr(debugger, "image_base", None)
    if not base:
        return None
    syms = getattr(debugger, "symbols", None)
    if syms is not None:
        try:
            mod = syms.get_module_at(base)
            if mod is not None:
                return int(mod.base_address), int(mod.end_address)
        except Exception:
            pass
    size = _pe_size_of_image(getattr(debugger, "exe_path", None))
    if size:
        return int(base), int(base) + int(size)
    return None


def _is_prologue_at(insns, idx):
    """True if insns[idx] starts a common function prologue."""
    try:
        _, _, mn, op = insns[idx]
    except Exception:
        return False
    mnl = mn.lower()
    opl = op.lower().replace(" ", "")
    if mnl in ("endbr32", "endbr64"):
        return True
    if mnl == "push" and opl in ("ebp", "rbp"):
        nxt = insns[idx + 1] if idx + 1 < len(insns) else None
        if nxt is None:
            return True
        n_mn = nxt[2].lower()
        n_op = nxt[3].lower().replace(" ", "")
        if n_mn == "mov" and n_op in ("ebp,esp", "rbp,rsp"):
            return True
    return False


# --- Public API --------------------------------------------------------------

def is_user_code(debugger, addr):
    """True only if `addr` is inside the MAIN executable image range.

    Conservative: returns False whenever we cannot positively place the address
    inside the main image (so auto-mode never spams the LLM on library code).
    """
    try:
        rng = _main_image_range(debugger)
        if not rng:
            return False
        start, end = rng
        return start <= addr < end
    except Exception:
        return False


def _pdata_bounds(debugger, addr):
    """x64 .pdata RUNTIME_FUNCTION extent containing `addr`, or None."""
    syms = getattr(debugger, "symbols", None)
    if syms is None or not getattr(syms, "modules", None):
        return None
    mod = None
    for m in syms.modules:
        try:
            if m.base_address <= addr < m.end_address:
                mod = m
                break
        except Exception:
            continue
    if mod is None:
        return None
    try:
        from .seh import list_runtime_functions
        rfs = list_runtime_functions(mod.base_address, mod.path)
    except Exception:
        return None
    for rf in rfs:
        try:
            if rf["begin"] <= addr < rf["end"]:
                return int(rf["begin"]), int(rf["end"])
        except Exception:
            continue
    return None


def _discovered_bounds(debugger, addr):
    """Bounds from the debugger's auto-discovered function table, or None.

    Ensures analysis has run (guarded), locates the discovered function head
    at/below ``addr``, and returns ``(start, end)`` where ``end`` is the next
    discovered start above it (or the main-image end). Only trusts a start when
    both it and ``addr`` sit inside the main executable image.
    """
    try:
        debugger.analyze()
    except Exception:
        pass
    syms = getattr(debugger, "symbols", None)
    if syms is None:
        return None
    try:
        dc = syms.discovered_containing(addr)
    except Exception:
        dc = None
    if not dc:
        return None
    start, _name = dc

    rng = _main_image_range(debugger)
    if not rng:
        return None
    lo, hi = rng
    if not (lo <= start <= addr < hi):
        return None

    end = hi
    try:
        import bisect
        starts = getattr(syms, "_discovered_sorted", None) or []
        pos = bisect.bisect_right(starts, start)
        if pos < len(starts):
            nxt = starts[pos]
            if lo <= nxt <= hi:
                end = nxt
    except Exception:
        pass
    return int(start), int(end)


def _heuristic_bounds(debugger, addr, max_insns):
    """Scan backward to the nearest prologue and forward to the terminating ret."""
    # ---- backward: find the nearest prologue at/before addr ----
    back = 0x600
    scan_start = max(int(addr) - back, 0x1000)
    pre_size = (int(addr) - scan_start) + 16
    pre = _disasm_range(debugger, scan_start, pre_size, 4000)

    func_start = None
    if pre:
        for idx in range(len(pre)):
            iaddr = pre[idx][0]
            if iaddr > addr:
                break
            if _is_prologue_at(pre, idx):
                func_start = iaddr
    if func_start is None:
        func_start = max(int(addr) - 0x40, 0x1000)

    # ---- forward: disassemble from func_start until a top-level ret / next
    #      prologue, capped at max_insns / _MAX_SPAN_BYTES ----
    fwd_size = min(_MAX_SPAN_BYTES, max(64, max_insns * 15))
    fwd = _disasm_range(debugger, func_start, fwd_size, max_insns)

    if not fwd:
        return func_start, min(int(addr) + 0x200, func_start + _MAX_SPAN_BYTES)

    end = fwd[-1][0] + fwd[-1][1]
    for idx in range(len(fwd)):
        iaddr, isize, mn, op = fwd[idx]
        end = iaddr + isize
        mnl = mn.lower()
        # A terminating ret at or past our target closes the function.
        if mnl in ("ret", "retn", "retf") and iaddr >= addr:
            break
        # A fresh prologue after our target starts the next function.
        if iaddr > addr and _is_prologue_at(fwd, idx):
            end = iaddr
            break

    if end > func_start + _MAX_SPAN_BYTES:
        end = func_start + _MAX_SPAN_BYTES
    if end <= addr:
        end = min(int(addr) + 0x200, func_start + _MAX_SPAN_BYTES)
        if end <= addr:
            end = int(addr) + 0x200
    return func_start, end


def get_function_bounds(debugger, addr, max_insns=_DEFAULT_MAX_INSNS):
    """Return (start, end) for the function containing `addr`.

    Prefers auto-discovered function starts (works on stripped images), then
    x64 .pdata bounds, then a prologue/ret heuristic. Always returns a sane
    window with start <= addr < end, even when heuristics are weak (final
    fallback [addr-0x40 .. addr+0x200]).
    """
    # Discovered functions take priority: on a stripped image they are the only
    # reliable source of head/extent, and they also beat .pdata when present.
    try:
        b = _discovered_bounds(debugger, addr)
        if b is not None:
            start, end = b
            if end - start > _MAX_SPAN_BYTES:
                end = start + _MAX_SPAN_BYTES
            if start <= addr < end:
                return start, end
    except Exception:
        pass
    try:
        b = _pdata_bounds(debugger, addr)
        if b is not None:
            start, end = b
            if end - start > _MAX_SPAN_BYTES:
                end = start + _MAX_SPAN_BYTES
            if start <= addr < end:
                return start, end
    except Exception:
        pass
    try:
        start, end = _heuristic_bounds(debugger, addr, max_insns)
        if start <= addr < end:
            return start, end
    except Exception:
        pass
    return (int(addr) - 0x40, int(addr) + 0x200)


_HEX_RE = re.compile(r"0x[0-9A-Fa-f]+")


def _hex_imms(op):
    """Yield integer values of every hex token in an operand string."""
    out = []
    for t in _HEX_RE.findall(op or ""):
        try:
            out.append(int(t, 16))
        except ValueError:
            continue
    return out


def _string_at(debugger, imm):
    """Return a printable, NUL-terminated string that `imm` points at, or None.

    Conservative so we never mislabel a plain integer immediate as a string:
    the address must be plausible (>= 0x1000), the bytes must be readable, a
    NUL terminator must appear within the read window, and the decoded text
    must be at least two mostly-printable characters.
    """
    if imm is None or imm < 0x1000:
        return None
    data = _read(debugger, imm, 128)
    if not data:
        return None
    nul = data.find(b"\x00")
    if nul == -1:
        return None
    raw = data[:nul]
    if len(raw) < 2:
        return None
    try:
        s = raw.decode("utf-8")
    except Exception:
        try:
            s = raw.decode("latin-1")
        except Exception:
            return None
    if not s or not all(ch.isprintable() or ch in "\t" for ch in s):
        return None
    if len(s) > 60:
        s = s[:60] + "..."
    return s


def extract_disasm(debugger, start, end):
    """Disassemble [start, end) into annotated text lines.

    Each line: ``0xADDR:  mnemonic operands  ; note`` where the trailing note is
    the resolved symbol for a call/jmp/loop target, or the referenced string
    constant for any immediate operand that points at readable NUL-terminated
    text (so the model can recover e.g. ``system("...cmd.exe")``).
    """
    size = max(0, int(end) - int(start))
    if size <= 0:
        return ""
    size = min(size, _MAX_SPAN_BYTES)
    insns = _disasm_range(debugger, start, size, 100000)
    if not insns:
        return ""
    syms = getattr(debugger, "symbols", None)
    lines = []
    for iaddr, isize, mn, op in insns:
        if iaddr >= end:
            break
        line = f"{iaddr:#x}:  {mn} {op}".rstrip()
        note = ""
        mnl = mn.lower()
        is_branch = mnl == "call" or mnl.startswith("j") or mnl == "loop"
        if syms is not None and get_branch_target is not None and is_branch:
            try:
                tgt = get_branch_target(op)
            except Exception:
                tgt = None
            if tgt is not None:
                try:
                    s = syms.resolve_address(tgt)
                except Exception:
                    s = None
                if s:
                    note = f"  ; {s}"
        # For non-branch instructions (push/mov/lea/cmp/...), annotate any
        # immediate that points at a readable string constant. This is what
        # lets the model see `push 0x41b000  ; "...cmd.exe"` and reconstruct
        # the real call argument.
        if not note and not is_branch:
            for imm in _hex_imms(op):
                s = _string_at(debugger, imm)
                if s:
                    note = f'  ; "{s}"'
                    break
        lines.append(line + note)
    return "\n".join(lines)


def _decomp_dir():
    """Return (creating if needed) the on-disk decompile cache directory."""
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    d = os.path.join(base, "pwnWinDbg", "decomp")
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        pass
    return d


def _disk_load(key):
    """Load a cached result dict from disk, or None."""
    try:
        path = os.path.join(_decomp_dir(), key + ".json")
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict) or "code" not in data:
            return None
        amap = data.get("addr_map") or []
        data["addr_map"] = [(int(a), int(i)) for a, i in amap]
        if not isinstance(data.get("lines"), list):
            data["lines"] = (data.get("code") or "").split("\n")
        return data
    except Exception:
        return None


def _disk_save(key, result):
    """Persist a result dict to disk (best effort)."""
    try:
        path = os.path.join(_decomp_dir(), key + ".json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(result, fh)
    except Exception:
        pass


def _strip_fences(text):
    """Clean an LLM reply down to just the C body.

    Removes markdown code fences wherever they appear (models sometimes emit
    stray or multiple ``` lines) and drops obvious conversational prose lines
    (e.g. "Wait, let me correct ...") so a rambling reply degrades to usable C
    instead of polluting the live pane. Never raises.
    """
    t = (text or "").strip()
    if not t:
        return ""
    out = []
    for line in t.split("\n"):
        stripped = line.strip()
        # Drop any fence line (``` or ```c / ```cpp / ...).
        if stripped.startswith("```"):
            continue
        # Drop obvious meta / apology / narration lines. Code lines that end in
        # C punctuation, contain an address annotation, or are braces are kept.
        low = stripped.lower()
        if low.startswith((
            "wait", "let me", "here's", "here is", "note:", "note that",
            "i'll ", "i will ", "actually", "sorry", "apolog", "correction",
            "the function", "this function", "to strictly", "on second",
        )) and "// @" not in stripped and not stripped.endswith((";", "{", "}")):
            continue
        out.append(line)
    return "\n".join(out).strip("\n")


def _build_addr_map(lines):
    """Build a sorted [(addr, line_index), ...] map from // @0xADDR annotations."""
    out = []
    for idx, line in enumerate(lines):
        m = _ADDR_RE.search(line)
        if not m:
            continue
        try:
            a = int(m.group(1), 16)
        except ValueError:
            continue
        out.append((a, idx))
    out.sort(key=lambda t: t[0])
    return out


def _run_llm(cfg, user_prompt):
    """One-shot completion. Returns text or None on any provider error."""
    if create_session is None:
        return None
    try:
        sess = create_session(cfg or {}, DECOMPILE_SYSTEM)
        text = "".join(sess.send(user_prompt))
        return text if text and text.strip() else None
    except Exception:
        return None


def decompile_function(debugger, addr, force=False):
    """Decompile the function containing `addr`. Returns a result dict or None.

    Result dict shape::

        {"start": int, "end": int, "code": str,
         "lines": [str, ...], "addr_map": [(addr, line_index), ...]}

    In auto mode (force=False) library / non-main-image code returns None so the
    live context never fires an LLM call on system DLLs. Never raises.
    """
    try:
        if not force and not is_user_code(debugger, addr):
            return None

        cfg = {}
        if ai_config is not None:
            try:
                cfg = ai_config.load()
            except Exception:
                cfg = {}
        try:
            max_insns = int(cfg.get("decompile_max_insns", _DEFAULT_MAX_INSNS))
        except Exception:
            max_insns = _DEFAULT_MAX_INSNS

        start, end = get_function_bounds(debugger, addr, max_insns)
        if start is None or end is None or end <= start:
            return None

        func_bytes = _read(debugger, start, min(end - start, _MAX_SPAN_BYTES))
        if not func_bytes:
            return None

        key = f"{start:#x}_{hashlib.sha1(func_bytes).hexdigest()[:16]}"

        # Fast path: already decompiled this exact function body in memory.
        cached = _MEM_CACHE.get(key)
        if cached is not None:
            return cached

        # Recent failure? Skip re-hitting the LLM until the short TTL expires.
        exp = _FAIL_CACHE.get(key)
        if exp is not None:
            if time.monotonic() < exp:
                return None
            _FAIL_CACHE.pop(key, None)

        # Persistent on-disk cache (survives across runs).
        disk = _disk_load(key)
        if disk is not None:
            _MEM_CACHE[key] = disk
            return disk

        # Cache miss -> extract disasm and call the model.
        disasm = extract_disasm(debugger, start, end)
        if not disasm:
            return None

        text = _run_llm(cfg, disasm)
        if text is None:
            # Remember the failure briefly (memory only, never to disk).
            _FAIL_CACHE[key] = time.monotonic() + _FAIL_TTL
            return None

        text = _strip_fences(text)
        lines = text.split("\n")
        result = {
            "start": start,
            "end": end,
            "code": text,
            "lines": lines,
            "addr_map": _build_addr_map(lines),
        }
        _MEM_CACHE[key] = result
        _disk_save(key, result)
        return result
    except Exception:
        return None


def line_for_addr(result, addr):
    """Return the line index whose annotated addr is the greatest <= addr.

    None if there is no address map (or nothing at/below addr).
    """
    if not result:
        return None
    amap = result.get("addr_map") or []
    if not amap:
        return None
    best = None
    for a, idx in amap:
        if a <= addr:
            best = idx
        else:
            break
    return best
