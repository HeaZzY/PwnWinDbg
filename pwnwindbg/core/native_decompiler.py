"""Fast NATIVE (no-LLM) x86 pseudo-C decompiler.

Runs instantly (pure capstone, no network) so the live context can show it on
every `si`/`ni`. Recovers stack variables, lifts each instruction to a readable
pseudo-C statement with register copy-propagation, annotates calls with their
resolved name + arguments, and — the differentiator over a static tool — shows
the RUNTIME values of the current call's arguments (from live regs/stack).

Control flow is emitted as labels + `if (cond) goto Lxxxx;` (correct and
readable); the on-demand LLM decompiler (`dc ai`) does full if/while/for
structuring. Result shape matches display/decompile_view.py:
    {"start","end","code","lines","addr_map":[(addr,line_idx)]}
"""

import hashlib
import re

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM
    _CAPSTONE = True
except Exception:  # pragma: no cover
    _CAPSTONE = False

from .memory import read_memory_safe

# structural cache: (start, sha1(bytes)) -> result dict (WITHOUT the live
# current-call annotation, which is re-applied per render).
_CACHE = {}

_CC_JCC = {
    "je": "==", "jz": "==", "jne": "!=", "jnz": "!=",
    "jl": "<", "jnge": "<", "jle": "<=", "jng": "<=",
    "jg": ">", "jnle": ">", "jge": ">=", "jnl": ">=",
    "jb": "<", "jnae": "<", "jc": "<", "jbe": "<=", "jna": "<=",
    "ja": ">", "jnbe": ">", "jae": ">=", "jnb": ">=", "jnc": ">=",
    "js": "< 0", "jns": ">= 0",
}


def _regs(debugger):
    r = debugger.get_registers()
    if isinstance(r, tuple):
        r = r[0]
    return r or {}


def _ip(debugger, regs):
    return regs.get("Eip") if debugger.is_wow64 else regs.get("Rip")


def _bounds(debugger, addr):
    try:
        from .decompiler import get_function_bounds
        return get_function_bounds(debugger, addr)
    except Exception:
        return (addr, addr + 0x200)


# --- operand / expression formatting --------------------------------------

class _Ctx:
    """Per-function lifting context."""
    def __init__(self, debugger, is64):
        self.debugger = debugger
        self.is64 = is64
        self.regexpr = {}      # reg name -> current expression string
        self.pushes = []       # pending pushed arg expressions (for the next call)
        self.stack_args = {}   # cdecl: sp-disp -> arg expr, folded into next call
        self.decls = {}        # var name -> (decl string) for the header
        self.arrays = set()     # var names used with an index -> arrays
        self.array_sizes = {}  # array var name -> inferred size in bytes


def _reg_name(insn, op):
    try:
        return insn.reg_name(op.reg)
    except Exception:
        return "reg"


def _sp_disp(ctx, insn, op):
    """If `op` is a plain `[esp+disp]`/`[rsp+disp]` (no index), return disp."""
    if op.type != X86_OP_MEM:
        return None
    m = op.mem
    if m.index != 0:
        return None
    base = insn.reg_name(m.base) if m.base != 0 else None
    sp = "esp" if not ctx.is64 else "rsp"
    return m.disp if base == sp else None


def _stringify(ctx, expr):
    """If `expr` is a bare pointer immediate to a readable C string, quote it."""
    if not isinstance(expr, str) or not re.match(r"^0x[0-9a-fA-F]+$", expr.strip()):
        return expr
    try:
        addr = int(expr.strip(), 16)
        data = read_memory_safe(getattr(ctx.debugger, "process_handle", None),
                                addr, 64)
    except Exception:
        return expr
    if not data:
        return expr
    nul = data.find(b"\x00")
    raw = data[:nul] if nul >= 0 else data
    if len(raw) < 2 or not all(0x20 <= b < 0x7f or b in (9, 10, 13) for b in raw):
        return expr
    text = raw.decode("ascii", "replace")
    for a, b in (("\\", "\\\\"), ('"', '\\"'), ("\n", "\\n"),
                 ("\t", "\\t"), ("\r", "\\r")):
        text = text.replace(a, b)
    if len(text) > 48:
        text = text[:48] + "..."
    return '"%s"' % text


def _fmt_imm(v):
    v &= 0xFFFFFFFFFFFFFFFF
    if v > 0x7FFFFFFF and v <= 0xFFFFFFFF:
        # show small negatives nicely
        sv = v - 0x100000000
        if -16 <= sv < 0:
            return str(sv)
    if v < 10:
        return str(v)
    return hex(v)


def _var_for_mem(ctx, insn, op):
    """Return a variable/deref expression for a memory operand, and register it."""
    m = op.mem
    base = insn.reg_name(m.base) if m.base != 0 else None
    index = insn.reg_name(m.index) if m.index != 0 else None
    disp = m.disp
    # ebp/rbp frame locals & args
    bp = "ebp" if not ctx.is64 else "rbp"
    sp = "esp" if not ctx.is64 else "rsp"
    if base == bp and index is None:
        if disp < 0:
            name = "v_%x" % (-disp)
            ctx.decls.setdefault(name, None)
            return name
        elif disp >= (8 if not ctx.is64 else 16):
            k = (disp - (8 if not ctx.is64 else 16)) // (4 if not ctx.is64 else 8) + 1
            return "a%d" % k
        else:
            return "*(saved_%x)" % disp
    if base == bp and index is not None:
        # array access v_N[index]
        name = "v_%x" % (-disp) if disp < 0 else "v_%x" % disp
        ctx.arrays.add(name)
        ctx.decls.setdefault(name, None)
        idx = ctx.regexpr.get(index, index)
        return "%s[%s]" % (name, idx)
    # generic [reg + disp]
    b = ctx.regexpr.get(base, base) if base else None
    parts = []
    if b:
        parts.append(b)
    if index:
        ix = ctx.regexpr.get(index, index)
        parts.append(ix if m.scale == 1 else "%s*%d" % (ix, m.scale))
    if disp:
        parts.append(_fmt_imm(disp & 0xFFFFFFFF))
    inner = " + ".join(parts) if parts else "0"
    return "*(%s)" % inner


def _opnd(ctx, insn, op):
    """Format one operand as a C expression (with copy-propagation)."""
    if op.type == X86_OP_REG:
        r = _reg_name(insn, op)
        return ctx.regexpr.get(r, r)
    if op.type == X86_OP_IMM:
        return _fmt_imm(op.imm)
    if op.type == X86_OP_MEM:
        return _var_for_mem(ctx, insn, op)
    return "?"


def _dest_reg(insn, op):
    if op.type == X86_OP_REG:
        return _reg_name(insn, op)
    return None


def _mem_addr(ctx, insn, op):
    """Address expression of a memory operand (for lea)."""
    expr = _var_for_mem(ctx, insn, op)
    if expr.startswith("*("):
        return expr[2:-1]          # *(X) -> X
    if expr.startswith("*"):
        return expr[1:]
    return "&" + expr              # &v_14 / &a1


_CALLER_SAVED = ("eax", "ecx", "edx", "rax", "rcx", "rdx", "r8", "r9",
                 "r10", "r11")


def _target_imm(insn):
    for op in insn.operands:
        if op.type == X86_OP_IMM:
            return op.imm
    return None


def _lift(ctx, insn, labels, cur_ip):
    """Return a list of C-statement strings for one instruction (no addr tag)."""
    m = insn.mnemonic
    ops = insn.operands
    try:
        if m in ("nop", "int3", "endbr32", "endbr64", "hlt", "fnop"):
            return []
        if m in ("push",):
            if ops:
                d = _dest_reg(insn, ops[0])
                if d in ("ebp", "esp", "rbp", "rsp"):
                    return []      # frame save, not a call argument
                ctx.pushes.append(_opnd(ctx, insn, ops[0]))
            return []
        if m in ("pop",):
            if ops:
                d = _dest_reg(insn, ops[0])
                if d:
                    ctx.regexpr.pop(d, None)
            return []
        if m in ("mov", "movzx", "movsx", "movsxd", "movaps", "movdqu", "movd", "movq"):
            if len(ops) == 2:
                d = _dest_reg(insn, ops[0])
                if d in ("ebp", "rbp"):
                    return []      # `mov ebp, esp` frame setup
                src = _opnd(ctx, insn, ops[1])
                if d:
                    ctx.regexpr[d] = src
                    return []          # folded into the register; no statement
                # cdecl arg: `mov [esp+k], val` -> fold into the next call.
                sd = _sp_disp(ctx, insn, ops[0])
                if sd is not None and sd >= 0:
                    ctx.stack_args[sd] = src
                    return []
                dst = _opnd(ctx, insn, ops[0])
                return ["%s = %s;" % (dst, src)]
        if m == "lea" and len(ops) == 2:
            addr = _mem_addr(ctx, insn, ops[1])
            d = _dest_reg(insn, ops[0])
            if d:
                ctx.regexpr[d] = addr
                return []
        if m in ("add", "sub", "and", "or", "xor", "shl", "shr", "sar",
                 "imul", "mul", "sal"):
            cop = {"add": "+", "sub": "-", "and": "&", "or": "|", "xor": "^",
                   "shl": "<<", "shr": ">>", "sar": ">>", "sal": "<<",
                   "imul": "*", "mul": "*"}[m]
            if len(ops) >= 2:
                d = _dest_reg(insn, ops[0])
                if d in ("esp", "rsp"):
                    return []      # hide stack-pointer cleanup (add/sub esp, N)
                src = _opnd(ctx, insn, ops[1])
                # `xor reg, reg` (same register) is a zero-idiom.
                if m == "xor" and d and ops[1].type == X86_OP_REG \
                        and _reg_name(insn, ops[1]) == d:
                    ctx.regexpr[d] = "0"
                    return []
                # For a register dest, print the register name (not its stale
                # folded value) so we never emit `0 += 0xf`.
                dst = d if d else _opnd(ctx, insn, ops[0])
                if d:
                    ctx.regexpr[d] = d      # stop folding after arithmetic
                return ["%s %s= %s;" % (dst, cop, src)]
        if m in ("inc", "dec") and ops:
            dst = _opnd(ctx, insn, ops[0])
            d = _dest_reg(insn, ops[0])
            if d:
                ctx.regexpr[d] = d
            return ["%s%s;" % (dst, "++" if m == "inc" else "--")]
        if m in ("neg", "not") and ops:
            dst = _opnd(ctx, insn, ops[0])
            return ["%s = %s%s;" % (dst, "-" if m == "neg" else "~", dst)]
        if m in ("cmp", "test") and len(ops) == 2:
            a = _opnd(ctx, insn, ops[0])
            b = _opnd(ctx, insn, ops[1])
            ctx.pending = ("test", a, b) if m == "test" else ("cmp", a, b)
            return []
        if m == "call":
            return _lift_call(ctx, insn, cur_ip)
        if m in _CC_JCC:
            tgt = _target_imm(insn)
            cond = _cond_expr(ctx, m)
            lbl = "L_%x" % tgt if tgt in labels else (hex(tgt) if tgt else "?")
            ctx.regexpr.clear()
            return ["if (%s) goto %s;" % (cond, lbl)]
        if m in ("jmp",):
            tgt = _target_imm(insn)
            ctx.regexpr.clear()
            if tgt in labels:
                return ["goto L_%x;" % tgt]
            if tgt is not None:
                return ["goto %s;  /* tailcall */" % _callee_name(ctx, tgt)]
            return ["goto *(%s);" % _opnd(ctx, insn, ops[0])]
        if m in ("ret", "retn"):
            eax = ctx.regexpr.get("eax") or ctx.regexpr.get("rax")
            return ["return %s;" % eax] if eax else ["return;"]
        if m in ("leave",):
            return []
        if m in ("loop", "loope", "loopne"):
            tgt = _target_imm(insn)
            return ["if (--ecx) goto L_%x;" % tgt] if tgt in labels else []
    except Exception:
        pass
    # Fallback: keep the raw asm so nothing is silently lost.
    return ["/* %s %s */" % (insn.mnemonic, insn.op_str)]


def _cond_expr(ctx, jcc):
    op = _CC_JCC.get(jcc, "!=")
    pend = getattr(ctx, "pending", None)
    if not pend:
        return "cond"
    kind, a, b = pend
    if kind == "test":
        if a == b:
            return "%s %s" % (a, op) if op.endswith("0") else "%s %s 0" % (a, op)
        return "(%s & %s) %s 0" % (a, b, op if op.endswith("0") is False else op)
    # cmp a, b
    if op.endswith("0"):
        return "%s %s" % (a, op)
    return "%s %s %s" % (a, op, b)


def _callee_name(ctx, tgt):
    try:
        n = ctx.debugger.symbols.resolve_address(tgt)
        if n:
            # strip module! prefix for readability
            return n.split("!", 1)[1] if "!" in n else n
    except Exception:
        pass
    return "sub_%X" % tgt


def _lift_call(ctx, insn, cur_ip):
    ops = insn.operands
    # resolve target name
    name = None
    tgt = None
    if ops and ops[0].type == X86_OP_IMM:
        tgt = ops[0].imm
        name = _callee_name(ctx, tgt)
    elif ops:
        name = "(%s)" % _opnd(ctx, insn, ops[0])
    else:
        name = "??"
    # C args come either from pushes (stdcall/MSVC) or from `mov [esp+k], val`
    # writes (cdecl/gcc). Pushes are in program order, so C order = reversed;
    # stack_args are keyed by offset, so ascending offset = arg order.
    if ctx.pushes:
        args = [_stringify(ctx, a) for a in reversed(ctx.pushes)]
    elif ctx.stack_args:
        args = [_stringify(ctx, ctx.stack_args[k])
                for k in sorted(ctx.stack_args)]
    else:
        args = []
    ctx.pushes = []
    ctx.stack_args = {}
    call_expr = "%s(%s)" % (name, ", ".join(args))
    # live runtime values for the CURRENT call
    live = ""
    if cur_ip is not None and insn.address == cur_ip:
        live = _live_args(ctx, name)
    # result flows into eax; clear caller-saved
    for r in _CALLER_SAVED:
        ctx.regexpr.pop(r, None)
    ctx.regexpr["eax"] = call_expr
    ctx.regexpr["rax"] = call_expr
    stmt = call_expr + ";"
    if live:
        stmt += "  // " + live
    return [stmt]


def _live_args(ctx, name):
    """Runtime values of the current call's args (the debugger differentiator)."""
    try:
        from .call_args import resolve_call_args
        proto = None
        try:
            from .api_protos import lookup
            base = name.split("(")[0]
            proto = lookup(base)
        except Exception:
            proto = None
        regs = _regs(ctx.debugger)
        arglist = resolve_call_args(ctx.debugger, regs, num_args=4, proto=proto)
        parts = []
        for a in arglist[:6]:
            try:
                nm, val, ann = a
            except Exception:
                continue
            if ann:
                parts.append("%s=%#x %s" % (nm, val & 0xFFFFFFFFFFFFFFFF, ann))
            else:
                parts.append("%s=%#x" % (nm, val & 0xFFFFFFFFFFFFFFFF))
        return "args: " + ", ".join(parts) if parts else ""
    except Exception:
        return ""


_INIT_RE = re.compile(r"^\s*v_([0-9a-f]+) = (?:0|ax|al|eax|ecx|edx|xmm0);?\s*$")


def _collapse_init(body, ctx):
    """Collapse an unrolled zero-init run into a single memset(&buf, 0, N)."""
    out = []
    i = 0
    n = len(body)
    while i < n:
        m = _INIT_RE.match(body[i][1])
        if m:
            j = i
            offs = []
            while j < n:
                mj = _INIT_RE.match(body[j][1])
                if not mj:
                    break
                offs.append(int(mj.group(1), 16))
                j += 1
            if len(offs) >= 3:
                base_off = max(offs)
                size = base_off - min(offs) + 1
                base = "v_%x" % base_off
                ctx.arrays.add(base)
                ctx.array_sizes[base] = size
                for o in offs:
                    if o != base_off:
                        ctx.decls.pop("v_%x" % o, None)
                out.append((body[i][0], "    memset(&%s, 0, %#x);" % (base, size)))
                i = j
                continue
        out.append(body[i])
        i += 1
    return out


def _classify(addr, text):
    """Classify a body line into a structural item for the structurer."""
    t = text.strip()
    if t.endswith(":") and t.startswith("L_"):
        return {"k": "label", "name": t[:-1], "addr": addr, "text": text}
    if t.startswith("if (") and "goto L_" in t:
        cond = t[4:t.rindex(")")] if ")" in t else "cond"
        # `if (COND) goto L_x;`
        try:
            cond = t[t.index("(") + 1:t.rindex(") goto")]
        except Exception:
            pass
        tgt = t.split("goto", 1)[1].strip().rstrip(";").strip()
        return {"k": "ifgoto", "cond": cond, "target": tgt, "addr": addr, "text": text}
    if t.startswith("goto L_"):
        tgt = t.split("goto", 1)[1].strip().rstrip(";").strip()
        return {"k": "goto", "target": tgt, "addr": addr, "text": text}
    if t.startswith("return"):
        return {"k": "ret", "addr": addr, "text": text}
    return {"k": "stmt", "addr": addr, "text": text}


_ALIGN_ADD = re.compile(r"^\s*(\w+) \+= 0xf;\s*$")


def _strip_align_probe(body):
    """Drop GCC's ``__main``/alloca stack-alignment idiom, which Hex-Rays elides.

    It compiles to ``reg = 0; reg += 0xf (x1-2); reg >>= 4; reg <<= 4;`` and an
    optional spill to a dead local -- a rounded constant used only as an alloca
    probe size. We recognize the ``>>= 4`` + ``<<= 4`` signature and remove it.
    """
    out, i, n = [], 0, len(body)
    while i < n:
        m = _ALIGN_ADD.match(body[i][1])
        if m:
            reg = m.group(1)
            j = i
            while j < n:
                mm = _ALIGN_ADD.match(body[j][1])
                if not mm or mm.group(1) != reg:
                    break
                j += 1
            if (j + 1 < n and body[j][1].strip() == "%s >>= 4;" % reg
                    and body[j + 1][1].strip() == "%s <<= 4;" % reg):
                j += 2
                if j < n and re.match(r"^\s*v_[0-9a-f]+ = %s;\s*$" % reg,
                                      body[j][1]):
                    j += 1
                i = j          # skip the whole idiom
                continue
        out.append(body[i])
        i += 1
    return out


def _dedup_call_in_branch(body):
    """Drop a standalone ``EXPR;`` when the next line is ``if (EXPR ...)``.

    A call whose result is immediately tested (``strcmp(...); if (strcmp(...) ==
    0)``) is emitted twice; keep only the inlined form inside the branch.
    """
    out, i, n = [], 0, len(body)
    while i < n:
        cur = body[i][1].strip()
        if i + 1 < n and cur.endswith(");"):
            expr = cur[:-1]                       # "NAME(args)"
            nxt = body[i + 1][1].strip()
            if nxt.startswith("if (" + expr + " ") or \
                    nxt.startswith("if (" + expr + ")"):
                i += 1                            # inlined in the branch
                continue
        out.append(body[i])
        i += 1
    return out


def _label_uses(items):
    uses = {}
    for it in items:
        if it["k"] in ("goto", "ifgoto"):
            uses[it["target"]] = uses.get(it["target"], 0) + 1
    return uses


def _invert(cond):
    cond = cond.strip()
    inv = {"==": "!=", "!=": "==", "<": ">=", ">=": "<", ">": "<=", "<=": ">"}
    for op in ("==", "!=", "<=", ">=", "<", ">"):
        if (" %s " % op) in cond:
            a, b = cond.split(" %s " % op, 1)
            return "%s %s %s" % (a, inv[op], b)
    if cond.endswith(">= 0"):
        return cond[:-4] + "< 0"
    if cond.endswith("< 0"):
        return cond[:-3] + ">= 0"
    return "!(%s)" % cond


def _structure(body):
    """Rewrite the flat (addr,text) body into structured C with real blocks.

    Recognizes for/while loops and if / if-else diamonds, emitting braces
    (`if (c) { ... } else { ... }`) instead of `if (c) goto L; ... L:` wherever
    the jump targets are single-use and the spanned regions are brace-balanced.
    Nested control flow is folded inside-out over repeated passes. Irreducible
    flow degrades gracefully to label + goto. Returns a list of (addr_or_None,
    text) with indentation baked in. Guarded — returns the flat form on failure.
    """
    try:
        items = [_classify(a, t) for (a, t) in body]

        def _scan(start, n, want_kind, want_name, bail_kinds):
            """Index of the first *depth-0* item of `want_kind` (name matched via
            its ``name``/``target``), skipping over balanced open/close blocks.
            Returns None if a depth-0 ``bail_kinds`` item — or a same-kind item
            with the wrong name (a crossing boundary) — is hit first."""
            depth = 0
            for k in range(start, n):
                it = items[k]
                kk = it["k"]
                if depth == 0:
                    if kk == want_kind:
                        if (want_name is None
                                or it.get("name") == want_name
                                or it.get("target") == want_name):
                            return k
                        return None      # right kind, wrong name -> crossing
                    if kk in bail_kinds:
                        return None
                if kk == "open":
                    depth += 1
                elif kk == "close":
                    depth -= 1
                    if depth < 0:
                        return None
            return None

        changed = True
        passes = 0
        while changed and passes < 200:
            changed = False
            passes += 1
            uses = _label_uses(items)
            n = len(items)

            # --- for-loop:  init? ; goto Lc ; Lb: incr ; Lc: if(Cexit) goto La ;
            #                body ; goto Lb ; La:
            for i in range(n):
                if items[i]["k"] != "goto":
                    continue
                Lc = items[i]["target"]
                # find Lb label right after i
                j = i + 1
                if j >= n or items[j]["k"] != "label":
                    continue
                Lb = items[j]["name"]
                # find Lc label
                kc = None
                for k in range(j + 1, n):
                    if items[k]["k"] == "label" and items[k]["name"] == Lc:
                        kc = k
                        break
                if kc is None:
                    continue
                incr = items[j + 1:kc]
                if any(x["k"] not in ("stmt",) for x in incr):
                    continue
                # keep only the real increment expr(s) (drop copy-prop artifacts)
                incr_real = [x for x in incr if any(
                    op in x["text"] for op in ("+=", "-=", "++", "--"))]
                if incr_real:
                    incr = incr_real
                # Lc must be followed by if(Cexit) goto La
                if kc + 1 >= n or items[kc + 1]["k"] != "ifgoto":
                    continue
                guard = items[kc + 1]
                La = guard["target"]
                # body until `goto Lb`
                ke = None
                for k in range(kc + 2, n):
                    if items[k]["k"] == "goto" and items[k]["target"] == Lb:
                        ke = k
                        break
                    if items[k]["k"] == "label":
                        break
                if ke is None:
                    continue
                body_items = items[kc + 2:ke]
                if any(x["k"] == "label" for x in body_items):
                    continue
                # La label should follow the goto Lb
                if ke + 1 >= n or items[ke + 1]["k"] != "label" or \
                        items[ke + 1]["name"] != La:
                    continue
                # labels Lb/Lc must only be used by this loop
                if uses.get(Lb, 0) != 1 or uses.get(Lc, 0) != 1:
                    continue
                init = None
                # optional init: the stmt immediately before `goto Lc`
                start = i
                if i > 0 and items[i - 1]["k"] == "stmt":
                    init = items[i - 1]
                    start = i - 1
                incr_txt = ", ".join(x["text"].strip().rstrip(";") for x in incr)
                cond = _invert(guard["cond"])
                head_addr = guard["addr"]
                new = []
                if init is not None:
                    new.append({"k": "for", "text": "for (%s; %s; %s) {" % (
                        init["text"].strip().rstrip(";"), cond, incr_txt),
                        "addr": head_addr})
                else:
                    new.append({"k": "for", "text": "while (%s) {" % cond,
                                "addr": head_addr})
                new.append({"k": "open"})
                for x in body_items:
                    new.append(x)
                new.append({"k": "close", "text": "}"})
                items = items[:start] + new + items[ke + 2:]
                changed = True
                break
            if changed:
                continue

            # --- general loop with a single back-edge (test-first while):
            #     Lstart: <cond+body, exits via `goto Lend`> ; goto Lstart ; Lend:
            #   -> while (1) { ...; if (Cexit) break; ...; if (Cback) continue; }
            uses = _label_uses(items)
            n = len(items)
            for s in range(n):
                if items[s]["k"] != "label":
                    continue
                Lstart = items[s]["name"]
                # back-edge `goto Lstart` at depth 0 after s
                depth = 0
                b = None
                for k in range(s + 1, n):
                    kk = items[k]["k"]
                    if depth == 0 and kk == "goto" \
                            and items[k]["target"] == Lstart:
                        b = k
                        break
                    if kk == "open":
                        depth += 1
                    elif kk == "close":
                        depth -= 1
                        if depth < 0:
                            break
                if b is None:
                    continue
                # the fall-through label after the back-edge = the break target
                if b + 1 >= n or items[b + 1]["k"] != "label":
                    continue
                Lend = items[b + 1]["name"]
                loop_body = items[s + 1:b]
                # body must be brace-balanced and only escape to Lend / Lstart
                depth = 0
                okbody = True
                for x in loop_body:
                    kk = x["k"]
                    if kk == "open":
                        depth += 1
                    elif kk == "close":
                        depth -= 1
                    elif depth == 0:
                        if kk == "label":
                            okbody = False
                            break
                        if kk in ("goto", "ifgoto") \
                                and x.get("target") not in (Lend, Lstart):
                            okbody = False
                            break
                    if depth < 0:
                        okbody = False
                        break
                if not okbody or depth != 0:
                    continue
                # the loop head must only be re-entered by this back-edge
                if uses.get(Lstart, 0) != 1:
                    continue
                # rewrite escapes: ->Lend => break, ->Lstart => continue
                new_body = []
                d2 = 0
                for x in loop_body:
                    kk = x["k"]
                    if d2 == 0 and kk in ("goto", "ifgoto"):
                        kw = "break" if x.get("target") == Lend else "continue"
                        if kk == "goto":
                            new_body.append({"k": "stmt", "text": kw + ";",
                                             "addr": x.get("addr")})
                        else:
                            new_body.append({"k": "stmt", "addr": x.get("addr"),
                                             "text": "if (%s) %s;" % (x["cond"], kw)})
                    else:
                        new_body.append(x)
                    if kk == "open":
                        d2 += 1
                    elif kk == "close":
                        d2 -= 1
                head = {"k": "for", "text": "while (1) {",
                        "addr": items[s].get("addr")}
                new = [head, {"k": "open"}] + new_body + [{"k": "close", "text": "}"}]
                items = items[:s] + new + items[b + 1:]
                changed = True
                break
            if changed:
                continue

            # --- if / else diamond:
            #     if(C) goto Lt ; <else> ; goto Le ; Lt: <then> ; Le:
            uses = _label_uses(items)
            n = len(items)
            for i in range(n):
                if items[i]["k"] != "ifgoto":
                    continue
                Lt = items[i]["target"]
                # else-body ends at the first depth-0 `goto Le`
                g = _scan(i + 1, n, "goto", None, ("label", "ifgoto", "ret"))
                if g is None:
                    continue
                Le = items[g]["target"]
                if Le == Lt:
                    continue
                # that `goto Le` must be immediately followed by `label Lt`
                if g + 1 >= n or items[g + 1]["k"] != "label" \
                        or items[g + 1]["name"] != Lt:
                    continue
                # then-body ends at the first depth-0 `label Le`
                le = _scan(g + 2, n, "label", Le, ("goto", "ifgoto"))
                if le is None:
                    continue
                if uses.get(Lt, 0) != 1 or uses.get(Le, 0) != 1:
                    continue
                else_body = items[i + 1:g]
                then_body = items[g + 2:le]
                if not then_body and not else_body:
                    continue
                addr = items[i]["addr"]
                if then_body:
                    new = [{"k": "if", "text": "if (%s) {" % items[i]["cond"],
                            "addr": addr}, {"k": "open"}]
                    new += then_body
                    if else_body:
                        new.append({"k": "close_else", "text": "} else {",
                                    "addr": None})
                        new += else_body
                    new.append({"k": "close", "text": "}"})
                else:
                    # empty then -> invert and keep only the else body
                    new = [{"k": "if",
                            "text": "if (%s) {" % _invert(items[i]["cond"]),
                            "addr": addr}, {"k": "open"}]
                    new += else_body
                    new.append({"k": "close", "text": "}"})
                items = items[:i] + new + items[le + 1:]
                changed = True
                break
            if changed:
                continue

            # --- simple if (no else):  if(C) goto Lx ; <body> ; Lx: ---
            uses = _label_uses(items)
            n = len(items)
            for i in range(n):
                if items[i]["k"] != "ifgoto":
                    continue
                Lx = items[i]["target"]
                kx = _scan(i + 1, n, "label", Lx, ("goto", "ifgoto"))
                if kx is None:
                    continue
                inner = items[i + 1:kx]
                if not inner or uses.get(Lx, 0) != 1:
                    continue
                new = [{"k": "if", "text": "if (%s) {" % _invert(items[i]["cond"]),
                        "addr": items[i]["addr"]}, {"k": "open"}]
                new += inner
                new.append({"k": "close", "text": "}"})
                items = items[:i] + new + items[kx + 1:]
                changed = True
                break

        # Drop labels nothing jumps to anymore (structuring consumed them).
        final_uses = _label_uses(items)
        items = [it for it in items
                 if it["k"] != "label" or final_uses.get(it.get("name"), 0) > 0]

        # Flatten with indentation.
        out = []
        indent = 1
        for it in items:
            k = it["k"]
            if k == "open":
                indent += 1
                continue
            if k == "close":
                indent = max(1, indent - 1)
                out.append((None, "    " * indent + "}"))
                continue
            if k == "close_else":
                indent = max(1, indent - 1)
                out.append((it.get("addr"), "    " * indent + "} else {"))
                indent += 1
                continue
            if k == "label":
                out.append((None, it["text"]))
                continue
            pad = "    " * indent
            if k in ("for", "if"):
                out.append((it.get("addr"), pad + it["text"]))
            else:
                out.append((it.get("addr"), pad + it["text"].strip()))
        return out
    except Exception:
        return [(a, "    " + t.strip()) if not t.strip().endswith(":")
                else (None, t) for (a, t) in body]


def decompile_native(debugger, addr, max_insns=400):
    """Fast native pseudo-C for the function containing `addr`. Never raises."""
    if not _CAPSTONE:
        return None
    try:
        start, end = _bounds(debugger, addr)
        if not start or end <= start:
            return None
        size = min(end - start, 0x2000)
        code = read_memory_safe(getattr(debugger, "process_handle", None), start, size)
        if not code:
            return None

        regs = _regs(debugger)
        cur_ip = _ip(debugger, regs)
        is64 = not debugger.is_wow64
        md = Cs(CS_ARCH_X86, CS_MODE_64 if is64 else CS_MODE_32)
        md.detail = True
        insns = list(md.disasm(code, start))[:max_insns]
        if not insns:
            return None

        # branch-target labels
        labels = set()
        for ins in insns:
            mn = ins.mnemonic
            if mn in _CC_JCC or mn in ("jmp", "loop", "loope", "loopne"):
                t = _target_imm(ins)
                if t is not None and start <= t < end:
                    labels.add(t)

        # cache key on the structural part
        key = (start, hashlib.sha1(code[:end - start]).hexdigest()[:16])
        cached = _CACHE.get(key)

        name = _callee_name_for_start(debugger, start)
        if cached is None:
            ctx = _Ctx(debugger, is64)
            # skip standard prologue for readability
            body = []           # (addr, text)
            addr_map = []
            for ins in insns:
                # emit label
                if ins.address in labels:
                    body.append((ins.address, "L_%x:" % ins.address))
                stmts = _lift(ctx, ins, labels, None)  # structural pass: no live
                for s in stmts:
                    body.append((ins.address, "    " + s))
            body = _collapse_init(body, ctx)   # unrolled zero-init -> memset()
            body = _strip_align_probe(body)    # drop GCC stack-align idiom
            body = _dedup_call_in_branch(body)  # call+if(call) -> just the if
            # header
            decls = []
            for v in sorted(ctx.decls):
                if v in ctx.arrays:
                    sz = ctx.array_sizes.get(v)
                    decls.append("    char %s[%s];" % (
                        v, ("%#x" % sz) if sz else "/*?*/"))
                else:
                    decls.append("    int %s;" % v)
            header = ["%s()" % name, "{"] + decls + ([""] if decls else [])
            # Structure the flat goto body into for/while/if where recognizable.
            structured = _structure(body)
            out_lines = list(header)
            amap = []
            for a, t in structured:
                if a is None:
                    out_lines.append(t)
                else:
                    amap.append((a, len(out_lines)))
                    out_lines.append("%s // @0x%x" % (t, a))
            out_lines.append("}")
            result = {
                "start": start, "end": end,
                "code": "\n".join(out_lines),
                "lines": out_lines,
                "addr_map": amap,
            }
            _CACHE[key] = result
            cached = result

        # Re-apply the CURRENT-call live annotation fresh (not cached), by
        # recomputing just for the current ip's call line.
        result = _with_live(debugger, cached, cur_ip, is64)
        return result
    except Exception:
        return None


def _callee_name_for_start(debugger, start):
    try:
        n = debugger.symbols.resolve_address(start)
        if n and "!" in n:
            nm = n.split("!", 1)[1]
            if "+" not in nm:
                return nm
    except Exception:
        pass
    return "sub_%X" % start


def _with_live(debugger, cached, cur_ip, is64):
    """Return a copy of `cached` with a live arg comment on the current line."""
    if cur_ip is None:
        return cached
    try:
        line_idx = None
        for a, idx in cached.get("addr_map", []):
            if a == cur_ip:
                line_idx = idx
                break
        if line_idx is None:
            return cached
        lines = list(cached["lines"])
        ln = lines[line_idx]
        if "// live:" in ln:
            return cached
        # only annotate call lines
        if "(" in ln and ")" in ln:
            # recompute live args using a throwaway ctx
            ctx = _Ctx(debugger, is64)
            # name = text before '('
            base = ln.strip().split("(")[0]
            live = _live_args(ctx, base)
            if live:
                lines[line_idx] = ln + "   // live: " + live
        new = dict(cached)
        new["lines"] = lines
        new["code"] = "\n".join(lines)
        return new
    except Exception:
        return cached
