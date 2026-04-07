"""`wt` — WinDbg-style watch-and-trace.

Single-step from the current RIP until the function returns, building
a tree of called functions with per-frame instruction counts. The
output is the canonical WinDbg `wt` table:

    self  child  [depth]   symbol
      17      0  [  0]     test_heap!main+0x1c
       4      0  [  1]       kernel32!HeapAlloc
       9      0  [  2]         ntdll!RtlAllocateHeap
       …

Where `self` is the number of instructions executed *directly* in this
frame (excluding nested calls) and `child` is the sum across all of
its descendants. The root row's child column is the trace's grand
total minus its own self-count.

Modes
-----
By default, `wt` single-steps **into** every call up to a depth limit,
then steps over deeper calls so the trace doesn't explode inside
runtime libraries. The defaults are intentionally conservative — pwn
sessions usually want depth=3 over a small target function, not a
20-level dive through ntdll.

Flags
-----
    -l <N>     Maximum nesting depth before we step over (default: 3)
    -i <N>     Hard cap on total instructions executed (default: 50000)
    -v         Verbose: also print every executed instruction live

Stop conditions
---------------
The trace ends when:
    * the original function returns (stack of frames pops to empty), OR
    * the instruction budget is exhausted, OR
    * we hit a user breakpoint, exception, or AV (we stop and report).

Examples
--------
    wt                       — trace from current rip with defaults
    wt -l 5                  — go up to 5 levels deep
    wt -l 1                  — only count instructions in the current
                               function (calls are summarized as 1)
    wt -i 5000               — bail after 5000 instructions
"""

import shlex

from ..core.debugger import DebuggerState
from ..core.disasm import (
    disassemble_at, is_call_instruction, is_ret_instruction,
)
from ..core.memory import read_memory_safe
from ..core.registers import get_context, get_ip, get_sp
from ..display.common import banner, console
from ..display.formatters import error, info, warn


# Sensible defaults: shallow enough to keep the trace useful, deep
# enough to see one or two layers of called helpers.
_DEFAULT_MAX_DEPTH = 3
_DEFAULT_MAX_INSN = 50_000


class _Frame:
    """One stack frame in the trace tree."""

    __slots__ = ("name", "addr", "depth", "self_count", "children")

    def __init__(self, name, addr, depth):
        self.name = name
        self.addr = addr
        self.depth = depth
        self.self_count = 0
        self.children = []

    def total(self):
        """Sum of self + all descendant self_counts."""
        return self.self_count + sum(c.total() for c in self.children)


def cmd_wt(debugger, args):
    """Single-step until the current function returns, then print a
    call-count tree à la WinDbg `wt`."""
    if debugger.state != DebuggerState.STOPPED:
        error("Process is not stopped")
        return None

    max_depth, max_insn, verbose, parse_err = _parse_args(args)
    if parse_err:
        error(parse_err)
        return None

    th = debugger.get_active_thread_handle()
    if not th:
        error("No active thread")
        return None
    ctx = get_context(th, debugger.is_wow64)
    start_rip = get_ip(ctx, debugger.is_wow64)

    root = _Frame(_resolve(debugger, start_rip), start_rip, 0)
    stack = [root]
    insn_count = 0
    stop_reason = "function returned"

    info(
        f"Tracing from {start_rip:#x} ({root.name})  "
        f"max_depth={max_depth}  max_insn={max_insn}"
    )

    while True:
        if insn_count >= max_insn:
            stop_reason = f"instruction budget reached ({max_insn})"
            break

        # Read the current instruction so we know whether the about-
        # to-execute opcode is a call/ret and how many bytes long.
        ctx = get_context(th, debugger.is_wow64)
        rip = get_ip(ctx, debugger.is_wow64)
        code = read_memory_safe(debugger.process_handle, rip, 16)
        if not code:
            stop_reason = f"unreadable code at {rip:#x}"
            break
        insns = disassemble_at(debugger.disassembler, code, rip, 1)
        if not insns:
            stop_reason = f"undecodable insn at {rip:#x}"
            break
        addr, size, mnemonic, op_str = insns[0]
        is_call = is_call_instruction(mnemonic)
        is_ret = is_ret_instruction(mnemonic)

        # Decide whether to step into or step over this instruction.
        # Beyond max_depth a call gets stepped over so we don't dive
        # into runtime helpers. We don't use the BP-based do_step_over
        # because the callee may re-enter a function the user has a
        # BP on (e.g. recursive HeapAlloc), and that would fire before
        # our return-site BP — leaving wt confused. Instead we use an
        # RSP-tracking single-step: execute the call, then single-step
        # until rsp climbs back to its pre-call value. The deeper-than
        # -max-depth instructions are NOT counted (matches WinDbg's
        # `wt -l` summarisation: the call is reported as 1 insn).
        stepping_over_call = is_call and len(stack) > max_depth
        ctx_pre = get_context(th, debugger.is_wow64)
        sp_pre = get_sp(ctx_pre, debugger.is_wow64)
        stop = debugger.do_step_into()

        # The instruction we *just* executed always counts toward the
        # current frame.
        stack[-1].self_count += 1
        insn_count += 1

        if verbose:
            safe_op = op_str.replace("[", r"\[")
            console.print(
                f"  [bright_black]\\[{len(stack)-1:2d}][/] "
                f"[bright_blue]{addr:#x}[/]  "
                f"[bright_white]{mnemonic} {safe_op}[/]"
            )

        if stop is None:
            stop_reason = "step returned no result"
            break
        reason = stop.get("reason")
        if reason != "single_step":
            stop_reason = f"stopped: {reason}"
            break

        # If we just stepped a call we want to skip past, drain the
        # callee by single-stepping until rsp >= sp_pre. We bound the
        # drain by the same global instruction budget.
        if stepping_over_call:
            drained, ok, drain_reason = _drain_callee(
                debugger, th, sp_pre, max_insn - insn_count,
            )
            if not ok:
                stop_reason = drain_reason
                break
            # Drained instructions are NOT charged to self_count or
            # insn_count — wt's contract is "1 instruction for the
            # whole call when stepped over". We do however charge the
            # drained count toward the global insn budget so a
            # runaway callee can't loop forever.
            insn_count += drained
            continue

        if is_call:
            # We dove into the callee. The new RIP is the first insn
            # of the callee — resolve it as the frame's name.
            ctx = get_context(th, debugger.is_wow64)
            new_rip = get_ip(ctx, debugger.is_wow64)
            stack.append(_Frame(_resolve(debugger, new_rip), new_rip, len(stack)))
            continue

        if is_ret:
            popped = stack.pop()
            if not stack:
                # The original function returned — done.
                root = popped
                break
            stack[-1].children.append(popped)

    # If we bailed early (budget, BP, etc) the live stack still holds
    # in-progress frames. Drain them top-down so the tree includes
    # every frame we entered, even unfinished ones.
    while len(stack) > 1:
        popped = stack.pop()
        stack[-1].children.append(popped)
    if stack:
        root = stack[0]

    # Pretty-print the resulting tree.
    _print_tree(root)
    info(
        f"Trace complete: {root.total()} instruction(s), "
        f"{_count_frames(root)} frame(s)  ({stop_reason})"
    )
    return None


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _drain_callee(debugger, th, sp_pre, budget):
    """Single-step until rsp >= sp_pre (i.e. the callee has returned).

    `sp_pre` is the stack pointer captured *before* the `call` was
    executed. After the `call`, rsp is `sp_pre - ptr_size` (the return
    address is on the stack). We single-step until rsp climbs back to
    `sp_pre`, which means the callee has executed its `ret`.

    The drain silently absorbs breakpoint hits inside the callee
    (e.g. a recursive call to a function the user has a BP on) — wt
    is in "step over" mode for this region and the user does not
    want execution to stop. Real exceptions (AV, etc.) still bail.

    Bounded by `budget`. Returns (count, ok, reason).
    """
    count = 0
    while True:
        if count >= budget:
            return count, False, f"step-over drain budget exhausted ({budget})"
        ctx = get_context(th, debugger.is_wow64)
        sp = get_sp(ctx, debugger.is_wow64)
        if sp >= sp_pre:
            return count, True, None
        stop = debugger.do_step_into()
        count += 1
        if stop is None:
            return count, False, "drain step returned no result"
        reason = stop.get("reason")
        if reason in ("single_step", "breakpoint"):
            # Either a clean step or we landed on a user BP. The BP
            # handler restored the original byte and set _step_over_bp,
            # so the next do_step_into will single-step past the
            # original instruction and re-arm the BP. Just loop.
            continue
        return count, False, f"drain stopped: {reason}"


def _parse_args(args):
    """Return (max_depth, max_insn, verbose, error_or_None)."""
    max_depth = _DEFAULT_MAX_DEPTH
    max_insn = _DEFAULT_MAX_INSN
    verbose = False
    try:
        toks = shlex.split(args)
    except ValueError as e:
        return max_depth, max_insn, verbose, f"parse error: {e}"

    i = 0
    while i < len(toks):
        t = toks[i]
        if t == "-l":
            if i + 1 >= len(toks):
                return max_depth, max_insn, verbose, "-l requires a value"
            try:
                max_depth = int(toks[i + 1], 0)
            except ValueError:
                return max_depth, max_insn, verbose, f"bad -l value: {toks[i+1]}"
            if max_depth < 0:
                return max_depth, max_insn, verbose, "-l must be >= 0"
            i += 2
        elif t == "-i":
            if i + 1 >= len(toks):
                return max_depth, max_insn, verbose, "-i requires a value"
            try:
                max_insn = int(toks[i + 1], 0)
            except ValueError:
                return max_depth, max_insn, verbose, f"bad -i value: {toks[i+1]}"
            if max_insn <= 0:
                return max_depth, max_insn, verbose, "-i must be > 0"
            i += 2
        elif t == "-v":
            verbose = True
            i += 1
        else:
            return max_depth, max_insn, verbose, f"unknown arg: {t}"
    return max_depth, max_insn, verbose, None


def _resolve(debugger, addr):
    """Resolve `addr` to a display name. Falls back to a hex literal."""
    if debugger.symbols:
        sym = debugger.symbols.resolve_address(addr)
        if sym:
            return sym
    return f"{addr:#x}"


def _count_frames(frame):
    return 1 + sum(_count_frames(c) for c in frame.children)


def _print_tree(root):
    banner("WT TRACE")
    rows = []
    _walk(root, rows)
    if not rows:
        return
    # Column widths chosen to match WinDbg's default output.
    for self_n, child_n, depth, name in rows:
        indent = "  " * depth
        console.print(
            f"  [bright_white]{self_n:6d}[/] "
            f"[bright_black]{child_n:6d}[/] "
            f"[bright_blue]\\[{depth:2d}][/] "
            f"{indent}[bright_yellow]{name}[/]"
        )


def _walk(frame, rows):
    """Append (self, child, depth, name) rows in pre-order."""
    child_total = sum(c.total() for c in frame.children)
    rows.append((frame.self_count, child_total, frame.depth, frame.name))
    for c in frame.children:
        _walk(c, rows)
