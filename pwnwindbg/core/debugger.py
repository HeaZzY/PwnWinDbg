"""Core debugger: Windows Debug API loop, event handling, process management."""

import ctypes
import os
import struct
import threading
from ctypes import byref, sizeof

from ..utils.constants import (
    kernel32, DEBUG_EVENT, STARTUPINFOW, PROCESS_INFORMATION,
    DEBUG_PROCESS, DEBUG_ONLY_THIS_PROCESS, CREATE_NEW_CONSOLE,
    CREATE_NEW_PROCESS_GROUP, STARTF_USESTDHANDLES,
    INFINITE, DWORD, BOOL, HANDLE, PVOID,
    EXCEPTION_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT,
    CREATE_PROCESS_DEBUG_EVENT, EXIT_THREAD_DEBUG_EVENT,
    EXIT_PROCESS_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT,
    UNLOAD_DLL_DEBUG_EVENT, OUTPUT_DEBUG_STRING_EVENT, RIP_EVENT,
    EXCEPTION_BREAKPOINT, EXCEPTION_SINGLE_STEP,
    EXCEPTION_ACCESS_VIOLATION, STATUS_WX86_BREAKPOINT,
    STATUS_WX86_SINGLE_STEP,
    DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED,
    PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
    EFLAGS_TF,
    MAX_PATH,
)
from .memory import read_memory_safe, read_wstring
from .registers import (
    get_context, set_context, get_ip, set_ip, get_sp, get_bp,
    set_trap_flag, clear_trap_flag, set_resume_flag,
    context_to_dict, diff_registers,
)
from .breakpoints import BreakpointManager
from .watchpoints import WatchpointManager
from .symbols import SymbolManager
from .disasm import create_disassembler, disassemble_at


class DebuggerState:
    """Tracks current debugger state."""

    IDLE = "idle"
    RUNNING = "running"
    STOPPED = "stopped"
    TERMINATED = "terminated"


class Debugger:
    """Windows userland debugger engine."""

    def __init__(self):
        # Process state
        self.process_handle = None
        self.process_id = None
        self.main_thread_handle = None
        self.main_thread_id = None
        self.exe_path = None
        self.image_base = None

        # Architecture
        self.is_wow64 = False  # True if debugging a 32-bit process on 64-bit OS
        self.ptr_size = 8      # pointer size in bytes

        # Thread tracking
        self.threads = {}  # tid -> thread_handle
        self.active_thread_id = None

        # Module tracking
        self.symbols = SymbolManager()

        # Breakpoint management
        self.bp_manager = BreakpointManager()

        # Hardware watchpoint management (DR0-DR3)
        self.wp_manager = WatchpointManager()
        # Set when an EXCEPTION_SINGLE_STEP is the result of a watchpoint
        # rather than a user single-step.
        self._last_wp_hit = None

        # Disassembler
        self.disassembler = None

        # State
        self.state = DebuggerState.IDLE
        self.first_breakpoint_hit = False  # The system initial breakpoint
        self._initial_bp_count = 0  # WoW64 processes get 2 initial BPs

        # Register tracking (for change highlighting)
        self.prev_regs = None

        # Single-step state
        self._single_stepping = False
        self._step_over_bp = None  # BP to re-enable after single-step
        self._step_type = None     # "si", "ni", or "finish"
        self._finish_bp = None     # Temp BP for finish command
        self._ni_return_addr = None  # For step-over: address after call

        # Debug event
        self.last_event = None
        self.last_exception_code = None
        self.last_exception_addr = None

        # Loaded DLL tracking for name resolution
        self._dll_handles = {}  # base_addr -> hFile

        # Library-load catchpoints: substrings (case-insensitive) that, when
        # matched against a freshly-loaded DLL's path/name, cause a stop.
        # Populated by `catch load <pattern>` from commands/catch_cmds.py.
        self.catch_load_patterns = []

        # Interrupt flag (set by Ctrl+C handler from another thread)
        self._interrupt_requested = False

        # Auto-advance for repeating examine commands (tel, x/, disasm)
        # key -> (original_requested_addr, next_addr)
        self._examine_next = {}

    def spawn(self, exe_path, args="", stdin_file=None):
        """Spawn a new process under the debugger.
        stdin_file: path to a file to redirect as the process stdin.
        """
        si = STARTUPINFOW()
        si.cb = sizeof(si)
        pi = PROCESS_INFORMATION()

        cmd_line = f'"{exe_path}"'
        if args:
            cmd_line += f" {args}"

        # Separate console so Ctrl+C only affects pwnWinDbg
        flags = DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE

        inherit_handles = False
        stdin_handle = None

        if stdin_file:
            # Open file as inheritable handle for child stdin
            import msvcrt
            GENERIC_READ = 0x80000000
            FILE_SHARE_READ = 0x00000001
            OPEN_EXISTING = 3
            FILE_ATTRIBUTE_NORMAL = 0x80

            # SECURITY_ATTRIBUTES with bInheritHandle=True
            class SECURITY_ATTRIBUTES(ctypes.Structure):
                _fields_ = [
                    ("nLength", DWORD),
                    ("lpSecurityDescriptor", PVOID),
                    ("bInheritHandle", BOOL),
                ]

            sa = SECURITY_ATTRIBUTES()
            sa.nLength = sizeof(sa)
            sa.lpSecurityDescriptor = None
            sa.bInheritHandle = True

            stdin_handle = kernel32.CreateFileW(
                stdin_file,
                GENERIC_READ,
                FILE_SHARE_READ,
                byref(sa),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
            if not stdin_handle or stdin_handle == -1:
                raise RuntimeError(f"Cannot open stdin file: {stdin_file}")

            si.dwFlags |= STARTF_USESTDHANDLES
            si.hStdInput = stdin_handle
            # Inherit current stdout/stderr
            si.hStdOutput = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            si.hStdError = kernel32.GetStdHandle(-12)   # STD_ERROR_HANDLE
            inherit_handles = True

        ok = kernel32.CreateProcessW(
            None,
            cmd_line,
            None, None, inherit_handles,
            flags,
            None, None,
            byref(si), byref(pi),
        )

        # Close the stdin file handle in our process (child has its own copy)
        if stdin_handle and stdin_handle != -1:
            kernel32.CloseHandle(stdin_handle)

        if not ok:
            err = ctypes.GetLastError()
            raise RuntimeError(f"CreateProcessW failed (err={err})")

        self.process_handle = pi.hProcess
        self.process_id = pi.dwProcessId
        self.main_thread_handle = pi.hThread
        self.main_thread_id = pi.dwThreadId
        self.exe_path = os.path.abspath(exe_path)
        self.active_thread_id = pi.dwThreadId
        self.threads[pi.dwThreadId] = pi.hThread

        # Detect WoW64
        self._detect_wow64()

        # Init disassembler
        self.disassembler = create_disassembler(self.is_wow64)

        # Init symbols
        self.symbols.init_dbghelp(self.process_handle)

        self.state = DebuggerState.RUNNING
        self.first_breakpoint_hit = False

        return True

    def attach(self, pid):
        """Attach to a running process."""
        # Set kill-on-exit to false so the process survives detach
        kernel32.DebugSetProcessKillOnExit(False)

        ok = kernel32.DebugActiveProcess(pid)
        if not ok:
            err = ctypes.GetLastError()
            raise RuntimeError(f"DebugActiveProcess failed (err={err})")

        self.process_id = pid
        self.process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not self.process_handle:
            raise RuntimeError(f"OpenProcess failed (err={ctypes.GetLastError()})")

        self._detect_wow64()
        self.disassembler = create_disassembler(self.is_wow64)
        self.symbols.init_dbghelp(self.process_handle)

        self.state = DebuggerState.RUNNING
        self.first_breakpoint_hit = False
        self.active_thread_id = None  # Will be set on first event

        return True

    def detach(self):
        """Detach from the process."""
        if self.process_id:
            # Remove all breakpoints first
            if self.process_handle:
                self.bp_manager.clear_all(self.process_handle)
            kernel32.DebugActiveProcessStop(self.process_id)
        self._cleanup()

    def terminate(self):
        """Terminate the debugged process."""
        if self.process_handle:
            self.bp_manager.clear_all(self.process_handle)
            kernel32.TerminateProcess(self.process_handle, 1)
        self._cleanup()

    def _cleanup(self):
        """Clean up handles and state."""
        # Drop per-module caches that were populated for this target
        try:
            from .seh import invalidate_pdata_cache
            invalidate_pdata_cache()
        except Exception:
            pass
        self.symbols.cleanup()
        for tid, th in self.threads.items():
            if th and th != self.main_thread_handle:
                try:
                    kernel32.CloseHandle(th)
                except Exception:
                    pass
        if self.main_thread_handle:
            try:
                kernel32.CloseHandle(self.main_thread_handle)
            except Exception:
                pass
        if self.process_handle:
            try:
                kernel32.CloseHandle(self.process_handle)
            except Exception:
                pass
        self.threads.clear()
        self.state = DebuggerState.TERMINATED

    def _detect_wow64(self):
        """Detect if the target is a WoW64 (32-bit) process."""
        is_wow = BOOL(False)
        kernel32.IsWow64Process(self.process_handle, byref(is_wow))
        self.is_wow64 = bool(is_wow.value)
        self.ptr_size = 4 if self.is_wow64 else 8

    def get_active_thread_handle(self):
        """Get the handle for the currently active thread."""
        if self.active_thread_id in self.threads:
            return self.threads[self.active_thread_id]
        # Try to open it
        th = kernel32.OpenThread(THREAD_ALL_ACCESS, False, self.active_thread_id)
        if th:
            self.threads[self.active_thread_id] = th
            return th
        return None

    # -----------------------------------------------------------------
    # Debug loop
    # -----------------------------------------------------------------

    def wait_for_event(self, timeout=INFINITE):
        """Wait for a debug event. Returns the event or None on timeout."""
        event = DEBUG_EVENT()
        ok = kernel32.WaitForDebugEvent(byref(event), timeout)
        if not ok:
            return None
        self.last_event = event
        return event

    def continue_execution(self, status=DBG_CONTINUE):
        """Continue the debuggee after handling an event."""
        if self.last_event:
            kernel32.ContinueDebugEvent(
                self.last_event.dwProcessId,
                self.last_event.dwThreadId,
                status,
            )

    def interrupt(self):
        """Interrupt the running process (Ctrl+C). Injects a breakpoint."""
        if self.process_handle and self.state == DebuggerState.RUNNING:
            self._interrupt_requested = True
            kernel32.DebugBreakProcess(self.process_handle)

    def run_until_stop(self):
        """Run the debug loop until we hit a breakpoint or other stop condition.
        Uses short timeouts so Ctrl+C / interrupt() can take effect."""
        self._interrupt_requested = False
        while True:
            # Poll with 100ms timeout so we remain responsive
            event = self.wait_for_event(timeout=100)
            if event is None:
                # Timeout — check if we should keep waiting
                if self.state == DebuggerState.TERMINATED:
                    return {"reason": "exit", "exit_code": -1}
                continue

            result = self._handle_event(event)
            if result:
                return result

    def _handle_event(self, event):
        """Handle a debug event. Returns stop info dict if we should stop, else None."""
        code = event.dwDebugEventCode
        tid = event.dwThreadId

        if code == EXCEPTION_DEBUG_EVENT:
            return self._handle_exception(event)

        elif code == CREATE_PROCESS_DEBUG_EVENT:
            info = event.u.CreateProcessInfo
            self.image_base = info.lpBaseOfImage
            if not self.main_thread_handle:
                self.main_thread_handle = info.hThread
                self.main_thread_id = tid
                self.threads[tid] = info.hThread
            if self.active_thread_id is None:
                self.active_thread_id = tid

            # Get exe name
            name = self._get_dll_name(info.hFile, info.lpBaseOfImage, info.lpImageName, info.fUnicode)
            if name:
                self.exe_path = self.exe_path or name
            base = info.lpBaseOfImage or 0
            # Module will be added via refresh later
            self.continue_execution()
            return None

        elif code == CREATE_THREAD_DEBUG_EVENT:
            info = event.u.CreateThread
            self.threads[tid] = info.hThread
            # Re-arm watchpoints on the new thread (debug regs are
            # per-thread so a freshly created thread starts with DR7=0).
            if self.wp_manager.list_all():
                self.apply_watchpoints_to_thread(info.hThread)
            self.continue_execution()
            return None

        elif code == EXIT_THREAD_DEBUG_EVENT:
            if tid in self.threads:
                # Don't close - handle owned by debug API
                del self.threads[tid]
            self.continue_execution()
            return None

        elif code == EXIT_PROCESS_DEBUG_EVENT:
            exit_code = event.u.ExitProcess.dwExitCode
            self.state = DebuggerState.TERMINATED
            self.continue_execution()
            return {"reason": "exit", "exit_code": exit_code}

        elif code == LOAD_DLL_DEBUG_EVENT:
            info = event.u.LoadDll
            base = info.lpBaseOfDll or 0
            name = self._get_dll_name(info.hFile, info.lpBaseOfDll, info.lpImageName, info.fUnicode)
            self._dll_handles[base] = (info.hFile, name)

            # Library-load catchpoint: stop here if the loaded DLL matches
            # any user-registered substring. We refresh the symbol table so
            # the user's first command after the stop sees the new module.
            if self.catch_load_patterns and name:
                lname = name.lower()
                for entry in self.catch_load_patterns:
                    if entry["pattern"] in lname:
                        entry["hit_count"] += 1
                        self.state = DebuggerState.STOPPED
                        try:
                            self.symbols.refresh_modules(self.process_id)
                        except Exception:
                            pass
                        return {
                            "reason": "catch_load",
                            "dll_name": name,
                            "dll_base": base,
                            "catch_id": entry["id"],
                            "tid": event.dwThreadId,
                        }

            # Refresh modules will be done when we actually stop
            self.continue_execution()
            return None

        elif code == UNLOAD_DLL_DEBUG_EVENT:
            base = event.u.UnloadDll.lpBaseOfDll or 0
            if base in self._dll_handles:
                del self._dll_handles[base]
            self.symbols.remove_module(base)
            self.continue_execution()
            return None

        elif code == OUTPUT_DEBUG_STRING_EVENT:
            # We could capture debug output strings here
            self.continue_execution()
            return None

        elif code == RIP_EVENT:
            self.continue_execution()
            return None

        else:
            self.continue_execution()
            return None

    def _handle_exception(self, event):
        """Handle an exception debug event."""
        exc = event.u.Exception
        code = exc.ExceptionRecord.ExceptionCode
        addr = exc.ExceptionRecord.ExceptionAddress or 0
        first_chance = exc.dwFirstChance
        tid = event.dwThreadId

        self.active_thread_id = tid
        self.last_exception_code = code
        self.last_exception_addr = addr

        # System initial breakpoints
        # WoW64 processes get 2 initial BPs: one for 64-bit ntdll, one for 32-bit
        if code in (EXCEPTION_BREAKPOINT, STATUS_WX86_BREAKPOINT):
            # Check how many initial BPs we expect
            expected_initial = 2 if self.is_wow64 else 1

            if self._initial_bp_count < expected_initial:
                self._initial_bp_count += 1

                if self._initial_bp_count >= expected_initial:
                    # Last initial breakpoint — stop here
                    self.first_breakpoint_hit = True
                    self.state = DebuggerState.STOPPED
                    self.symbols.refresh_modules(self.process_id)
                    return {"reason": "initial_breakpoint", "address": addr, "tid": tid}
                else:
                    # More initial BPs expected, keep going
                    self.continue_execution()
                    return None

            # Ctrl+C interrupt via DebugBreakProcess
            if self._interrupt_requested:
                self._interrupt_requested = False
                self.state = DebuggerState.STOPPED
                return {"reason": "interrupt", "address": addr, "tid": tid}

            # Our breakpoint
            # INT3 moves IP past the 0xCC, we need to back it up
            th = self.get_active_thread_handle()
            ctx = get_context(th, self.is_wow64)
            ip = get_ip(ctx, self.is_wow64)
            bp_addr = ip - 1  # IP is one past INT3

            bp = self.bp_manager.on_breakpoint_hit(self.process_handle, bp_addr)
            if bp:
                # Move IP back to the breakpoint address
                set_ip(ctx, bp_addr, self.is_wow64)
                set_context(th, ctx, self.is_wow64)

                # Set single-step to re-enable BP after we execute the original instruction
                self._step_over_bp = bp
                self.state = DebuggerState.STOPPED

                # Thread-specific breakpoint: if the firing thread doesn't
                # match the target TID, treat the BP as silently passing
                # through. Same step-over-and-continue path as a falsy
                # condition. Checked BEFORE condition/action so we don't
                # spend cycles evaluating either on the wrong thread.
                if bp.thread_id is not None and bp.thread_id != tid:
                    set_trap_flag(ctx)
                    set_context(th, ctx, self.is_wow64)
                    self.continue_execution()
                    return None

                # Conditional breakpoint: if condition evaluates to false,
                # silently single-step past the BP and continue running.
                if bp.condition:
                    from .bp_conditions import evaluate_condition
                    ok, truthy, err = evaluate_condition(self, bp.condition)
                    if not ok:
                        from ..display.formatters import warn
                        warn(f"BP#{bp.id} condition error: {err}")
                        # Treat eval errors as a real stop so the user notices
                    elif not truthy:
                        # Step over the BP, then let the outer run_until_stop
                        # loop pick up the next event (returning None instead
                        # of recursing avoids blowing the Python stack on
                        # heavily-trafficked tracing/conditional BPs).
                        # NOTE: do NOT touch _single_stepping. The existing
                        # _step_over_bp re-enable path in the SINGLE_STEP
                        # handler already does the right thing: it absorbs
                        # the trap fire when the user wasn't stepping, and
                        # surfaces it as a step stop when they were.
                        set_trap_flag(ctx)
                        set_context(th, ctx, self.is_wow64)
                        self.continue_execution()
                        return None

                # dprintf-style action: render the format string, print it,
                # then transparently single-step past the BP and continue.
                # Tracing breakpoints never stop the debugger.
                if bp.action:
                    from .bp_conditions import format_dprintf
                    from ..display.formatters import console
                    from rich.text import Text
                    try:
                        rendered = format_dprintf(self, bp.action)
                    except Exception as e:
                        rendered = f"<dprintf error: {e}>"
                    line = Text()
                    line.append(f"[BP#{bp.id} @ {bp_addr:#x}] ", style="bright_magenta")
                    line.append(rendered, style="bright_white")
                    console.print(line)
                    # Step over the BP and let the outer loop continue.
                    # Like the conditional-BP path: do NOT touch
                    # _single_stepping. The _step_over_bp re-enable in the
                    # SINGLE_STEP handler will absorb the trap fire if the
                    # user is just running, or surface it as a step stop if
                    # they were single-stepping when the dprintf fired.
                    set_trap_flag(ctx)
                    set_context(th, ctx, self.is_wow64)
                    self.continue_execution()
                    return None

                return {"reason": "breakpoint", "bp": bp, "address": bp_addr, "tid": tid}
            else:
                # Not our breakpoint — could be another system BP, pass through
                self.continue_execution()
                return None

        # Single step  — also the entry path for hardware watchpoints,
        # which the CPU reports as a SINGLE_STEP exception with the
        # responsible slot indicated by DR6 bits B0..B3.
        if code in (EXCEPTION_SINGLE_STEP, STATUS_WX86_SINGLE_STEP):
            self.state = DebuggerState.STOPPED

            # ---- Watchpoint check (must come before user-step handling) ----
            if self.wp_manager.list_all():
                th = self.get_active_thread_handle()
                if th:
                    try:
                        ctx = get_context(th, self.is_wow64)
                        dr6 = ctx.Dr6
                        wp = self.wp_manager.hit_slot(dr6)
                        if wp:
                            # Clear B0..B3 in DR6 so the next read is clean.
                            ctx.Dr6 = dr6 & ~0xF
                            # Set RF so the next instruction doesn't re-trip
                            # an exec watchpoint at the same address.
                            set_resume_flag(ctx)
                            set_context(th, ctx, self.is_wow64)
                            self._last_wp_hit = wp
                            return {
                                "reason": "watchpoint",
                                "wp": wp,
                                "address": get_ip(ctx, self.is_wow64),
                                "tid": tid,
                            }
                    except Exception:
                        pass

            # Re-enable breakpoint we just stepped over
            if self._step_over_bp:
                self.bp_manager.re_enable_after_single_step(self.process_handle, self._step_over_bp)
                self._step_over_bp = None

                # If we were just doing internal step-over-bp (not user step),
                # continue and let the outer run_until_stop loop pick up the
                # next event (no recursion -> no stack overflow on hot BPs).
                if not self._single_stepping:
                    self.continue_execution()
                    return None

            self._single_stepping = False

            # Handle step-over (ni): if we set a temp BP, it means we stepped
            # through a non-call instruction normally
            if self._step_type == "ni":
                self._step_type = None
                return {"reason": "single_step", "address": self._get_current_ip(), "tid": tid}

            self._step_type = None
            return {"reason": "single_step", "address": self._get_current_ip(), "tid": tid}

        # Access violation
        if code == EXCEPTION_ACCESS_VIOLATION:
            self.state = DebuggerState.STOPPED
            info_params = exc.ExceptionRecord.ExceptionInformation
            access_type = "read" if info_params[0] == 0 else "write" if info_params[0] == 1 else "execute"
            fault_addr = info_params[1]
            return {
                "reason": "access_violation",
                "address": addr,
                "access_type": access_type,
                "fault_address": fault_addr,
                "first_chance": first_chance,
                "tid": tid,
            }

        # Other exceptions
        if first_chance:
            # Pass to the application
            self.continue_execution(DBG_EXCEPTION_NOT_HANDLED)
            return None
        else:
            # Second chance - stop
            self.state = DebuggerState.STOPPED
            return {
                "reason": "exception",
                "code": code,
                "address": addr,
                "first_chance": False,
                "tid": tid,
            }

    def _get_dll_name(self, hFile, base_addr, lpImageName, fUnicode):
        """Try to resolve a DLL name from debug event info."""
        # Method 1: Try GetFinalPathNameByHandleW
        if hFile:
            buf = ctypes.create_unicode_buffer(MAX_PATH)
            result = kernel32.GetFinalPathNameByHandleW(hFile, buf, MAX_PATH, 0)
            if result > 0:
                name = buf.value
                if name.startswith("\\\\?\\"):
                    name = name[4:]
                return name

        # Method 2: Read lpImageName from target memory
        if lpImageName and self.process_handle:
            ptr_data = read_memory_safe(self.process_handle, lpImageName, self.ptr_size)
            if ptr_data:
                if self.ptr_size == 8:
                    name_ptr = struct.unpack("<Q", ptr_data)[0]
                else:
                    name_ptr = struct.unpack("<I", ptr_data)[0]
                if name_ptr:
                    if fUnicode:
                        name = read_wstring(self.process_handle, name_ptr, 512)
                    else:
                        from .memory import read_string
                        name = read_string(self.process_handle, name_ptr, 256)
                    if name:
                        return name
        return None

    def _get_current_ip(self):
        """Get the current instruction pointer."""
        th = self.get_active_thread_handle()
        if not th:
            return 0
        ctx = get_context(th, self.is_wow64)
        return get_ip(ctx, self.is_wow64)

    # -----------------------------------------------------------------
    # Execution control
    # -----------------------------------------------------------------

    def do_continue(self):
        """Continue execution. If we need to step over a BP first, do that."""
        if self._step_over_bp:
            # Need to single-step past the BP instruction first
            self._single_step_internal()
        self.state = DebuggerState.RUNNING
        self.continue_execution()
        return self.run_until_stop()

    def do_step_into(self):
        """Single-step one instruction (step into calls)."""
        self._single_stepping = True
        self._step_type = "si"

        th = self.get_active_thread_handle()
        ctx = get_context(th, self.is_wow64)
        set_trap_flag(ctx)
        set_context(th, ctx, self.is_wow64)

        if self._step_over_bp:
            # We're on a BP - the instruction is already restored
            pass

        self.state = DebuggerState.RUNNING
        self.continue_execution()
        return self.run_until_stop()

    def do_step_over(self):
        """Step over (execute calls without stopping inside them)."""
        th = self.get_active_thread_handle()
        ctx = get_context(th, self.is_wow64)
        ip = get_ip(ctx, self.is_wow64)

        # Disassemble current instruction to check if it's a call
        code = read_memory_safe(self.process_handle, ip, 32)
        if code:
            from .disasm import disassemble_at
            insns = disassemble_at(self.disassembler, code, ip, 1)
            if insns:
                _, size, mnemonic, _ = insns[0]
                from .disasm import is_call_instruction
                if is_call_instruction(mnemonic):
                    # Set a temporary BP after the call
                    next_addr = ip + size
                    self.bp_manager.add(self.process_handle, next_addr, temporary=True)
                    self._step_type = "ni"

                    if self._step_over_bp:
                        self._single_step_internal()

                    self.state = DebuggerState.RUNNING
                    self.continue_execution()
                    return self.run_until_stop()

        # Not a call, just single-step
        return self.do_step_into()

    # -----------------------------------------------------------------
    # Hardware watchpoints
    # -----------------------------------------------------------------

    def apply_watchpoints_to_thread(self, thread_handle):
        """Push the current watchpoint slot state into one thread's CONTEXT.

        Idempotent — safe to call multiple times. Used both when arming a
        new watchpoint (push to every existing thread) and when a new
        thread is created mid-run (push current state to it).
        """
        if not thread_handle:
            return False
        try:
            ctx = get_context(thread_handle, self.is_wow64)
        except Exception:
            return False

        addrs = self.wp_manager.slot_addresses()
        ctx.Dr0 = addrs[0]
        ctx.Dr1 = addrs[1]
        ctx.Dr2 = addrs[2]
        ctx.Dr3 = addrs[3]
        ctx.Dr6 = 0
        ctx.Dr7 = self.wp_manager.build_dr7()
        try:
            set_context(thread_handle, ctx, self.is_wow64)
            return True
        except Exception:
            return False

    def apply_watchpoints_to_all_threads(self):
        """Push current watchpoint state into every known thread."""
        applied = 0
        for th in self.threads.values():
            if self.apply_watchpoints_to_thread(th):
                applied += 1
        return applied

    def add_watchpoint(self, address, access, length):
        """Allocate a hardware watchpoint and arm it on every thread.

        Returns the new Watchpoint or raises ValueError on failure.
        """
        wp = self.wp_manager.add(address, access, length)
        self.apply_watchpoints_to_all_threads()
        return wp

    def remove_watchpoint(self, wp_id):
        """Remove a watchpoint by id and re-arm remaining slots on all threads."""
        if not self.wp_manager.remove_by_id(wp_id):
            return False
        self.apply_watchpoints_to_all_threads()
        return True

    def do_finish(self):
        """Run until the current function returns (step out).

        On x64, prefers the .pdata UNWIND_INFO unwinder so we get the right
        RA even when RIP is mid-function (rsp != saved-RA slot). Falls back
        to the naive `[rsp]` read otherwise.
        """
        th = self.get_active_thread_handle()
        ctx = get_context(th, self.is_wow64)
        sp = get_sp(ctx, self.is_wow64)
        ip = get_ip(ctx, self.is_wow64)

        from .memory import read_ptr, read_memory_safe

        ret_addr = None
        if not self.is_wow64 and self.symbols and self.symbols.modules:
            # Use the same unwinder that powers backtrace_x64. We pass
            # mid_prolog=True so that codes whose prolog instruction has
            # not yet executed are NOT counted (RIP may be sitting just
            # after a `call` into a function whose prolog hasn't run).
            from .seh import unwind_one_frame_x64
            def _read(addr, size):
                return read_memory_safe(self.process_handle, addr, size)
            try:
                caller_rip, _ = unwind_one_frame_x64(
                    _read, self.symbols.modules, ip, sp, mid_prolog=True,
                )
                if caller_rip and caller_rip > 0x10000:
                    ret_addr = caller_rip
            except Exception:
                ret_addr = None

        if ret_addr is None:
            ret_addr = read_ptr(self.process_handle, sp, self.ptr_size)
        if ret_addr is None:
            # Last resort: [ebp+ptr_size]
            bp_val = get_bp(ctx, self.is_wow64)
            ret_addr = read_ptr(self.process_handle, bp_val + self.ptr_size, self.ptr_size)

        if ret_addr:
            self.bp_manager.add(self.process_handle, ret_addr, temporary=True)
            return self.do_continue()
        from ..display.formatters import error
        error("Cannot determine return address")
        return None

    def do_stepuntil(self, target_addr):
        """Set a temporary breakpoint at `target_addr` and continue.

        Mirrors GDB's `until <location>`. The BP is one-shot — it's removed
        as soon as it fires (handled by BreakpointManager).
        """
        self.bp_manager.add(self.process_handle, target_addr, temporary=True)
        return self.do_continue()

    def do_retbreak(self, run_after=False):
        """Find all ret instructions in the current function and set temp BPs on them.
        If run_after=True, continue execution after setting BPs.
        Returns list of addresses where BPs were set."""
        th = self.get_active_thread_handle()
        if not th:
            return []
        ctx = get_context(th, self.is_wow64)
        ip = get_ip(ctx, self.is_wow64)

        # Try to find function boundaries
        # Heuristic: scan backward for a common prologue (push ebp / sub rsp)
        # and forward until we hit a ret followed by padding/next function
        func_start = ip
        func_end = ip

        # Scan backward (max 4KB) to find function start
        scan_back = 4096
        start_addr = max(ip - scan_back, 0x1000)
        code_before = read_memory_safe(self.process_handle, start_addr, ip - start_addr + 64)
        if code_before:
            from .disasm import disassemble_at, is_ret_instruction
            # Disassemble forward from start_addr and find the function containing ip
            insns = disassemble_at(self.disassembler, code_before, start_addr, 2000)
            # Find the last function prologue before ip
            for addr, size, mnemonic, op_str in insns:
                if addr > ip:
                    break
                # Common prologues
                if mnemonic == "push" and op_str in ("ebp", "rbp"):
                    func_start = addr
                elif mnemonic == "sub" and ("esp" in op_str or "rsp" in op_str) and addr == func_start + size:
                    pass  # already found it
            # Simple fallback: if we didn't find prologue, use current IP
            if func_start == ip:
                func_start = ip

        # Scan forward (max 8KB) to find all ret instructions
        scan_size = 8192
        code_forward = read_memory_safe(self.process_handle, func_start, scan_size)
        if not code_forward:
            return []

        from .disasm import disassemble_at, is_ret_instruction
        insns = disassemble_at(self.disassembler, code_forward, func_start, 2000)

        ret_addrs = []
        found_first_ret = False
        for addr, size, mnemonic, op_str in insns:
            if addr < func_start:
                continue
            if is_ret_instruction(mnemonic):
                ret_addrs.append(addr)
                found_first_ret = True
            elif found_first_ret:
                # After a ret, if we see another prologue or padding, stop
                if mnemonic in ("push",) and op_str in ("ebp", "rbp"):
                    break
                if mnemonic in ("int3", "nop", "cc"):
                    continue  # padding
                elif mnemonic.startswith("j") or mnemonic == "call":
                    found_first_ret = False  # still in function, keep going
                else:
                    found_first_ret = False

        # Set temporary breakpoints on all ret addresses
        for addr in ret_addrs:
            self.bp_manager.add(self.process_handle, addr, temporary=True)

        if run_after and ret_addrs:
            return ret_addrs
        return ret_addrs

    def get_return_address(self):
        """Get the return address for the current frame (top of stack or [ebp+ptr])."""
        th = self.get_active_thread_handle()
        if not th:
            return None
        ctx = get_context(th, self.is_wow64)
        sp = get_sp(ctx, self.is_wow64)
        bp_val = get_bp(ctx, self.is_wow64)
        ip = get_ip(ctx, self.is_wow64)

        from .memory import read_ptr

        # Check if current instruction is a ret
        code = read_memory_safe(self.process_handle, ip, 16)
        if code:
            insns = disassemble_at(self.disassembler, code, ip, 1)
            if insns:
                _, _, mnemonic, _ = insns[0]
                from .disasm import is_ret_instruction
                if is_ret_instruction(mnemonic):
                    # ret pops from [esp/rsp]
                    return read_ptr(self.process_handle, sp, self.ptr_size)

        # Otherwise, return address is at [ebp+ptr_size] in a standard frame
        if bp_val and bp_val > 0x1000:
            ret = read_ptr(self.process_handle, bp_val + self.ptr_size, self.ptr_size)
            if ret and ret > 0x1000:
                return ret

        # Or just top of stack if no frame pointer
        return read_ptr(self.process_handle, sp, self.ptr_size)

    def track_examine(self, key, requested_addr, block_size):
        """Auto-advance for repeating examine commands.
        On first call with an addr, returns that addr.
        On repeat (same addr), returns the next block."""
        state = self._examine_next.get(key)
        if state is not None:
            last_requested, next_addr = state
            if requested_addr == last_requested:
                # Repeating — advance
                self._examine_next[key] = (requested_addr, next_addr + block_size)
                return next_addr
        # New address
        self._examine_next[key] = (requested_addr, requested_addr + block_size)
        return requested_addr

    def _single_step_internal(self):
        """Internal single-step (to step over a restored breakpoint)."""
        th = self.get_active_thread_handle()
        ctx = get_context(th, self.is_wow64)
        set_trap_flag(ctx)
        set_context(th, ctx, self.is_wow64)

    # -----------------------------------------------------------------
    # Context & Info
    # -----------------------------------------------------------------

    def get_registers(self):
        """Get current registers as a dict, plus the set of changed regs."""
        th = self.get_active_thread_handle()
        if not th:
            return {}, set()
        ctx = get_context(th, self.is_wow64)
        regs = context_to_dict(ctx, self.is_wow64)
        changed = diff_registers(self.prev_regs, regs)
        self.prev_regs = regs.copy()
        return regs, changed

    def get_disassembly(self, address=None, count=10):
        """Disassemble at address (default: current IP)."""
        if address is None:
            address = self._get_current_ip()
        # Read enough bytes for disassembly
        code = read_memory_safe(self.process_handle, address, count * 15)
        if not code:
            return []
        return disassemble_at(self.disassembler, code, address, count)

    def get_stack_entries(self, count=8):
        """Read stack entries from current SP."""
        th = self.get_active_thread_handle()
        if not th:
            return [], 0
        ctx = get_context(th, self.is_wow64)
        sp = get_sp(ctx, self.is_wow64)

        entries = []
        from .memory import read_ptr
        for i in range(count):
            addr = sp + i * self.ptr_size
            val = read_ptr(self.process_handle, addr, self.ptr_size)
            entries.append((addr, val))

        return entries, sp

    def get_backtrace(self, max_frames=10):
        """Walk the stack frames to build a backtrace.

        On x64, prefers .pdata UNWIND_INFO-based unwinding (the only correct
        approach since most x64 functions don't maintain an RBP frame). Falls
        back to RBP frame chaining on x86 / WoW64 or when .pdata coverage
        fails.
        """
        th = self.get_active_thread_handle()
        if not th:
            return []
        ctx = get_context(th, self.is_wow64)
        ip = get_ip(ctx, self.is_wow64)
        bp_val = get_bp(ctx, self.is_wow64)
        sp = get_sp(ctx, self.is_wow64)

        # ---- x64: try the .pdata-based unwinder first ----
        if not self.is_wow64 and self.symbols and self.symbols.modules:
            from .seh import backtrace_x64
            from .memory import read_memory_safe

            def _read(addr, size):
                return read_memory_safe(self.process_handle, addr, size)

            try:
                frames = backtrace_x64(_read, self.symbols.modules,
                                       ip, sp, max_frames=max_frames)
            except Exception:
                frames = []
            if len(frames) >= 2:
                return frames

        # ---- Fallback: RBP frame chaining (x86 / WoW64 / no .pdata) ----
        frames = [(0, ip)]
        current_bp = bp_val
        from .memory import read_ptr

        for i in range(1, max_frames):
            if current_bp == 0 or current_bp < 0x1000:
                break
            # Read saved BP and return address
            saved_bp = read_ptr(self.process_handle, current_bp, self.ptr_size)
            ret_addr = read_ptr(self.process_handle, current_bp + self.ptr_size, self.ptr_size)
            if saved_bp is None or ret_addr is None:
                break
            if ret_addr == 0 or ret_addr < 0x1000:
                break
            frames.append((i, ret_addr))
            if saved_bp <= current_bp:
                break  # Stack growing wrong way = corrupt
            current_bp = saved_bp

        return frames

    def get_vmmap(self):
        """Enumerate memory regions with module labels."""
        from .memory import enumerate_memory_regions
        from ..utils.constants import MEM_COMMIT, prot_to_str

        regions = []
        for base, mbi in enumerate_memory_regions(self.process_handle):
            if mbi.State == 0x10000:  # MEM_FREE
                continue
            protect = mbi.Protect if mbi.State == MEM_COMMIT else mbi.AllocationProtect
            # Find module label
            label = ""
            mod = self.symbols.get_module_at(base)
            if mod:
                label = mod.name

            regions.append((
                base,
                mbi.RegionSize,
                protect,
                mbi.State,
                mbi.Type,
                label,
            ))
        return regions

    def telescope(self, address=None, depth=8, chain_depth=5):
        """Dereference pointer chains starting at address.
        Returns list of (offset, chain) where chain is list of
        (value, label, perm_str, is_string, string_val, asm_str) tuples."""
        if address is None:
            th = self.get_active_thread_handle()
            ctx = get_context(th, self.is_wow64)
            address = get_sp(ctx, self.is_wow64)

        from .memory import read_ptr, read_string, read_memory_safe, virtual_query
        from ..utils.constants import prot_to_str, MEM_COMMIT

        chains = []
        for i in range(depth):
            offset = i * self.ptr_size
            addr = address + offset
            chain = []
            seen = set()
            current = addr

            for j in range(chain_depth):
                val = read_ptr(self.process_handle, current, self.ptr_size)
                if val is None:
                    chain.append((None, "", "", False, "", ""))
                    break

                # Get label and permissions
                label = ""
                perm_str = ""
                mod = self.symbols.get_module_at(val)
                if mod:
                    label = f"{mod.name}+{mod.offset_of(val):#x}"

                sym = self.symbols.resolve_address(val)
                if sym:
                    label = sym

                mbi = virtual_query(self.process_handle, val)
                if mbi and mbi.State == MEM_COMMIT:
                    perm_str = prot_to_str(mbi.Protect)

                # Check if it might be a string
                is_str = False
                str_val = ""
                asm_str = ""
                if val > 0x1000 and mbi and mbi.State == MEM_COMMIT:
                    test = read_string(self.process_handle, val, 64)
                    if test and len(test) > 3 and all(c.isprintable() or c in '\t\n\r' for c in test):
                        is_str = True
                        str_val = test[:60]

                # If executable and not a string, disassemble 1 instruction
                if not is_str and val > 0x1000 and mbi and mbi.State == MEM_COMMIT:
                    if mbi.Protect & 0xF0:  # any execute bit
                        code = read_memory_safe(self.process_handle, val, 16)
                        if code:
                            insns = disassemble_at(self.disassembler, code, val, 1)
                            if insns:
                                _, _, mnem, ops = insns[0]
                                asm_str = f"{mnem} {ops}".strip()

                chain.append((val, label, perm_str, is_str, str_val, asm_str))

                # Follow pointer?
                if val in seen or val < 0x1000 or is_str:
                    break
                seen.add(val)
                current = val

            chains.append((offset, chain))

        return chains
