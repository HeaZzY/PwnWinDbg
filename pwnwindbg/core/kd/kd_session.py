"""High-level KD debugging session: connect, read/write memory, registers, bp, continue."""

import struct
import time

from .kd_structs import (
    DbgKdReadVirtualMemoryApi, DbgKdWriteVirtualMemoryApi,
    DbgKdGetContextApi, DbgKdSetContextApi,
    DbgKdWriteBreakPointApi, DbgKdRestoreBreakPointApi,
    DbgKdContinueApi, DbgKdContinueApi2,
    DbgKdGetVersionApi, DbgKdReadPhysicalMemoryApi,
    DbgKdExceptionStateChange, DbgKdLoadSymbolsStateChange,
    DbgKdSearchMemoryApi, DbgKdQueryMemoryApi,
    DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED,
    KD_MACH_AMD64, KD_MACH_I386,
    DBGKD_VERS_FLAG_PTR64,
    KD_REQ_HEADER_SIZE, KD_MAX_PAYLOAD,
    CONTEXT_AMD64_ALL, CONTEXT_I386_ALL,
    AMD64_CONTEXT_OFFSETS, I386_CONTEXT_OFFSETS,
    PACKET_TYPE_KD_STATE_CHANGE64, PACKET_TYPE_KD_DEBUG_IO,
)
from .protocol import KdProtocol
from .transport import KdnetTransport, PipeTransport


class KdSession:
    """High-level kernel debugging session."""

    def __init__(self, transport):
        self._transport = transport
        self._proto = KdProtocol(transport)
        self.connected = False

        # Target info
        self.machine_type = None    # KD_MACH_AMD64, KD_MACH_I386
        self.is_64bit = False
        self.ptr_size = 4
        self.kernel_base = 0
        self.ps_loaded_module_list = 0
        self.debugger_data_list = 0
        self.os_version = ""

        # State
        self.cpu_count = 0
        self.current_cpu = 0
        self.current_thread = 0
        self.current_pc = 0
        self.exception_code = 0
        self.stopped = False

        # Context cache
        self._context_raw = None
        self._context_regs = None

        # DbgPrint buffer
        self.dbgprint_log = []

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def connect(self):
        """Connect to the target and perform handshake."""
        self._transport.connect()

        if isinstance(self._transport, KdnetTransport):
            return self._kdnet_handshake()
        else:
            return self._pipe_handshake()

    def _kdnet_handshake(self):
        """KDNET handshake: wait for poke, send response, wait for state change."""
        from ...display.formatters import info as _info, warn as _warn

        transport = self._transport

        # Wait for target poke
        _info("Waiting for target poke packet...")
        poke_data = transport.wait_for_poke(timeout=60.0)
        if poke_data is None:
            return False, "Timeout waiting for target poke packet (is the target configured for KDNET and rebooted?)"

        _info(f"Received poke ({len(poke_data)} bytes) — sending response...")

        # Send response (derives data key)
        transport.send_response(poke_data)
        _info("Data key derived — waiting for KD state change...")

        # Now wait for KD packets on the encrypted channel
        # Send reset
        self._proto.send_reset()

        # Wait for state change
        pkt = self._proto.wait_state_change(timeout=30.0)
        if pkt is None:
            return False, "Timeout waiting for state change after handshake (encryption key mismatch?)"

        self._handle_state_change(pkt)
        self.connected = True
        return True, "Connected"

    def _pipe_handshake(self):
        """Pipe handshake: send break-in + reset, wait for state change."""
        self._proto.send_breakin()
        time.sleep(0.1)
        self._proto.send_reset()

        pkt = self._proto.wait_state_change(timeout=30.0)
        if pkt is None:
            return False, "Timeout waiting for state change"

        self._handle_state_change(pkt)
        self.connected = True
        return True, "Connected"

    def _handle_state_change(self, pkt):
        """Parse a STATE_CHANGE64 packet payload."""
        payload = pkt.get("payload", b'')
        if len(payload) < 0x28:
            return

        new_state = struct.unpack_from("<I", payload, 0)[0]
        cpu_level = struct.unpack_from("<H", payload, 4)[0]
        cpu = struct.unpack_from("<H", payload, 6)[0]
        cpu_count = struct.unpack_from("<I", payload, 8)[0]
        thread = struct.unpack_from("<Q", payload, 0x10)[0]
        pc = struct.unpack_from("<Q", payload, 0x18)[0]

        self.cpu_count = cpu_count
        self.current_cpu = cpu
        self.current_thread = thread
        self.current_pc = pc
        self.stopped = True
        self._context_raw = None  # invalidate

        if new_state == DbgKdExceptionStateChange and len(payload) >= 0x40:
            self.exception_code = struct.unpack_from("<I", payload, 0x20)[0]

    # ------------------------------------------------------------------
    # State manipulation helpers
    # ------------------------------------------------------------------

    def _build_req(self, api_number: int, union_data: bytes = b'') -> bytes:
        """Build a 56-byte manipulate state request."""
        # Header: ApiNumber(4) + ProcessorLevel(2) + Processor(2) + ReturnStatus(4) + pad(4)
        header = struct.pack("<IHHI I",
                             api_number,
                             0,  # processor level
                             self.current_cpu,
                             0,  # return status
                             0,  # pad
                             )
        # Union: 40 bytes
        union = union_data.ljust(40, b'\x00')[:40]
        return header + union

    def _do_manipulate(self, api_number: int, union_data: bytes = b'',
                       extra_data: bytes = b'', timeout: float = 10.0):
        """Send a manipulate request and return the response packet."""
        req = self._build_req(api_number, union_data)
        payload = req + extra_data
        self._proto.send_manipulate(payload)
        return self._proto.recv_manipulate_response(timeout=timeout)

    # ------------------------------------------------------------------
    # GetVersion
    # ------------------------------------------------------------------

    def get_version(self):
        """Query the target's version info."""
        resp = self._do_manipulate(DbgKdGetVersionApi)
        if resp is None:
            return None

        payload = resp.get("payload", b'')
        if len(payload) < 56:
            return None

        # Union starts at offset 16 in the payload (after the 16-byte header part)
        # Actually, the manipulate response payload starts with the 56-byte req structure
        union_off = 16  # offset of union within the 56-byte structure
        if len(payload) < union_off + 40:
            return None

        major = struct.unpack_from("<H", payload, union_off + 0)[0]
        minor = struct.unpack_from("<H", payload, union_off + 2)[0]
        proto_major = payload[union_off + 4] if len(payload) > union_off + 4 else 0
        proto_minor = payload[union_off + 5] if len(payload) > union_off + 5 else 0
        flags = struct.unpack_from("<H", payload, union_off + 6)[0]
        machine = struct.unpack_from("<H", payload, union_off + 8)[0]

        self.machine_type = machine
        self.is_64bit = bool(flags & DBGKD_VERS_FLAG_PTR64) or machine == KD_MACH_AMD64
        self.ptr_size = 8 if self.is_64bit else 4
        self.os_version = f"{major}.{minor}"

        # Kernel base and PsLoadedModuleList at fixed offsets in the union
        if len(payload) >= union_off + 0x28:
            self.kernel_base = struct.unpack_from("<Q", payload, union_off + 0x10)[0]
            self.ps_loaded_module_list = struct.unpack_from("<Q", payload, union_off + 0x18)[0]
            self.debugger_data_list = struct.unpack_from("<Q", payload, union_off + 0x20)[0]

        return {
            "os_version": self.os_version,
            "machine": machine,
            "is_64bit": self.is_64bit,
            "kernel_base": self.kernel_base,
            "ps_loaded_module_list": self.ps_loaded_module_list,
            "proto": f"{proto_major}.{proto_minor}",
        }

    # ------------------------------------------------------------------
    # Read / Write virtual memory
    # ------------------------------------------------------------------

    def read_virtual(self, address: int, size: int) -> bytes:
        """Read virtual memory from the target. Handles chunking."""
        result = b''
        remaining = size
        addr = address

        while remaining > 0:
            chunk = min(remaining, KD_MAX_PAYLOAD)
            # Union: TargetBaseAddress(Q) + TransferCount(I) + ActualBytesRead(I)
            union = struct.pack("<QII", addr, chunk, 0)
            resp = self._do_manipulate(DbgKdReadVirtualMemoryApi, union)
            if resp is None:
                break

            payload = resp.get("payload", b'')
            # Response has 56-byte header, then the memory data
            if len(payload) <= KD_REQ_HEADER_SIZE:
                break

            # Check return status
            ret_status = struct.unpack_from("<I", payload, 8)[0]  # offset 8 = ReturnStatus
            data = payload[KD_REQ_HEADER_SIZE:]
            if not data:
                break

            result += data
            addr += len(data)
            remaining -= len(data)

            if len(data) < chunk:
                break  # short read

        return result

    def write_virtual(self, address: int, data: bytes) -> bool:
        """Write virtual memory to the target."""
        offset = 0
        while offset < len(data):
            chunk = data[offset:offset + KD_MAX_PAYLOAD]
            union = struct.pack("<QII", address + offset, len(chunk), 0)
            resp = self._do_manipulate(
                DbgKdWriteVirtualMemoryApi, union, extra_data=chunk
            )
            if resp is None:
                return False
            offset += len(chunk)
        return True

    # ------------------------------------------------------------------
    # Read physical memory
    # ------------------------------------------------------------------

    def read_physical(self, address: int, size: int) -> bytes:
        """Read physical memory from the target."""
        union = struct.pack("<QII", address, min(size, KD_MAX_PAYLOAD), 0)
        resp = self._do_manipulate(DbgKdReadPhysicalMemoryApi, union)
        if resp is None:
            return b''
        payload = resp.get("payload", b'')
        if len(payload) <= KD_REQ_HEADER_SIZE:
            return b''
        return payload[KD_REQ_HEADER_SIZE:]

    # ------------------------------------------------------------------
    # Registers
    # ------------------------------------------------------------------

    def get_context(self) -> dict:
        """Read the current CPU context (registers). Returns register dict."""
        if self.is_64bit:
            ctx_flags = CONTEXT_AMD64_ALL
        else:
            ctx_flags = CONTEXT_I386_ALL

        # Union: Flags at offset 0
        union = struct.pack("<I", ctx_flags) + b'\x00' * 36
        resp = self._do_manipulate(DbgKdGetContextApi, union)
        if resp is None:
            return {}

        payload = resp.get("payload", b'')
        if len(payload) <= KD_REQ_HEADER_SIZE:
            return {}

        ctx_data = payload[KD_REQ_HEADER_SIZE:]
        self._context_raw = ctx_data

        offsets = AMD64_CONTEXT_OFFSETS if self.is_64bit else I386_CONTEXT_OFFSETS
        regs = {}
        for name, (off, fmt) in offsets.items():
            if off + struct.calcsize(fmt) <= len(ctx_data):
                regs[name] = struct.unpack_from(fmt, ctx_data, off)[0]

        self._context_regs = regs
        return regs

    def set_context(self, regs_to_set: dict) -> bool:
        """Write modified registers back to the target."""
        if self._context_raw is None:
            self.get_context()
        if self._context_raw is None:
            return False

        ctx = bytearray(self._context_raw)
        offsets = AMD64_CONTEXT_OFFSETS if self.is_64bit else I386_CONTEXT_OFFSETS

        for name, value in regs_to_set.items():
            if name in offsets:
                off, fmt = offsets[name]
                struct.pack_into(fmt, ctx, off, value)

        union = b'\x00' * 40
        resp = self._do_manipulate(DbgKdSetContextApi, union, extra_data=bytes(ctx))
        return resp is not None

    # ------------------------------------------------------------------
    # Breakpoints
    # ------------------------------------------------------------------

    def set_breakpoint(self, address: int) -> int:
        """Set a kernel breakpoint. Returns handle (>= 0) or -1 on failure."""
        union = struct.pack("<QI", address, 0) + b'\x00' * 28
        resp = self._do_manipulate(DbgKdWriteBreakPointApi, union)
        if resp is None:
            return -1
        payload = resp.get("payload", b'')
        if len(payload) >= 24:
            handle = struct.unpack_from("<I", payload, 24)[0]  # union offset 8 within payload
            return handle
        return -1

    def remove_breakpoint(self, handle: int) -> bool:
        """Remove a kernel breakpoint by handle."""
        union = struct.pack("<I", handle) + b'\x00' * 36
        resp = self._do_manipulate(DbgKdRestoreBreakPointApi, union)
        return resp is not None

    # ------------------------------------------------------------------
    # Continue / Step
    # ------------------------------------------------------------------

    def do_continue(self, status: int = DBG_CONTINUE):
        """Continue execution on the target."""
        # Use ContinueApi2 for single-step support
        # ContinueApi2: ContinueStatus(4) + TraceFlag(4) + Dr7(8) + SymStart(8) + SymEnd(8)
        union = struct.pack("<II", status, 0)  # no single-step
        union = union.ljust(40, b'\x00')
        self._proto.send_manipulate(
            self._build_req(DbgKdContinueApi2, union)
        )
        self.stopped = False
        self._context_raw = None

    def do_step(self):
        """Single-step one instruction (set TraceFlag)."""
        # ContinueApi2 with TraceFlag = 0x100 (TF for x86) or 0x400
        trace_flag = 0x100 if not self.is_64bit else 0x100
        union = struct.pack("<II", DBG_CONTINUE, trace_flag)
        union = union.ljust(40, b'\x00')
        self._proto.send_manipulate(
            self._build_req(DbgKdContinueApi2, union)
        )
        self.stopped = False
        self._context_raw = None

    def wait_break(self, timeout: float = 60.0):
        """Wait for the target to break (after continue/step).

        Returns a state change dict or None.
        """
        pkt = self._proto.wait_state_change(timeout=timeout)
        if pkt is None:
            return None

        # Handle DEBUG_IO (DbgPrint)
        while pkt and pkt["type"] == PACKET_TYPE_KD_DEBUG_IO:
            self._handle_debug_io(pkt)
            pkt = self._proto.wait_state_change(timeout=timeout)

        if pkt and pkt["type"] == PACKET_TYPE_KD_STATE_CHANGE64:
            self._handle_state_change(pkt)
            return {
                "pc": self.current_pc,
                "thread": self.current_thread,
                "cpu": self.current_cpu,
                "exception_code": self.exception_code,
            }
        return None

    def do_break(self):
        """Send break-in to interrupt the running target."""
        self._proto.send_breakin()

    # ------------------------------------------------------------------
    # Debug I/O
    # ------------------------------------------------------------------

    def _handle_debug_io(self, pkt):
        """Handle a DEBUG_IO packet (DbgPrint output)."""
        payload = pkt.get("payload", b'')
        if len(payload) < 64:
            return
        # req type at offset 0
        req = struct.unpack_from("<I", payload, 0)[0]
        if req == 0x3230:  # PrintString
            string_data = payload[64:]
            try:
                text = string_data.decode("utf-16-le", errors="replace").rstrip('\x00')
                if not text:
                    text = string_data.decode("utf-8", errors="replace").rstrip('\x00')
            except Exception:
                text = string_data.hex()
            if text.strip():
                self.dbgprint_log.append(text)

    # ------------------------------------------------------------------
    # Disconnect
    # ------------------------------------------------------------------

    def disconnect(self):
        """Disconnect from the target."""
        if self.stopped:
            try:
                self.do_continue()
            except Exception:
                pass
        self._transport.close()
        self.connected = False
