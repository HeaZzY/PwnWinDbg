"""GDB Remote Serial Protocol transport for QEMU stub kernel debugging.

Connects to a QEMU GDB stub (TCP) and provides the same high-level
interface as KdSession: register/memory read-write, breakpoints,
continue/step.

This is an alternative to KDNET when the target runs in QEMU and
the GDB stub is enabled (-gdb tcp::port or via the QEMU monitor).
"""

import socket
import struct
import threading


class GdbTransport:
    """Low-level GDB Remote Serial Protocol over TCP."""

    def __init__(self, host: str, port: int):
        self._host = host
        self._port = port
        self._sock = None
        self._lock = threading.Lock()
        self._connected = False
        self._recv_buf = b""  # leftover bytes from previous recv

    @property
    def is_connected(self) -> bool:
        return self._connected

    def connect(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.settimeout(10.0)
        self._sock.connect((self._host, self._port))
        self._connected = True

    def close(self):
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        self._connected = False

    # ------------------------------------------------------------------
    # GDB packet framing
    # ------------------------------------------------------------------

    def _checksum(self, data: bytes) -> int:
        return sum(data) & 0xFF

    def send_packet(self, data: str | bytes):
        """Send a GDB packet: $data#XX"""
        if isinstance(data, str):
            data = data.encode("ascii")
        cs = self._checksum(data)
        frame = b"$" + data + b"#" + f"{cs:02x}".encode()
        with self._lock:
            self._sock.sendall(frame)

    def _fill_buf(self, timeout: float) -> bool:
        """Read more data from socket into _recv_buf. Returns False on EOF/timeout."""
        import select
        ready = select.select([self._sock], [], [], timeout)
        if not ready[0]:
            return False
        try:
            data = self._sock.recv(65536)
        except (socket.timeout, OSError):
            return False
        if not data:
            return False
        self._recv_buf += data
        return True

    def recv_packet(self, timeout: float = 10.0) -> bytes | None:
        """Receive a GDB packet. Returns payload (without framing).

        Uses an internal buffer (_recv_buf) so that data from multiple
        packets arriving in a single recv() is never lost.
        """
        import time as _time

        deadline = _time.monotonic() + timeout

        # Phase 1: find '$' start marker, skipping '+'/'-' ACK/NACK bytes
        while True:
            # Scan buffer for '$'
            while self._recv_buf:
                ch = self._recv_buf[0:1]
                if ch == b"$":
                    self._recv_buf = self._recv_buf[1:]
                    break
                # Skip ACK (+), NACK (-), other noise
                self._recv_buf = self._recv_buf[1:]
            else:
                # Buffer empty or no '$' found yet — need more data
                remaining = deadline - _time.monotonic()
                if remaining <= 0:
                    return None
                wait = min(remaining, 0.5)
                if not self._fill_buf(wait):
                    continue  # timeout slice — loop lets KeyboardInterrupt through
                continue
            break  # found '$'

        # Phase 2: read payload until '#XX'
        while True:
            hash_pos = self._recv_buf.find(b"#")
            if hash_pos >= 0 and hash_pos + 2 < len(self._recv_buf):
                # Full packet available: payload + '#' + 2 checksum chars
                payload = self._recv_buf[:hash_pos]
                self._recv_buf = self._recv_buf[hash_pos + 3:]  # skip #XX
                self._sock.sendall(b"+")
                return payload
            # Need more data
            remaining = deadline - _time.monotonic()
            if remaining <= 0:
                return None
            if not self._fill_buf(min(remaining, 5.0)):
                # Timeout — check if we have a partial packet with #X (1 checksum char)
                if hash_pos >= 0 and hash_pos + 1 < len(self._recv_buf):
                    if not self._fill_buf(1.0):
                        return None
                else:
                    return None

    def command(self, cmd: str, timeout: float = 10.0) -> bytes | None:
        """Send command and receive response."""
        self.send_packet(cmd)
        return self.recv_packet(timeout=timeout)

    def pipeline(self, cmds: list[str], timeout: float = 10.0) -> list[bytes | None]:
        """Send multiple commands at once, collect all responses.

        QEMU GDB stub processes pipelined requests in order, giving
        ~50x throughput vs sequential request-response for small reads.
        """
        for cmd in cmds:
            self.send_packet(cmd)
        results = []
        for _ in cmds:
            results.append(self.recv_packet(timeout=timeout))
        return results

    def monitor_command(self, monitor_cmd: str, timeout: float = 5.0) -> str:
        """Execute a QEMU monitor command via qRcmd and collect output."""
        hex_cmd = monitor_cmd.encode().hex()
        self.send_packet(f"qRcmd,{hex_cmd}")
        output = b""
        for _ in range(500):
            pkt = self.recv_packet(timeout=timeout)
            if pkt is None or pkt == b"OK":
                break
            if pkt.startswith(b"O"):
                try:
                    output += bytes.fromhex(pkt[1:].decode())
                except (ValueError, UnicodeDecodeError):
                    pass
        return output.decode("ascii", errors="replace")

    def send_interrupt(self):
        """Send Ctrl+C to break into the debugger."""
        with self._lock:
            self._sock.sendall(b"\x03")


class GdbSession:
    """High-level kernel debugging session via QEMU GDB stub.

    Provides the same interface as KdSession for register/memory
    access, breakpoints, and execution control.
    """

    # x86_64 GDB register order (matching QEMU's response to 'g')
    # Each entry: (gdb_name, byte_size)
    _REG_LAYOUT_64 = [
        ("rax", 8), ("rbx", 8), ("rcx", 8), ("rdx", 8),
        ("rsi", 8), ("rdi", 8), ("rbp", 8), ("rsp", 8),
        ("r8", 8), ("r9", 8), ("r10", 8), ("r11", 8),
        ("r12", 8), ("r13", 8), ("r14", 8), ("r15", 8),
        ("rip", 8), ("eflags", 4),
        ("cs", 4), ("ss", 4), ("ds", 4), ("es", 4), ("fs", 4), ("gs", 4),
    ]

    # Map GDB lowercase names → KD-style names used by display code
    _GDB_TO_KD = {
        "rax": "Rax", "rbx": "Rbx", "rcx": "Rcx", "rdx": "Rdx",
        "rsi": "Rsi", "rdi": "Rdi", "rbp": "Rbp", "rsp": "Rsp",
        "r8": "R8", "r9": "R9", "r10": "R10", "r11": "R11",
        "r12": "R12", "r13": "R13", "r14": "R14", "r15": "R15",
        "rip": "Rip", "eflags": "EFlags",
        "cs": "SegCs", "ss": "SegSs", "ds": "SegDs",
        "es": "SegEs", "fs": "SegFs", "gs": "SegGs",
    }

    def __init__(self, host: str, port: int):
        self._transport = GdbTransport(host, port)
        self.connected = False

        # Target info
        self.machine_type = 0x8664  # AMD64
        self.is_64bit = True
        self.ptr_size = 8
        self.kernel_base = 0
        self.os_version = ""

        # Negotiated max bytes per memory read (derived from PacketSize)
        self._max_read_chunk = 0x800  # conservative default

        # Register index map from target XML (name -> gdb index)
        self._reg_index_map = {}

        # State
        self.cpu_count = 1
        self.current_cpu = 0
        self.current_thread = 0
        self.current_pc = 0
        self.exception_code = 0
        self.stopped = True

        # Context cache
        self._context_regs = None
        self._raw_regs_hex = None
        self._regs_fresh = False  # True if regs were just read (avoid redundant RTT)

        # Persistent page cache — survives across steps for code pages
        self._page_cache = {}       # page_base (addr & ~0xFFF) -> 4KB bytes
        self._code_pages = set()    # known executable pages (never invalidated between steps)

        # Breakpoints
        self._breakpoints = {}  # handle -> (address, is_hardware)
        self._sw_bp_orig = {}   # address -> original byte (for software BPs)
        self._next_bp_handle = 1
        self._pending_reenable = []  # hw bps disabled for stepping

        # DbgPrint (not available via GDB stub)
        self.dbgprint_log = []

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def connect(self):
        """Connect to the GDB stub."""
        self._transport.connect()

        # Halt target first — this also drains any pending stop notification
        # from a previous session that closed without resuming.
        self._transport.send_interrupt()
        self._transport.recv_packet(timeout=2.0)
        self.stopped = True

        # Query supported features (now clean, no pending notifications)
        resp = self._transport.command("qSupported:multiprocess+;swbreak+;hwbreak+")
        if resp is None:
            return False, "No response from GDB stub"

        # If we got a stop notification instead, retry once
        if resp and resp[:1] in (b"T", b"S"):
            resp = self._transport.command("qSupported:multiprocess+;swbreak+;hwbreak+")

        # Parse PacketSize to maximize read throughput
        # Response is hex-encoded, so max read bytes = PacketSize / 2
        try:
            features = resp.decode("ascii", errors="replace")
            for feat in features.split(";"):
                if feat.startswith("PacketSize="):
                    pkt_size = int(feat.split("=")[1], 16)
                    # Leave room for packet framing ($...#XX)
                    self._max_read_chunk = max(0x800, (pkt_size - 32) // 2)
        except (ValueError, IndexError):
            pass

        # Get target architecture and discover register indices
        desc = self._transport.command("qXfer:features:read:target.xml:0,ffff")
        if desc and b"x86-64" in desc:
            self.is_64bit = True
            self.machine_type = 0x8664
            self.ptr_size = 8
        elif desc and b"i386" in desc:
            self.is_64bit = False
            self.machine_type = 0x014c
            self.ptr_size = 4

        if desc:
            self._parse_target_xml(desc)

        # Target already halted at the top of connect()

        # Read registers to get initial state
        self._refresh_regs()
        if self._context_regs and "Rip" in self._context_regs:
            self.current_pc = self._context_regs["Rip"]

        self.connected = True
        return True, "Connected via GDB stub"

    # ------------------------------------------------------------------
    # Target XML parsing — discover register indices (gs_base, etc.)
    # ------------------------------------------------------------------

    def _parse_target_xml(self, root_xml: bytes):
        """Parse target XML and included sub-XMLs to build register index map."""
        import re
        text = root_xml.decode("ascii", errors="replace")
        # Strip qXfer prefix ('l' = last, 'm' = more)
        if text and text[0] in "lm":
            text = text[1:]

        # Collect all XML content (root + included files)
        all_xml = [text]
        for href in re.findall(r'href="([^"]+)"', text):
            sub = self._transport.command(f"qXfer:features:read:{href}:0,ffff")
            if sub:
                s = sub.decode("ascii", errors="replace")
                if s and s[0] in "lm":
                    s = s[1:]
                all_xml.append(s)

        # Parse <reg> elements, track index sequentially
        idx = 0
        for xml in all_xml:
            for m in re.finditer(
                r'<reg\s+[^>]*name="([^"]+)"[^>]*bitsize="(\d+)"[^>]*/?>',
                xml,
            ):
                name = m.group(1)
                # Check for explicit regnum override
                rn = re.search(r'regnum="(\d+)"', m.group(0))
                if rn:
                    idx = int(rn.group(1))
                self._reg_index_map[name] = idx
                idx += 1

    def read_register(self, name: str) -> int | None:
        """Read a single register by name (e.g. 'gs_base'). Uses 'p' command."""
        idx = self._reg_index_map.get(name)
        if idx is None:
            return None
        resp = self._transport.command(f"p{idx:x}")
        if resp is None or resp.startswith(b"E"):
            return None
        try:
            raw = bytes.fromhex(resp.decode("ascii"))
            return int.from_bytes(raw, "little")
        except (ValueError, UnicodeDecodeError):
            return None

    def read_msr_lstar(self) -> int:
        """Read MSR LSTAR (0xC0000082) — contains KiSystemCall64 address.

        Tries multiple methods:
          1. 'p' command for 'lstar' register (if exposed in target XML)
          2. Parse QEMU monitor 'info registers' for LSTAR= line
        """
        # Method 1: direct register read (fast, 1 RTT)
        val = self.read_register("lstar")
        if val and val > 0xFFFF800000000000:
            return val

        # Method 2: parse monitor output (slower, but works on all QEMU)
        import re
        text = self._transport.monitor_command("info registers")
        m = re.search(r"LSTAR\s*=\s*([0-9a-fA-F]+)", text)
        if m:
            v = int(m.group(1), 16)
            if v > 0xFFFF800000000000:
                return v
        return 0

    def read_gs_base(self) -> int:
        """Read kernel GS base (points to KPCR on Windows x64)."""
        # Try gs_base first (most QEMU versions expose this)
        val = self.read_register("gs_base")
        if val and val > 0xFFFF800000000000:
            return val
        # Try kernel_gs_base (swapped by swapgs)
        val = self.read_register("k_gs_base")
        if val and val > 0xFFFF800000000000:
            return val
        return 0

    def read_idt_base(self) -> int:
        """Read IDT base address via gs_base -> KPCR+0x38.

        On x64 Windows, gs_base (GDB reg #25) points to KPCR.
        KPCR+0x38 = IdtBase. Two register/memory reads, no monitor parsing.
        Falls back to QEMU monitor if gs_base is unavailable.
        """
        import struct as _struct
        gs = self._read_raw_register(25)  # gs_base
        if gs and gs > 0xFFFF800000000000:
            idt_data = self.read_virtual(gs + 0x38, 8)
            if idt_data and len(idt_data) == 8:
                idt = _struct.unpack("<Q", idt_data)[0]
                if idt > 0xFFFF800000000000:
                    return idt
        # Fallback: parse monitor output
        import re
        text = self._transport.monitor_command("info registers")
        m = re.search(r"IDT\s*=\s*([0-9a-fA-F]+)", text)
        if m:
            return int(m.group(1), 16)
        return 0

    def _read_raw_register(self, index: int) -> int:
        """Read a register by its GDB index number. Returns value or 0."""
        resp = self._transport.command(f"p{index:x}")
        if resp is None or resp.startswith(b"E"):
            return 0
        try:
            raw = bytes.fromhex(resp.decode("ascii"))
            return int.from_bytes(raw, "little")
        except (ValueError, UnicodeDecodeError):
            return 0

    # ------------------------------------------------------------------
    # Register access
    # ------------------------------------------------------------------

    def _refresh_regs(self):
        """Read all registers from target."""
        resp = self._transport.command("g")
        if resp is None:
            return

        self._raw_regs_hex = resp
        self._context_regs = {}

        hex_str = resp.decode("ascii", errors="replace")
        off = 0
        for name, byte_size in self._REG_LAYOUT_64:
            hex_len = byte_size * 2
            if off + hex_len > len(hex_str):
                break
            raw = bytes.fromhex(hex_str[off:off + hex_len])
            val = int.from_bytes(raw, "little")
            kd_name = self._GDB_TO_KD.get(name, name)
            self._context_regs[kd_name] = val
            off += hex_len

        if "Rip" in self._context_regs:
            self.current_pc = self._context_regs["Rip"]
        self._regs_fresh = True

    def get_context(self) -> dict:
        """Read CPU registers. Returns {name: value} dict.

        Skips the network read if registers were already fetched by
        wait_break() and haven't been invalidated by continue/step.
        """
        if not self._regs_fresh:
            self._refresh_regs()
        return dict(self._context_regs) if self._context_regs else {}

    def set_context(self, regs_to_set: dict) -> bool:
        """Write modified registers back. Accepts KD-style names (Rax, Rip, etc.)."""
        if self._raw_regs_hex is None:
            self._refresh_regs()
        if self._raw_regs_hex is None:
            return False

        # Reverse map: KD name -> GDB name
        kd_to_gdb = {v: k for k, v in self._GDB_TO_KD.items()}

        # Build offset table: gdb_name -> (hex_offset, byte_size)
        reg_offsets = {}
        hex_off = 0
        for gdb_name, byte_size in self._REG_LAYOUT_64:
            reg_offsets[gdb_name] = (hex_off, byte_size)
            hex_off += byte_size * 2

        hex_str = bytearray(self._raw_regs_hex)
        for name, value in regs_to_set.items():
            gdb_name = kd_to_gdb.get(name, name)
            if gdb_name in reg_offsets:
                off, byte_size = reg_offsets[gdb_name]
                raw = value.to_bytes(byte_size, "little")
                hex_len = byte_size * 2
                hex_str[off:off + hex_len] = raw.hex().encode()

        resp = self._transport.command("G" + hex_str.decode())
        return resp is not None and resp.startswith(b"OK")

    # ------------------------------------------------------------------
    # Memory access
    # ------------------------------------------------------------------

    def read_virtual(self, address: int, size: int) -> bytes:
        """Read virtual memory from the target.

        Transparently restores original bytes at software breakpoint
        addresses so the INT3 (0xCC) patch is invisible to callers.
        """
        result = b""
        remaining = size
        addr = address

        while remaining > 0:
            chunk = min(remaining, self._max_read_chunk)
            resp = self._transport.command(f"m{addr:x},{chunk:x}")
            if resp is None or resp.startswith(b"E"):
                break

            try:
                data = bytes.fromhex(resp.decode("ascii"))
            except (ValueError, UnicodeDecodeError):
                break

            result += data
            addr += len(data)
            remaining -= len(data)

            if len(data) < chunk:
                break

        # Mask software breakpoints: replace CC with saved original byte
        if self._sw_bp_orig and result:
            buf = None
            for bp_addr, orig_byte in self._sw_bp_orig.items():
                off = bp_addr - address
                if 0 <= off < len(result) and result[off] == 0xCC:
                    if buf is None:
                        buf = bytearray(result)
                    buf[off] = orig_byte
            if buf is not None:
                result = bytes(buf)

        return result

    def write_virtual(self, address: int, data: bytes) -> bool:
        """Write virtual memory to the target."""
        hex_data = data.hex()
        resp = self._transport.command(f"M{address:x},{len(data):x}:{hex_data}")
        return resp is not None and resp.startswith(b"OK")

    def read_physical(self, address: int, size: int) -> bytes:
        """Read physical memory via QEMU monitor `xp` command.

        QEMU's standard `m` GDB packet reads VIRTUAL memory through the
        current CPU's page tables. To walk page tables themselves we need
        true physical reads, which QEMU exposes via the monitor command
        `xp /Nbx <addr>` (eXamine Physical).

        Slow (~1 RTT per call due to monitor parsing) but correct.
        Returns empty bytes on failure.
        """
        if size <= 0:
            return b""
        # `xp /Nbx <addr>` prints N bytes in hex form, e.g.
        # "0000000000001000: 0xfa  0x33  0xc0  ..."
        out = self._transport.monitor_command(f"xp /{size}bx 0x{address:x}")
        if not out:
            return b""
        result = bytearray()
        for token in out.replace("\r", " ").replace("\n", " ").split():
            if token.startswith("0x") and len(token) <= 4:
                try:
                    result.append(int(token, 16) & 0xFF)
                except ValueError:
                    pass
            if len(result) >= size:
                break
        return bytes(result[:size])

    def pipeline_read(self, reads: list[tuple[int, int]]) -> list[bytes]:
        """Pipelined memory reads — sends all requests at once.

        Args:
            reads: list of (address, size) tuples. Each size must be
                   <= _max_read_chunk.
        Returns:
            list of bytes (empty bytes on error) in same order as reads.
        """
        cmds = [f"m{addr:x},{sz:x}" for addr, sz in reads]
        responses = self._transport.pipeline(cmds)
        results = []
        for resp in responses:
            if resp is None or resp.startswith(b"E"):
                results.append(b"")
            else:
                try:
                    results.append(bytes.fromhex(resp.decode("ascii")))
                except (ValueError, UnicodeDecodeError):
                    results.append(b"")
        return results

    def read_virtual_pipelined(self, address: int, size: int) -> bytes:
        """Read virtual memory using pipelined GDB commands.

        Splits the read into _max_read_chunk-sized pieces and sends
        all requests at once, then collects responses. ~50x faster
        than sequential read_virtual for large reads.
        """
        if size <= self._max_read_chunk:
            return self.read_virtual(address, size)

        chunks = []
        addr = address
        remaining = size
        while remaining > 0:
            n = min(remaining, self._max_read_chunk)
            chunks.append((addr, n))
            addr += n
            remaining -= n

        cmds = [f"m{a:x},{s:x}" for a, s in chunks]
        responses = self._transport.pipeline(cmds)

        result = b""
        for resp in responses:
            if resp is None or resp.startswith(b"E"):
                break
            try:
                data = bytes.fromhex(resp.decode("ascii"))
            except (ValueError, UnicodeDecodeError):
                break
            result += data
        return result

    def batch_probe_mz(self, addrs: list[int]) -> int:
        """Pipeline-probe multiple addresses for MZ header.

        Sends all 2-byte reads at once via pipeline, returns the first
        address that has an MZ signature, or 0 if none found.
        """
        reads = [(addr, 2) for addr in addrs]
        results = self.pipeline_read(reads)
        for addr, data in zip(addrs, results):
            if data == b"MZ":
                return addr
        return 0

    # ------------------------------------------------------------------
    # Page cache — reduces RTTs by caching 4KB pages locally
    # ------------------------------------------------------------------

    def read_cached(self, address: int, size: int) -> bytes:
        """Read from page cache, fetching on miss.

        Concatenates data across page boundaries. Falls back to a single
        read_virtual() if any page is missing from the cache.
        """
        result = b""
        cur = address
        remaining = size
        while remaining > 0:
            page = cur & ~0xFFF
            offset = cur - page
            data = self._page_cache.get(page)
            if data is None:
                # Cache miss — fetch the page
                data = self.read_virtual(page, 0x1000)
                if data and len(data) == 0x1000:
                    self._page_cache[page] = data
                elif data:
                    # Partial page (edge of valid memory)
                    self._page_cache[page] = data + b"\x00" * (0x1000 - len(data))
                    data = self._page_cache[page]
                else:
                    break
            avail = min(remaining, len(data) - offset)
            if avail <= 0:
                break
            result += data[offset:offset + avail]
            cur += avail
            remaining -= avail
        return result

    def prefetch_pages(self, page_addrs):
        """Batch-prefetch multiple pages, merging contiguous into large reads.

        Args:
            page_addrs: iterable of page-aligned addresses to prefetch.
                        Non-cached pages are fetched; already-cached pages are skipped.

        Merges contiguous pages into reads of up to _max_read_chunk bytes
        to minimize the number of network round-trips.
        """
        # Filter out already-cached pages
        needed = sorted(set(p & ~0xFFF for p in page_addrs) - self._page_cache.keys())
        if not needed:
            return

        # Merge contiguous pages into large reads
        max_chunk = max(self._max_read_chunk, 0x1000)
        i = 0
        while i < len(needed):
            start = needed[i]
            end = start + 0x1000
            while (i + 1 < len(needed)
                   and needed[i + 1] == end
                   and end - start < max_chunk):
                i += 1
                end = needed[i] + 0x1000
            # Read the merged range
            data = self.read_virtual(start, end - start)
            if data:
                for off in range(0, len(data), 0x1000):
                    pg = start + off
                    page_data = data[off:off + 0x1000]
                    if len(page_data) == 0x1000:
                        self._page_cache[pg] = page_data
                    elif page_data:
                        self._page_cache[pg] = page_data + b"\x00" * (0x1000 - len(page_data))
            i += 1

    def mark_code_pages(self, page_addrs):
        """Mark pages as executable/code — these survive invalidate_data_pages()."""
        for p in page_addrs:
            self._code_pages.add(p & ~0xFFF)

    def invalidate_data_pages(self):
        """Clear data pages from cache, keeping code pages.

        Called after step/continue: data (stack, heap) may have changed,
        but code pages are assumed stable between steps.
        """
        code_entries = {pg: self._page_cache[pg]
                        for pg in self._code_pages
                        if pg in self._page_cache}
        self._page_cache.clear()
        self._page_cache.update(code_entries)

    # ------------------------------------------------------------------
    # Breakpoints — hardware by default (no memory patching)
    # ------------------------------------------------------------------

    # Max 4 hardware breakpoints (DR0-DR3)
    _MAX_HW_BP = 4

    def set_breakpoint(self, address: int, hardware: bool = True) -> int:
        """Set a breakpoint. Hardware by default (no INT3 patching).

        Hardware breakpoints (Z1) use DR0-DR3 debug registers:
          - No memory modification (code pages stay intact)
          - Max 4 simultaneous breakpoints
          - Works safely in kernel mode (no PatchGuard issues)

        Falls back to software breakpoint (Z0) if hardware fails
        or if hardware=False is explicitly requested.
        """
        if hardware:
            hw_count = sum(1 for _, (_, hw) in self._breakpoints.items() if hw)
            if hw_count < self._MAX_HW_BP:
                resp = self._transport.command(f"Z1,{address:x},1")
                if resp is not None and resp.startswith(b"OK"):
                    handle = self._next_bp_handle
                    self._next_bp_handle += 1
                    self._breakpoints[handle] = (address, True)  # (addr, is_hardware)
                    return handle

        # Software breakpoint fallback (saves original byte for read transparency)
        orig = self.read_virtual(address, 1)
        resp = self._transport.command(f"Z0,{address:x},1")
        if resp is not None and resp.startswith(b"OK"):
            handle = self._next_bp_handle
            self._next_bp_handle += 1
            self._breakpoints[handle] = (address, False)
            if orig:
                self._sw_bp_orig[address] = orig[0]
            return handle
        return -1

    def remove_breakpoint(self, handle: int) -> bool:
        """Remove a breakpoint by handle."""
        entry = self._breakpoints.pop(handle, None)
        if entry is None:
            return False
        addr, is_hw = entry
        cmd = f"z1,{addr:x},1" if is_hw else f"z0,{addr:x},1"
        resp = self._transport.command(cmd)
        if not is_hw:
            self._sw_bp_orig.pop(addr, None)
        return resp is not None and resp.startswith(b"OK")

    # ------------------------------------------------------------------
    # Execution control
    # ------------------------------------------------------------------

    def _disable_hw_bp_at_pc(self):
        """Temporarily disable hardware breakpoints at current PC.

        When sitting on a hardware breakpoint, the CPU will re-trigger
        it immediately on step/continue. We must disable it first,
        then re-enable after the step completes.
        Returns list of (handle, address) that were disabled.
        """
        disabled = []
        pc = self.current_pc
        for handle, (addr, is_hw) in self._breakpoints.items():
            if is_hw and addr == pc:
                self._transport.command(f"z1,{addr:x},1")
                disabled.append((handle, addr))
        return disabled

    def _reenable_hw_bps(self, disabled):
        """Re-enable hardware breakpoints that were temporarily disabled."""
        for handle, addr in disabled:
            if handle in self._breakpoints:
                self._transport.command(f"Z1,{addr:x},1")

    def do_continue(self, status: int = 0):
        """Continue execution."""
        # If sitting on a hw bp, step past it first then continue
        disabled = self._disable_hw_bp_at_pc()
        if disabled:
            self._transport.send_packet("s")
            self.stopped = False
            resp = self._transport.recv_packet(timeout=10.0)
            self.stopped = True
            self._reenable_hw_bps(disabled)
            # Now continue for real
        self._transport.send_packet("c")
        self.stopped = False
        self._context_regs = None
        self._regs_fresh = False
        self.invalidate_data_pages()

    def do_step(self):
        """Single-step one instruction."""
        disabled = self._disable_hw_bp_at_pc()
        self._transport.send_packet("s")
        self.stopped = False
        self._context_regs = None
        self._regs_fresh = False
        self.invalidate_data_pages()
        # Store for re-enabling in wait_break
        self._pending_reenable = disabled

    def wait_break(self, timeout: float = 60.0):
        """Wait for target to stop (after continue/step)."""
        resp = self._transport.recv_packet(timeout=timeout)
        if resp is None:
            return None

        self.stopped = True
        # Re-enable any hw bps that were disabled for stepping
        pending = getattr(self, '_pending_reenable', [])
        if pending:
            self._reenable_hw_bps(pending)
            self._pending_reenable = []

        self._refresh_regs()

        # Parse stop reason (T05 = SIGTRAP, etc.)
        reason = resp.decode("ascii", errors="replace")
        if reason.startswith("T") or reason.startswith("S"):
            signal = int(reason[1:3], 16)
            self.exception_code = signal

        return {
            "pc": self.current_pc,
            "thread": self.current_thread,
            "cpu": self.current_cpu,
            "exception_code": self.exception_code,
        }

    def do_break(self):
        """Send break (Ctrl+C) to interrupt the running target."""
        self._transport.send_interrupt()

    # ------------------------------------------------------------------
    # Version info
    # ------------------------------------------------------------------

    def get_version(self):
        """Return target info."""
        return {
            "os_version": "QEMU GDB Stub",
            "machine": self.machine_type,
            "is_64bit": self.is_64bit,
            "kernel_base": self.kernel_base,
            "ps_loaded_module_list": 0,
            "proto": "GDB RSP",
        }

    # ------------------------------------------------------------------
    # Disconnect
    # ------------------------------------------------------------------

    def disconnect(self):
        """Disconnect from target."""
        if self.stopped:
            try:
                self.do_continue()
            except Exception:
                pass
        self._transport.close()
        self.connected = False
