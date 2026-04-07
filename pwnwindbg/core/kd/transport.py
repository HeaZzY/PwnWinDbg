"""KD transport layer: abstract base + KDNET (UDP) + Named Pipe implementations."""

import abc
import ctypes
import hashlib
import hmac
import os
import socket
import struct
import time


class KdTransport(abc.ABC):
    """Abstract base for KD transports."""

    @abc.abstractmethod
    def connect(self):
        """Establish connection to the debug target."""

    @abc.abstractmethod
    def send(self, data: bytes):
        """Send raw bytes."""

    @abc.abstractmethod
    def recv(self, size: int, timeout: float = 5.0) -> bytes:
        """Receive up to `size` bytes. Returns b'' on timeout."""

    @abc.abstractmethod
    def close(self):
        """Close the transport."""

    @property
    @abc.abstractmethod
    def is_connected(self) -> bool:
        """Whether the transport is connected."""


# ---------------------------------------------------------------------------
# KDNET transport (UDP + AES-256-CBC + HMAC-SHA256)
# ---------------------------------------------------------------------------

def _base36_decode(s: str) -> int:
    """Decode a base36 string to int."""
    return int(s, 36)


def _derive_keys(key_str: str):
    """Derive control key, HMAC key from the bcdedit key string.

    Key format: "x.x.x.x" where each x is a base36-encoded 64-bit value.
    Returns (control_key_32B, hmac_key_32B).
    """
    parts = key_str.strip().split(".")
    if len(parts) != 4:
        raise ValueError(f"Invalid KDNET key format (expected 4 parts): {key_str}")

    control_key = b""
    for part in parts:
        val = _base36_decode(part)
        control_key += struct.pack("<Q", val)

    # HMAC key = bitwise NOT of control key
    hmac_key = bytes(~b & 0xFF for b in control_key)
    return control_key, hmac_key


class KdnetTransport(KdTransport):
    """KDNET transport — UDP with AES-256-CBC encryption + HMAC-SHA256.

    Protocol flow (from pcap analysis of WinDbg):
      Phase 1 — Solicitation (unencrypted, magic = "GBDM"):
        Debugger sends 4 GBDM packets (6B, 22B, 38B, 54B) per round.
        Target responds with encrypted MDBG poke (374B, ver=5, type=1).
      Phase 2 — Handshake (encrypted, magic = "MDBG"):
        Debugger sends encrypted MDBG response (38B, ver=2, type=1).
        Target sends encrypted MDBG poke (374B, ver=5, type=1).
        Debugger sends encrypted MDBG (358B, ver=5, type=1).
      Phase 3 — Session (encrypted, magic = "MDBG"):
        Both sides exchange MDBG data/control packets.

    Two different magic values:
      - b'GBDM' (0x4D444247 LE) — unencrypted solicitation from debugger
      - b'MDBG' (0x4742444D LE) — encrypted session packets (both directions)
    """

    MAGIC_GBDM = 0x4D444247  # b'GBDM' as LE u32 — solicitation
    MAGIC_MDBG = 0x4742444D  # b'MDBG' as LE u32 — encrypted session

    def __init__(self, target_ip: str, port: int, key_str: str):
        self._target_ip = target_ip
        self._port = port
        self._key_str = key_str

        self._sock = None
        self._connected = False
        self._target_addr = (target_ip, port)  # send to target directly

        # Keys
        self._control_key, self._hmac_key = _derive_keys(key_str)
        self._data_key = None  # derived after handshake

        # Sequence
        self._seq_send = 0
        self._seq_recv = 0

    @property
    def is_connected(self) -> bool:
        return self._connected

    def connect(self):
        """Create UDP socket and set target address."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Bind to any local port (OS picks one)
        self._sock.bind(("0.0.0.0", 0))
        self._sock.settimeout(30.0)
        self._connected = True

    def close(self):
        if self._sock:
            self._sock.close()
            self._sock = None
        self._connected = False
        self._data_key = None

    def send_raw_udp(self, data: bytes, addr=None):
        """Send raw UDP datagram."""
        dest = addr or self._target_addr
        if dest and self._sock:
            self._sock.sendto(data, dest)

    def recv_raw_udp(self, timeout: float = 5.0):
        """Receive a raw UDP datagram. Returns (data, addr) or (None, None)."""
        old_timeout = self._sock.gettimeout()
        self._sock.settimeout(timeout)
        try:
            data, addr = self._sock.recvfrom(65536)
            if self._target_addr is None:
                self._target_addr = addr
            return data, addr
        except socket.timeout:
            return None, None
        finally:
            self._sock.settimeout(old_timeout)

    # ---- Encryption helpers ----

    def _aes_decrypt(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        """AES-256-CBC decrypt."""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        dec = cipher.decryptor()
        return dec.update(data) + dec.finalize()

    def _aes_encrypt(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        """AES-256-CBC encrypt."""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        enc = cipher.encryptor()
        return enc.update(data) + enc.finalize()

    def _compute_hmac(self, data: bytes) -> bytes:
        """HMAC-SHA256, truncated to 16 bytes."""
        h = hmac.new(self._hmac_key, data, hashlib.sha256)
        return h.digest()[:16]

    def _pad_to_16(self, data: bytes) -> tuple:
        """Pad data to 16-byte boundary. Returns (padded_data, padding_size)."""
        remainder = len(data) % 16
        if remainder == 0:
            return data, 0
        pad_size = 16 - remainder
        return data + b'\x00' * pad_size, pad_size

    def decrypt_packet(self, raw: bytes):
        """Decrypt a KDNET UDP packet.

        Format: [KDNet Header 6B][Encrypted: KDNet Data 8B + KD payload (padded to 16B)][HMAC 16B]

        Accepts both GBDM and MDBG magic (target always sends MDBG).
        Returns (kdnet_type, kd_payload) or (None, None) on failure.
        """
        if len(raw) < 6 + 8 + 16:
            return None, None

        # KDNet header (6 bytes, unencrypted)
        magic = struct.unpack_from("<I", raw, 0)[0]
        if magic not in (self.MAGIC_MDBG, self.MAGIC_GBDM):
            return None, None
        version = raw[4]
        kdnet_type = raw[5]  # 0=Data, 1=Control

        # HMAC is the last 16 bytes
        hmac_tag = raw[-16:]
        encrypted = raw[6:-16]

        if len(encrypted) == 0 or len(encrypted) % 16 != 0:
            return None, None

        # Choose key based on type
        key = self._data_key if (kdnet_type == 0 and self._data_key) else self._control_key

        # IV = HMAC tag
        iv = hmac_tag

        # Decrypt
        try:
            decrypted = self._aes_decrypt(encrypted, key, iv)
        except Exception:
            # Try with the other key (control vs data)
            alt_key = self._control_key if key != self._control_key else self._data_key
            if alt_key:
                try:
                    decrypted = self._aes_decrypt(encrypted, alt_key, iv)
                except Exception:
                    return None, None
            else:
                return None, None

        # First 8 bytes of decrypted = KDNet data header
        if len(decrypted) < 8:
            return None, None
        kdnet_data = decrypted[:8]
        direction_and_pad = kdnet_data[0]
        padding_size = direction_and_pad & 0x7F

        # KD payload is the rest minus padding
        kd_payload = decrypted[8:]
        if padding_size > 0 and padding_size < len(kd_payload):
            kd_payload = kd_payload[:len(kd_payload) - padding_size]

        return kdnet_type, kd_payload

    def encrypt_packet(self, kdnet_type: int, kd_payload: bytes,
                       version: int = 1) -> bytes:
        """Encrypt and build a KDNET MDBG packet.

        Encrypted session packets always use MDBG magic (not GBDM).
        """
        # Build KDNet data header (8 bytes)
        padded_payload, pad_size = self._pad_to_16(kd_payload)
        # direction bit (0x80 = from debugger), padding in lower 7 bits
        direction_and_pad = 0x80 | (pad_size & 0x7F)

        # Sequence number in bytes 1-3 (24-bit LE)
        seq = self._seq_send & 0xFFFFFF
        self._seq_send += 1

        kdnet_data = struct.pack("<B", direction_and_pad)
        kdnet_data += struct.pack("<I", seq)[:3]  # 3 bytes of sequence
        kdnet_data += b'\x00' * 4  # padding to 8 bytes

        plaintext = kdnet_data + padded_payload

        key = self._data_key if (kdnet_type == 0 and self._data_key) else self._control_key

        # MDBG header (6 bytes) — encrypted packets use MDBG magic
        header = struct.pack("<I", self.MAGIC_MDBG) + bytes([version, kdnet_type])

        # HMAC over header + plaintext
        hmac_input = header + plaintext
        hmac_tag = self._compute_hmac(hmac_input)

        # IV = HMAC tag
        iv = hmac_tag

        # Encrypt
        encrypted = self._aes_encrypt(plaintext, key, iv)

        # Final packet: header + encrypted + HMAC
        return header + encrypted + hmac_tag

    def _send_gbdm_solicitation(self, version: int = 0, ptype: int = 1):
        """Send 4 unencrypted GBDM solicitation packets like WinDbg.

        WinDbg sends 4 GBDM packets per round with sizes 6, 22, 38, 54 bytes:
          [GBDM(4B)][ver(1B)][type(1B)] + zeros(0/16/32/48B)
        """
        header = b'GBDM' + bytes([version, ptype])
        for extra in [0, 16, 32, 48]:
            pkt = header + b'\x00' * extra
            self.send_raw_udp(pkt)
            time.sleep(0.005)

    def wait_for_poke(self, timeout: float = 60.0):
        """Solicit and wait for the target's initial Poke control packet.

        Sends unencrypted GBDM solicitation rounds (like WinDbg),
        then waits for an encrypted MDBG poke response from the target.

        Returns the raw MDBG poke packet (for send_response) or None on timeout.
        """
        deadline = time.time() + timeout
        round_num = 0
        # WinDbg sends GBDM with increasing version numbers: (0,1), (1,0), (1,1), (2,0), (2,1), (3,0)
        versions = [(0, 1), (1, 0), (1, 1), (2, 0), (2, 1), (3, 0), (3, 1)]

        while time.time() < deadline:
            # Send GBDM solicitation round
            ver, typ = versions[round_num % len(versions)]
            self._send_gbdm_solicitation(ver, typ)
            round_num += 1

            # Wait for MDBG poke response (target sends ~374B encrypted MDBG)
            remaining = deadline - time.time()
            raw, addr = self.recv_raw_udp(timeout=min(remaining, 3.0))
            if raw is None:
                continue

            # Update target addr if response from different port
            if addr:
                self._target_addr = addr

            # Check if this is an MDBG packet from target
            if len(raw) >= 6:
                magic = struct.unpack_from("<I", raw, 0)[0]
                if magic == self.MAGIC_MDBG:
                    # Got MDBG poke — return raw packet for handshake processing
                    return raw

            # Also try decrypt in case magic is GBDM (unlikely but handle it)
            kdnet_type, payload = self.decrypt_packet(raw)
            if kdnet_type is not None:
                return raw

        return None

    def send_response(self, poke_raw: bytes):
        """Handle the poke packet and send the handshake response.

        poke_raw is the raw MDBG packet from wait_for_poke.
        Tries to decrypt it, then sends a response, and derives the data key.
        """
        # Try to decrypt the poke to extract its payload
        kdnet_type, poke_payload = self.decrypt_packet(poke_raw)
        if poke_payload is None:
            # Can't decrypt — use raw data minus header/HMAC as best-effort
            poke_payload = poke_raw[6:-16] if len(poke_raw) > 22 else poke_raw

        # Extract client key from poke payload (first 32 bytes if available)
        client_key = poke_payload[:32] if len(poke_payload) >= 32 else poke_payload.ljust(32, b'\x00')
        host_key = os.urandom(32)

        response_buf = b'\x01\x02' + client_key + host_key + b'\x00' * 256
        # Send as encrypted MDBG control packet (ver=2, type=1 per pcap)
        packet = self.encrypt_packet(1, response_buf, version=2)
        self.send_raw_udp(packet)

        # Derive data key = SHA256(control_key || response_buf)
        self._data_key = hashlib.sha256(self._control_key + response_buf).digest()
        return True

    # ---- KdTransport interface (send/recv KD payloads) ----

    def send(self, data: bytes):
        """Send a KD packet payload over KDNET."""
        packet = self.encrypt_packet(0, data)  # type=0 (data)
        self.send_raw_udp(packet)

    def recv(self, size: int = 65536, timeout: float = 5.0) -> bytes:
        """Receive a KD packet payload from KDNET. Returns b'' on timeout."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = deadline - time.time()
            raw, addr = self.recv_raw_udp(timeout=min(remaining, 2.0))
            if raw is None:
                continue
            kdnet_type, payload = self.decrypt_packet(raw)
            if payload is not None:
                return payload
        return b''


# ---------------------------------------------------------------------------
# Named Pipe transport (for VM debugging)
# ---------------------------------------------------------------------------

class PipeTransport(KdTransport):
    """Named pipe transport for VM kernel debugging.

    Two modes:
      client (default): VBox creates the pipe, we connect to it.
        VBox: "Create Pipe" checked, pwnWinDbg connects after VM starts.
      server: We create the pipe, VBox connects to it.
        VBox: "Connect to existing pipe" checked, pwnWinDbg starts first.

    E.g. pipe_path = r"\\\\.\\pipe\\kd_pipe"
    """

    INVALID_HANDLE = ctypes.c_void_p(-1).value

    def __init__(self, pipe_path: str, server: bool = False):
        self._pipe_path = pipe_path
        self._server = server
        self._handle = None
        self._connected = False
        self._setup_api()

    def _setup_api(self):
        """Configure ctypes prototypes for proper 64-bit HANDLE support."""
        import ctypes.wintypes as w

        k32 = ctypes.windll.kernel32

        k32.CreateNamedPipeW.argtypes = [
            w.LPCWSTR, w.DWORD, w.DWORD, w.DWORD,
            w.DWORD, w.DWORD, w.DWORD, ctypes.c_void_p,
        ]
        k32.CreateNamedPipeW.restype = ctypes.c_void_p

        k32.ConnectNamedPipe.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        k32.ConnectNamedPipe.restype = w.BOOL

        k32.CreateFileW.argtypes = [
            w.LPCWSTR, w.DWORD, w.DWORD, ctypes.c_void_p,
            w.DWORD, w.DWORD, ctypes.c_void_p,
        ]
        k32.CreateFileW.restype = ctypes.c_void_p

        k32.WaitNamedPipeW.argtypes = [w.LPCWSTR, w.DWORD]
        k32.WaitNamedPipeW.restype = w.BOOL

        k32.WriteFile.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, w.DWORD,
            ctypes.POINTER(w.DWORD), ctypes.c_void_p,
        ]
        k32.WriteFile.restype = w.BOOL

        k32.ReadFile.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, w.DWORD,
            ctypes.POINTER(w.DWORD), ctypes.c_void_p,
        ]
        k32.ReadFile.restype = w.BOOL

        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        k32.CloseHandle.restype = w.BOOL

        self._k32 = k32

    @property
    def is_connected(self) -> bool:
        return self._connected

    def _connect_client(self):
        """Connect as client to an existing pipe (VBox created it)."""
        GENERIC_READ_WRITE = 0x80000000 | 0x40000000
        OPEN_EXISTING = 3

        for attempt in range(10):
            h = self._k32.CreateFileW(
                self._pipe_path,
                GENERIC_READ_WRITE,
                0, None, OPEN_EXISTING, 0, None,
            )
            if h is not None and h != self.INVALID_HANDLE:
                self._handle = h
                self._connected = True
                return

            err = ctypes.windll.kernel32.GetLastError()
            if err == 231:  # ERROR_PIPE_BUSY
                # Wait up to 3s for the pipe instance to become free
                self._k32.WaitNamedPipeW(self._pipe_path, 3000)
                continue
            elif err == 2:  # ERROR_FILE_NOT_FOUND — pipe doesn't exist yet
                time.sleep(1)
                continue
            else:
                raise ConnectionError(
                    f"Cannot open pipe: {self._pipe_path} (error {err})"
                )

        raise ConnectionError(
            f"Cannot connect to pipe after retries: {self._pipe_path}\n"
            f"  If pipe is busy, try server mode: kdconnect pipe:{self._pipe_path} server"
        )

    def _connect_server(self):
        """Create pipe server and wait for VM to connect."""
        PIPE_ACCESS_DUPLEX = 0x00000003

        h = self._k32.CreateNamedPipeW(
            self._pipe_path,
            PIPE_ACCESS_DUPLEX,
            0,     # PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT
            1,     # max instances
            4096,  # out buffer
            4096,  # in buffer
            0,     # default timeout
            None,  # security
        )
        if h is None or h == self.INVALID_HANDLE:
            err = ctypes.windll.kernel32.GetLastError()
            raise ConnectionError(
                f"Cannot create pipe: {self._pipe_path} (error {err})"
            )
        self._handle = h

        ok = self._k32.ConnectNamedPipe(self._handle, None)
        if not ok:
            err = ctypes.windll.kernel32.GetLastError()
            if err != 535:  # ERROR_PIPE_CONNECTED = already connected, OK
                self._k32.CloseHandle(self._handle)
                self._handle = None
                raise ConnectionError(
                    f"ConnectNamedPipe failed (error {err})"
                )
        self._connected = True

    def connect(self):
        if self._server:
            self._connect_server()
        else:
            self._connect_client()

    def send(self, data: bytes):
        import ctypes.wintypes as w
        written = w.DWORD(0)
        self._k32.WriteFile(
            self._handle, data, len(data), ctypes.byref(written), None,
        )

    def recv(self, size: int = 4096, timeout: float = 5.0) -> bytes:
        import ctypes.wintypes as w
        buf = ctypes.create_string_buffer(size)
        nread = w.DWORD(0)
        ok = self._k32.ReadFile(
            self._handle, buf, size, ctypes.byref(nread), None,
        )
        if ok:
            return buf.raw[:nread.value]
        return b''

    def close(self):
        if self._handle is not None and self._handle != self.INVALID_HANDLE:
            self._k32.CloseHandle(self._handle)
            self._handle = None
        self._connected = False
