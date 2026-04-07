"""KD packet-level protocol: encode, decode, ack, resync."""

import struct
from .kd_structs import (
    PACKET_LEADER, CONTROL_PACKET_LEADER, BREAKIN_PACKET_BYTE,
    PACKET_TRAILING_BYTE, INITIAL_PACKET_ID,
    PACKET_TYPE_KD_ACKNOWLEDGE, PACKET_TYPE_KD_RESEND,
    PACKET_TYPE_KD_RESET, PACKET_TYPE_KD_STATE_CHANGE64,
    PACKET_TYPE_KD_STATE_MANIPULATE, PACKET_TYPE_KD_DEBUG_IO,
    KD_PACKET_HEADER_FORMAT, KD_PACKET_HEADER_SIZE,
)


def kd_checksum(data: bytes) -> int:
    """Compute KD checksum: sum of all bytes, as uint32."""
    return sum(data) & 0xFFFFFFFF


def build_packet(pkt_type: int, payload: bytes, packet_id: int) -> bytes:
    """Build a KD data packet (leader + header + payload + trailer)."""
    cksum = kd_checksum(payload)
    header = struct.pack(
        KD_PACKET_HEADER_FORMAT,
        PACKET_LEADER,
        pkt_type,
        len(payload),
        packet_id,
        cksum,
    )
    return header + payload + bytes([PACKET_TRAILING_BYTE])


def build_control_packet(pkt_type: int, packet_id: int = 0) -> bytes:
    """Build a KD control packet (no payload, no trailer)."""
    header = struct.pack(
        KD_PACKET_HEADER_FORMAT,
        CONTROL_PACKET_LEADER,
        pkt_type,
        0,       # length
        packet_id,
        0,       # checksum
    )
    return header


def parse_packet_header(data: bytes):
    """Parse a 16-byte KD packet header.

    Returns dict with: leader, type, length, id, checksum.
    Returns None if data is too short.
    """
    if len(data) < KD_PACKET_HEADER_SIZE:
        return None
    leader, ptype, length, pid, cksum = struct.unpack_from(
        KD_PACKET_HEADER_FORMAT, data, 0
    )
    return {
        "leader": leader,
        "type": ptype,
        "length": length,
        "id": pid,
        "checksum": cksum,
    }


class KdProtocol:
    """Manages KD packet exchange over a transport.

    Handles: send/recv packets, ACKs, sequence numbering, resync.
    Works with both raw pipe transport and KDNET (which gives us
    the same byte stream after decryption).
    """

    def __init__(self, transport):
        self._transport = transport
        self._packet_id = INITIAL_PACKET_ID
        self._is_kdnet = hasattr(transport, 'decrypt_packet')

    @property
    def packet_id(self):
        return self._packet_id

    def next_id(self):
        """Advance packet ID (toggle bit 0)."""
        self._packet_id ^= 1
        return self._packet_id

    def send_breakin(self):
        """Send break-in byte to interrupt the target."""
        if self._is_kdnet:
            # For KDNET, send a break-in as a data packet containing 'b'
            self._transport.send(bytes([BREAKIN_PACKET_BYTE]))
        else:
            self._transport.send(bytes([BREAKIN_PACKET_BYTE]))

    def send_reset(self):
        """Send a RESET control packet."""
        pkt = build_control_packet(PACKET_TYPE_KD_RESET, INITIAL_PACKET_ID)
        if self._is_kdnet:
            self._transport.send(pkt)
        else:
            self._transport.send(pkt)
        self._packet_id = INITIAL_PACKET_ID

    def send_ack(self, received_id: int):
        """Send an ACK for a received packet."""
        ack_id = received_id & ~0x800
        pkt = build_control_packet(PACKET_TYPE_KD_ACKNOWLEDGE, ack_id)
        if self._is_kdnet:
            self._transport.send(pkt)
        else:
            self._transport.send(pkt)

    def send_data_packet(self, pkt_type: int, payload: bytes):
        """Send a data packet (STATE_MANIPULATE, etc.)."""
        pkt = build_packet(pkt_type, payload, self._packet_id)
        if self._is_kdnet:
            self._transport.send(pkt)
        else:
            self._transport.send(pkt)

    def recv_packet(self, timeout: float = 10.0):
        """Receive and parse a KD packet.

        Returns dict: {leader, type, length, id, checksum, payload}
        or None on timeout.
        """
        data = self._transport.recv(65536, timeout=timeout)
        if not data:
            return None
        return self._parse_stream(data)

    def _parse_stream(self, data: bytes):
        """Parse a KD packet from a byte buffer.

        Scans for a valid leader, then extracts header + payload.
        """
        # Find leader
        offset = 0
        while offset <= len(data) - KD_PACKET_HEADER_SIZE:
            # Check for packet leader at current offset
            if len(data) - offset < 4:
                break
            leader = struct.unpack_from("<I", data, offset)[0]
            if leader in (PACKET_LEADER, CONTROL_PACKET_LEADER):
                break
            offset += 1

        if offset > len(data) - KD_PACKET_HEADER_SIZE:
            return None

        hdr = parse_packet_header(data[offset:])
        if hdr is None:
            return None

        payload_start = offset + KD_PACKET_HEADER_SIZE
        payload_len = hdr["length"]

        if hdr["leader"] == CONTROL_PACKET_LEADER:
            hdr["payload"] = b''
            return hdr

        # Data packet: extract payload
        if payload_start + payload_len > len(data):
            # Partial packet — payload truncated
            hdr["payload"] = data[payload_start:]
            return hdr

        hdr["payload"] = data[payload_start:payload_start + payload_len]
        return hdr

    def wait_state_change(self, timeout: float = 30.0):
        """Wait for a STATE_CHANGE64 packet from the target.

        Returns the parsed packet or None.
        """
        import time
        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = deadline - time.time()
            pkt = self.recv_packet(timeout=min(remaining, 5.0))
            if pkt is None:
                continue

            # ACK control packets silently
            if pkt["leader"] == CONTROL_PACKET_LEADER:
                continue

            if pkt["type"] in (PACKET_TYPE_KD_STATE_CHANGE64,
                               PACKET_TYPE_KD_STATE_MANIPULATE,
                               PACKET_TYPE_KD_DEBUG_IO):
                self.send_ack(pkt["id"])
                return pkt
        return None

    def send_manipulate(self, payload: bytes):
        """Send a STATE_MANIPULATE packet and wait for the response."""
        self.send_data_packet(PACKET_TYPE_KD_STATE_MANIPULATE, payload)
        self.next_id()

    def recv_manipulate_response(self, timeout: float = 10.0):
        """Receive a STATE_MANIPULATE response."""
        import time
        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = deadline - time.time()
            pkt = self.recv_packet(timeout=min(remaining, 3.0))
            if pkt is None:
                continue
            if pkt["leader"] == CONTROL_PACKET_LEADER:
                continue
            if pkt["type"] == PACKET_TYPE_KD_STATE_MANIPULATE:
                self.send_ack(pkt["id"])
                return pkt
            # Might get DEBUG_IO (DbgPrint) — ack and continue
            if pkt["type"] == PACKET_TYPE_KD_DEBUG_IO:
                self.send_ack(pkt["id"])
                continue
        return None
