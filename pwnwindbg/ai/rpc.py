"""Loopback-socket RPC shared by the parent debugger and the code-exec child.

Transport is a single TCP connection on 127.0.0.1 (parent binds an ephemeral
port and hands host/port/token to the child via env vars). Messages are
newline-delimited UTF-8 JSON. Because JSON cannot carry raw ``bytes``, we
recursively encode Python ``bytes`` as ``{"__b64__": "<base64>"}`` in every
request/response and decode them back on the far side.

The child stub (:class:`RpcClient`) calls parent methods by name; the parent
server (``rpc_server.RpcServer``) dispatches those names to ``DebugTools``.
Both ends live behind this one module so the wire format stays in lockstep.
"""

import base64
import json
import os
import secrets
import socket


# ---------------------------------------------------------------------------
# bytes <-> JSON transport encoding
# ---------------------------------------------------------------------------

def encode(obj):
    """Recursively convert Python ``bytes`` to a JSON-safe base64 marker.

    Walks dicts, lists and tuples; every ``bytes``/``bytearray`` value becomes
    ``{"__b64__": "<base64-ascii>"}``. Everything else is returned as-is.
    """
    if isinstance(obj, (bytes, bytearray)):
        return {"__b64__": base64.b64encode(bytes(obj)).decode("ascii")}
    if isinstance(obj, dict):
        return {k: encode(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [encode(v) for v in obj]
    return obj


def decode(obj):
    """Inverse of :func:`encode`: rebuild ``bytes`` from ``{"__b64__": ...}``."""
    if isinstance(obj, dict):
        if len(obj) == 1 and "__b64__" in obj:
            try:
                return base64.b64decode(obj["__b64__"])
            except Exception:
                return b""
        return {k: decode(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [decode(v) for v in obj]
    return obj


def new_token():
    """Return a fresh random auth token (hex string)."""
    return secrets.token_hex(16)


# ---------------------------------------------------------------------------
# Framing: newline-delimited JSON
# ---------------------------------------------------------------------------

def send_msg(sock, obj):
    """Serialize ``obj`` to a single newline-terminated JSON line and send it.

    ``obj`` is assumed to already be transport-encoded (bytes -> b64) by the
    caller. Raises ``OSError`` on a broken socket.
    """
    line = json.dumps(obj, separators=(",", ":")).encode("utf-8") + b"\n"
    sock.sendall(line)


class _LineReader:
    """Buffered newline reader over a blocking socket."""

    def __init__(self, sock):
        self._sock = sock
        self._buf = bytearray()

    def readline(self):
        """Read one line (without trailing newline) or return ``None`` on EOF."""
        while True:
            nl = self._buf.find(b"\n")
            if nl >= 0:
                line = bytes(self._buf[:nl])
                del self._buf[: nl + 1]
                return line
            chunk = self._sock.recv(65536)
            if not chunk:
                if self._buf:
                    line = bytes(self._buf)
                    self._buf.clear()
                    return line
                return None
            self._buf.extend(chunk)


# Weak association of a socket -> its buffered reader so recv_msg is a plain
# function (matches the contract's `recv_msg(sock)` signature) while still
# retaining any leftover bytes between calls on the same connection.
_readers = {}


def _reader_for(sock):
    key = id(sock)
    reader = _readers.get(key)
    if reader is None or reader._sock is not sock:
        reader = _LineReader(sock)
        _readers[key] = reader
    return reader


def recv_msg(sock):
    """Read one JSON message object from ``sock`` (still transport-encoded).

    Returns the parsed object, or ``None`` on EOF. Buffers any surplus bytes so
    successive calls on the same socket stay framed correctly.
    """
    reader = _reader_for(sock)
    line = reader.readline()
    if line is None:
        return None
    line = line.strip()
    if not line:
        # Skip blank keep-alive lines; recurse for the next real message.
        return recv_msg(sock)
    return json.loads(line.decode("utf-8"))


def _drop_reader(sock):
    """Forget the buffered reader for a closed socket."""
    _readers.pop(id(sock), None)


# ---------------------------------------------------------------------------
# Child-side client
# ---------------------------------------------------------------------------

class RpcClient:
    """Synchronous RPC client used by the code-exec child.

    Each :meth:`call` sends one request and blocks for the matching response.
    Requests are serialized (the child runs single-threaded scripts), so ids
    are a simple incrementing counter.
    """

    def __init__(self, host, port, token):
        self.host = host
        self.port = int(port)
        self.token = token
        self._id = 0
        self._sock = socket.create_connection((self.host, self.port))
        self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    @classmethod
    def from_env(cls):
        """Build a client from ``PWNWINDBG_RPC_HOST/PORT/TOKEN`` env vars."""
        return cls(
            os.environ["PWNWINDBG_RPC_HOST"],
            os.environ["PWNWINDBG_RPC_PORT"],
            os.environ["PWNWINDBG_RPC_TOKEN"],
        )

    def call(self, method, *args, **kwargs):
        """Invoke a parent method by name; return its result.

        ``bytes`` arguments/results cross the wire transparently. Raises
        ``RuntimeError`` if the parent reports ``{"ok": false}`` or the
        connection breaks.
        """
        self._id += 1
        req = {
            "id": self._id,
            "method": method,
            "args": encode(list(args)),
            "kwargs": encode(dict(kwargs)),
            "token": self.token,
        }
        try:
            send_msg(self._sock, req)
            resp = recv_msg(self._sock)
        except OSError as exc:
            raise RuntimeError(f"RPC transport error calling {method!r}: {exc}")
        if resp is None:
            raise RuntimeError(f"RPC connection closed during {method!r}")
        if not resp.get("ok"):
            raise RuntimeError(resp.get("error") or f"RPC call {method!r} failed")
        return decode(resp.get("result"))

    def close(self):
        try:
            _drop_reader(self._sock)
            self._sock.close()
        except Exception:
            pass
