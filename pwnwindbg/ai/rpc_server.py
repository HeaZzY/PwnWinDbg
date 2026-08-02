"""Parent-side RPC server.

Binds a loopback TCP socket on an ephemeral port, then serves a SINGLE
code-exec child over one connection: each request is dispatched to the
matching :class:`~pwnwindbg.ai.tools.DebugTools` method. Runs on a daemon
thread so the debugger REPL never blocks on it. Method exceptions are
returned as ``{"ok": false, "error": ...}`` — the serving thread must never
crash, even on a rude client disconnect.
"""

import socket
import threading

from .rpc import send_msg, recv_msg, encode, decode, new_token


class RpcServer:
    """Serves one code-exec child against a bound ``DebugTools`` instance."""

    def __init__(self, debug_tools):
        self.debug_tools = debug_tools
        self.token = new_token()
        self._listener = None
        self._client = None
        self._thread = None
        self._stop = threading.Event()
        self.host = "127.0.0.1"
        self.port = None

    # -- lifecycle -----------------------------------------------------

    def start(self):
        """Bind, start the accept/serve thread, and return (host, port, token)."""
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((self.host, 0))
        self._listener.listen(1)
        # Short timeout so the accept loop can notice stop().
        self._listener.settimeout(0.5)
        self.port = self._listener.getsockname()[1]

        self._thread = threading.Thread(
            target=self._serve, name="pwnwindbg-rpc", daemon=True
        )
        self._thread.start()
        return self.host, self.port, self.token

    def stop(self):
        """Signal shutdown and close all sockets. Safe to call repeatedly."""
        self._stop.set()
        for sock in (self._client, self._listener):
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
        self._client = None
        self._listener = None

    # -- serving -------------------------------------------------------

    def _serve(self):
        """Accept one client, then serve its requests until it disconnects."""
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self._client = conn
            try:
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass
            try:
                self._handle_client(conn)
            except Exception:
                # Never let a client blow up the daemon thread.
                pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
                self._client = None
            # One connection per code-exec child; accept the next child.

    def _handle_client(self, conn):
        """Read and answer requests on a single connection until EOF."""
        while not self._stop.is_set():
            try:
                req = recv_msg(conn)
            except (OSError, ValueError):
                return
            if req is None:
                return

            req_id = req.get("id")
            resp = self._dispatch(req)
            resp["id"] = req_id
            try:
                send_msg(conn, resp)
            except OSError:
                return

    def _dispatch(self, req):
        """Run one request against the tool table; build a response dict."""
        # Auth check first.
        if req.get("token") != self.token:
            return {"ok": False, "error": "bad token", "result": None}

        method = req.get("method")
        if not method or method.startswith("_"):
            return {"ok": False, "error": f"no such method: {method}", "result": None}

        fn = getattr(self.debug_tools, method, None)
        if fn is None or not callable(fn):
            return {"ok": False, "error": f"no such method: {method}", "result": None}

        try:
            args = decode(req.get("args") or [])
            kwargs = decode(req.get("kwargs") or {})
            result = fn(*args, **kwargs)
            return {"ok": True, "error": None, "result": encode(result)}
        except Exception as exc:
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "result": None}
