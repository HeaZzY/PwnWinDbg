"""Debuggee I/O tube — pwntools-style stdin/stdout pipe over a debugged process.

Self-contained ctypes: reuses the shared STARTUPINFOW / kernel32 / basic type
aliases from ``pwnwindbg.utils.constants`` but defines its own prototypes for the
pipe/file primitives (CreatePipe/ReadFile/WriteFile/SetHandleInformation/
CloseHandle/PeekNamedPipe) so this module owns its handle plumbing.

``make_pipe_startupinfo()`` builds a STARTUPINFOW wired to anonymous pipes and a
:class:`ProcTube` that the debugger stores as ``debugger.tube``; a background
reader thread drains the child's stdout into a buffer so ``recv``/``recvuntil``/
``recvline`` can serve data with timeouts without blocking the debug loop.

Importable on any OS: the ctypes/Windows bindings are built lazily inside
``make_pipe_startupinfo`` (and guarded), so ``import`` never touches a live
process and does not fail off-Windows at module load.
"""

import ctypes
import threading
import time

from ..utils.constants import (
    STARTUPINFOW, kernel32, HANDLE, DWORD, BOOL, STARTF_USESTDHANDLES,
)

# ---------------------------------------------------------------------------
# ctypes prototypes for the pipe / file primitives we own
# ---------------------------------------------------------------------------
#
# These are declared at import time. Assigning argtypes/restype on the shared
# kernel32 object is idempotent and does not call anything, so it is safe on
# any OS where ``ctypes.windll.kernel32`` resolved (i.e. Windows). On non-Windows
# the import of ``constants`` would already have failed to build ``kernel32``;
# to stay importable everywhere we guard the prototype setup.

LPVOID = ctypes.c_void_p
LPDWORD = ctypes.POINTER(DWORD)

# Handle-flag for SetHandleInformation
HANDLE_FLAG_INHERIT = 0x00000001

_PROTOTYPES_READY = False


def _ensure_prototypes():
    """Attach argtypes/restype to the kernel32 pipe functions once.

    Called lazily so merely importing this module never requires a live
    Windows kernel32. Returns True on success, False if the platform does not
    provide the needed symbols.
    """
    global _PROTOTYPES_READY
    if _PROTOTYPES_READY:
        return True
    if kernel32 is None:
        return False
    try:
        class _SECURITY_ATTRIBUTES(ctypes.Structure):
            _fields_ = [
                ("nLength", DWORD),
                ("lpSecurityDescriptor", LPVOID),
                ("bInheritHandle", BOOL),
            ]

        # Stash the struct type on the function object namespace via module global
        global SECURITY_ATTRIBUTES
        SECURITY_ATTRIBUTES = _SECURITY_ATTRIBUTES

        kernel32.CreatePipe.argtypes = [
            ctypes.POINTER(HANDLE),           # hReadPipe (out)
            ctypes.POINTER(HANDLE),           # hWritePipe (out)
            ctypes.POINTER(_SECURITY_ATTRIBUTES),
            DWORD,                            # nSize
        ]
        kernel32.CreatePipe.restype = BOOL

        kernel32.ReadFile.argtypes = [
            HANDLE, LPVOID, DWORD, LPDWORD, LPVOID,
        ]
        kernel32.ReadFile.restype = BOOL

        kernel32.WriteFile.argtypes = [
            HANDLE, LPVOID, DWORD, LPDWORD, LPVOID,
        ]
        kernel32.WriteFile.restype = BOOL

        kernel32.SetHandleInformation.argtypes = [HANDLE, DWORD, DWORD]
        kernel32.SetHandleInformation.restype = BOOL

        # CloseHandle is already prototyped in constants, but re-asserting is
        # harmless and keeps this module self-describing.
        kernel32.CloseHandle.argtypes = [HANDLE]
        kernel32.CloseHandle.restype = BOOL

        kernel32.PeekNamedPipe.argtypes = [
            HANDLE, LPVOID, DWORD, LPDWORD, LPDWORD, LPDWORD,
        ]
        kernel32.PeekNamedPipe.restype = BOOL
    except Exception:
        return False

    _PROTOTYPES_READY = True
    return True


# Populated by _ensure_prototypes(); referenced by make_pipe_startupinfo.
SECURITY_ATTRIBUTES = None


# ---------------------------------------------------------------------------
# ProcTube — parent-side stdin/stdout pipe to the debuggee
# ---------------------------------------------------------------------------

class ProcTube:
    """A pwntools-style tube over a debugged process's stdin/stdout pipes.

    Holds the parent-side write handle (child stdin) and read handle (child
    stdout). A daemon reader thread block-reads the stdout pipe and appends
    into a lock-guarded ``bytearray`` so ``recv``/``recvuntil``/``recvline``
    can honour timeouts without blocking the debugger's event loop.
    """

    def __init__(self, stdin_write_handle, stdout_read_handle):
        self._stdin_write = stdin_write_handle
        self._stdout_read = stdout_read_handle

        self._buf = bytearray()
        self._lock = threading.Lock()
        self._closed = False
        # Set once the reader observes EOF / a broken pipe on stdout.
        self._eof = False

        self._reader = threading.Thread(
            target=self._reader_loop, name="ProcTubeReader", daemon=True,
        )
        self._reader.start()

    # -- background reader ------------------------------------------------

    def _reader_loop(self):
        """Continuously block-read stdout and buffer whatever arrives."""
        chunk = ctypes.create_string_buffer(65536)
        n_read = DWORD(0)
        while True:
            if self._closed:
                break
            ok = kernel32.ReadFile(
                self._stdout_read, chunk, 65536, ctypes.byref(n_read), None,
            )
            if not ok or n_read.value == 0:
                # EOF (child closed its stdout / exited) or a read error such
                # as ERROR_BROKEN_PIPE — nothing more will ever arrive.
                self._eof = True
                break
            with self._lock:
                self._buf += chunk.raw[: n_read.value]

    # -- writing ----------------------------------------------------------

    def write(self, data):
        """Write raw bytes to the debuggee's stdin. Returns bytes written."""
        if self._closed or self._stdin_write is None:
            raise RuntimeError("tube is closed")
        if isinstance(data, str):
            data = data.encode("utf-8", "surrogateescape")
        if not data:
            return 0
        buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
        written = DWORD(0)
        ok = kernel32.WriteFile(
            self._stdin_write, buf, len(data), ctypes.byref(written), None,
        )
        if not ok:
            err = ctypes.get_last_error() if hasattr(ctypes, "get_last_error") else 0
            raise RuntimeError(f"WriteFile to debuggee stdin failed (err={err})")
        return written.value

    # -- reading ----------------------------------------------------------

    def read_available(self, max=65536):
        """Return up to ``max`` buffered bytes immediately (never blocks)."""
        with self._lock:
            if not self._buf:
                return b""
            n = len(self._buf) if max is None else min(max, len(self._buf))
            out = bytes(self._buf[:n])
            del self._buf[:n]
            return out

    def _buffered_len(self):
        with self._lock:
            return len(self._buf)

    def recv(self, size=4096, timeout=1.0):
        """Receive up to ``size`` bytes, waiting up to ``timeout`` seconds.

        Returns as soon as any data is available (like a socket recv). Returns
        b"" on timeout with nothing buffered, or when the pipe has hit EOF.
        """
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            with self._lock:
                if self._buf:
                    n = min(size, len(self._buf))
                    out = bytes(self._buf[:n])
                    del self._buf[:n]
                    return out
            if self._eof:
                return b""
            if deadline is not None and time.monotonic() >= deadline:
                return b""
            time.sleep(0.005)

    def recvn(self, size, timeout=5.0):
        """Receive exactly ``size`` bytes or raise TimeoutError.

        Provided for convenience; not part of the core contract methods but
        handy for framed protocols.
        """
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            with self._lock:
                if len(self._buf) >= size:
                    out = bytes(self._buf[:size])
                    del self._buf[:size]
                    return out
            if self._eof:
                raise EOFError("tube closed before %d bytes arrived" % size)
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError("recvn(%d) timed out" % size)
            time.sleep(0.005)

    def recvuntil(self, delim, timeout=5.0):
        """Receive until ``delim`` appears. Returns everything up to & incl. it.

        On timeout (or EOF) returns whatever was buffered so far, so no data is
        lost even if the delimiter never showed up.
        """
        if isinstance(delim, str):
            delim = delim.encode("utf-8", "surrogateescape")
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            with self._lock:
                idx = self._buf.find(delim)
                if idx != -1:
                    end = idx + len(delim)
                    out = bytes(self._buf[:end])
                    del self._buf[:end]
                    return out
            if self._eof:
                # No more data will arrive — flush what we have.
                return self.read_available(None)
            if deadline is not None and time.monotonic() >= deadline:
                return self.read_available(None)
            time.sleep(0.005)

    def recvline(self, timeout=5.0):
        """Receive one line including the trailing newline (b"\\n")."""
        return self.recvuntil(b"\n", timeout=timeout)

    # -- teardown ---------------------------------------------------------

    def close(self):
        """Close both parent-side handles and stop the reader thread."""
        if self._closed:
            return
        self._closed = True
        for attr in ("_stdin_write", "_stdout_read"):
            h = getattr(self, attr, None)
            if h:
                try:
                    kernel32.CloseHandle(h)
                except Exception:
                    pass
            setattr(self, attr, None)
        # The reader thread will fall out of ReadFile (broken pipe) or notice
        # the _closed flag; it is a daemon so we don't hard-join for long.
        reader = getattr(self, "_reader", None)
        if reader is not None and reader.is_alive():
            reader.join(timeout=0.2)


# ---------------------------------------------------------------------------
# STARTUPINFOW builder for pipe-backed spawn
# ---------------------------------------------------------------------------

def make_pipe_startupinfo():
    """Build a STARTUPINFOW wired to fresh anonymous pipes for the debuggee.

    Returns ``(startupinfo, proc_tube, child_handles_to_close)``:
      * ``startupinfo``           — STARTUPINFOW with STARTF_USESTDHANDLES set
                                     and hStdInput/hStdOutput/hStdError pointing
                                     at the child-side pipe ends.
      * ``proc_tube``             — a :class:`ProcTube` owning the parent-side
                                     write (stdin) and read (stdout) handles.
      * ``child_handles_to_close``— list of the child-side handles the CALLER
                                     must ``CloseHandle`` *after* CreateProcessW
                                     (the child has inherited its own copies).

    The parent ends have HANDLE_FLAG_INHERIT cleared so only the child inherits
    the pipe ends it needs. stdout and stderr are merged onto one pipe so the
    tube captures both interleaved (matching a typical console).

    Raises RuntimeError if the platform can't provide the pipe primitives.
    """
    if not _ensure_prototypes():
        raise RuntimeError("pipe I/O is only available on Windows")

    # SECURITY_ATTRIBUTES with bInheritHandle=True so the pipe ends are
    # inheritable at creation; we then selectively un-inherit the parent ends.
    sa = SECURITY_ATTRIBUTES()
    sa.nLength = ctypes.sizeof(sa)
    sa.lpSecurityDescriptor = None
    sa.bInheritHandle = True

    # --- child stdin pipe: parent writes -> child reads ---
    child_stdin_read = HANDLE()
    parent_stdin_write = HANDLE()
    if not kernel32.CreatePipe(
        ctypes.byref(child_stdin_read), ctypes.byref(parent_stdin_write),
        ctypes.byref(sa), 0,
    ):
        err = ctypes.get_last_error() if hasattr(ctypes, "get_last_error") else 0
        raise RuntimeError(f"CreatePipe (stdin) failed (err={err})")

    # --- child stdout pipe: child writes -> parent reads ---
    parent_stdout_read = HANDLE()
    child_stdout_write = HANDLE()
    if not kernel32.CreatePipe(
        ctypes.byref(parent_stdout_read), ctypes.byref(child_stdout_write),
        ctypes.byref(sa), 0,
    ):
        err = ctypes.get_last_error() if hasattr(ctypes, "get_last_error") else 0
        # Clean up the stdin pipe we already created before bailing.
        for h in (child_stdin_read, parent_stdin_write):
            try:
                kernel32.CloseHandle(h)
            except Exception:
                pass
        raise RuntimeError(f"CreatePipe (stdout) failed (err={err})")

    # Ensure the parent-side ends are NOT inherited by the child. Only the
    # child ends (stdin-read, stdout-write) should cross into the debuggee.
    kernel32.SetHandleInformation(parent_stdin_write, HANDLE_FLAG_INHERIT, 0)
    kernel32.SetHandleInformation(parent_stdout_read, HANDLE_FLAG_INHERIT, 0)

    # Build STARTUPINFOW pointing the child at its pipe ends.
    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(si)
    si.dwFlags |= STARTF_USESTDHANDLES
    si.hStdInput = child_stdin_read
    si.hStdOutput = child_stdout_write
    si.hStdError = child_stdout_write

    tube = ProcTube(parent_stdin_write, parent_stdout_read)

    # The caller closes these after CreateProcessW so we don't keep the write
    # end of stdout open in the parent (otherwise the reader never sees EOF).
    child_handles_to_close = [child_stdin_read, child_stdout_write]

    return si, tube, child_handles_to_close
