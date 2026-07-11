"""Child-process runtime namespace for AI-authored Python scripts.

Everything here runs INSIDE the isolated code-exec child. Debugger-touching
callables (``dbg``, ``read``, ``write``, ``send``, ``recv`` ...) are thin
wrappers over ``rpc_client.call(<method>, ...)`` — the actual work happens back
in the parent (see ``tools.DebugTools``). The wrapper names below are one half
of the frozen contract; the method strings passed to ``rpc_client.call`` MUST
match ``DebugTools`` method names exactly.

Local-only helpers (shell, file I/O, struct packing, cyclic) run right here in
the child with no RPC round-trip. If pwntools is importable, we merge its
namespace first and then overlay OUR names so our debuggee-bound
``send/recv/read/write/dbg`` win.
"""

import struct
import subprocess


def build_namespace(rpc_client):
    """Return the globals dict injected into AI-authored scripts.

    The same dict is also published as a synthetic ``pwnwindbg_agent`` module
    in ``sys.modules`` so ``from pwnwindbg_agent import *`` works inside a
    script.
    """
    ns = {}

    def _b(data):
        """Coerce str/bytes to bytes (utf-8 for str)."""
        if isinstance(data, str):
            return data.encode("utf-8")
        if isinstance(data, bytearray):
            return bytes(data)
        return data

    # -- RPC-backed (talk to the live debugger via the parent) ---------

    def dbg(cmd):
        """Run a debugger command in the parent; return captured text."""
        return rpc_client.call("dbg", cmd)

    def read(addr, n):
        """Read ``n`` bytes at ``addr`` from the debuggee."""
        return rpc_client.call("read_mem", int(addr), int(n))

    def write(addr, data):
        """Write bytes at ``addr`` in the debuggee; return bytes written."""
        return rpc_client.call("write_mem", int(addr), _b(data))

    def regs():
        """Return the debuggee register dict."""
        return rpc_client.call("regs")

    def getreg(name):
        """Return one register value by name (case-insensitive)."""
        return rpc_client.call("getreg", name)

    def setreg(name, value):
        """Set a register in the debuggee."""
        return rpc_client.call("setreg", name, int(value))

    def send(data):
        """Send bytes (or str) to the debuggee's stdin."""
        return rpc_client.call("send", _b(data))

    def sendline(data):
        """Send bytes (or str) + newline to the debuggee's stdin."""
        return rpc_client.call("sendline", _b(data))

    def recv(size=4096, timeout=1.0):
        """Receive up to ``size`` bytes from the debuggee's stdout."""
        return rpc_client.call("recv", int(size), float(timeout))

    def recvuntil(delim, timeout=5.0):
        """Receive from the debuggee until ``delim`` (str/bytes) appears."""
        return rpc_client.call("recvuntil", _b(delim), float(timeout))

    def recvline(timeout=5.0):
        """Receive one line from the debuggee's stdout."""
        return rpc_client.call("recvline", float(timeout))

    def shutdown_stdin():
        """Close the debuggee's stdin (send EOF) so a blocked read returns."""
        return rpc_client.call("shutdown_stdin")

    def eval_addr(expr):
        """Evaluate an address expression in the parent to an int."""
        return rpc_client.call("eval_addr", str(expr))

    def state():
        """Return a compact debugger-state dict."""
        return rpc_client.call("state")

    def log(msg):
        """Print an informational message on the parent console."""
        return rpc_client.call("log", str(msg))

    # -- Local-only helpers (run in the child, no RPC) -----------------

    def _trace(kind, summary, detail=None):
        """Announce a local-only action over RPC; never break the caller."""
        try:
            rpc_client.call("trace", kind, summary, detail)
        except Exception:
            pass

    def sh(cmd, timeout=60):
        """Run a shell command; return combined stdout+stderr as text."""
        _trace("sh", str(cmd)[:200])
        try:
            proc = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout or b""
            err = exc.stderr or b""
            tail = (out + err).decode("utf-8", "replace")
            result = tail + f"\n[sh timeout after {timeout}s]"
            _trace("sh", f"output {len(result)} chars", result[:200])
            return result
        combined = (proc.stdout or b"") + (proc.stderr or b"")
        result = combined.decode("utf-8", "replace")
        _trace("sh", f"output {len(result)} chars", result[:200])
        return result

    def read_file(path, binary=False):
        """Read a file. Returns bytes if ``binary`` else utf-8 text."""
        mode = "rb" if binary else "r"
        if binary:
            with open(path, mode) as fh:
                data = fh.read()
        else:
            with open(path, mode, encoding="utf-8", errors="replace") as fh:
                data = fh.read()
        _trace(
            "file",
            f"read_file {path} ({len(data)} {'B' if binary else 'chars'})",
        )
        return data

    def write_file(path, data):
        """Write ``data`` (str or bytes) to ``path``. Returns bytes written."""
        if isinstance(data, str):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(data)
            nbytes = len(data.encode("utf-8"))
            _trace("file", f"write_file {path} ({nbytes} B)")
            return nbytes
        with open(path, "wb") as fh:
            fh.write(bytes(data))
        nbytes = len(data)
        _trace("file", f"write_file {path} ({nbytes} B)")
        return nbytes

    def patch_file(path, find, replace):
        """Replace bytes ``find`` with ``replace`` in ``path``.

        Operates on raw bytes; ``find``/``replace`` may be str (utf-8) or
        bytes. Returns the number of occurrences replaced.
        """
        find_b = _b(find)
        replace_b = _b(replace)
        with open(path, "rb") as fh:
            data = fh.read()
        count = data.count(find_b)
        if count:
            data = data.replace(find_b, replace_b)
            with open(path, "wb") as fh:
                fh.write(data)
        _trace("file", f"patch_file {path} ({count} hits)")
        return count

    # -- struct packing / unpacking (little-endian) --------------------

    def p8(x):
        return struct.pack("<B", x & 0xFF)

    def p16(x):
        return struct.pack("<H", x & 0xFFFF)

    def p32(x):
        return struct.pack("<I", x & 0xFFFFFFFF)

    def p64(x):
        return struct.pack("<Q", x & 0xFFFFFFFFFFFFFFFF)

    def u8(data):
        return struct.unpack("<B", _b(data)[:1])[0]

    def u16(data):
        return struct.unpack("<H", _b(data)[:2])[0]

    def u32(data):
        return struct.unpack("<I", _b(data)[:4])[0]

    def u64(data):
        return struct.unpack("<Q", _b(data)[:8])[0]

    # -- cyclic (pure functions, safe to import in the child) ----------

    try:
        from ..commands.cyclic_cmds import cyclic as _cyclic, cyclic_find as _cyclic_find
    except Exception:
        _cyclic = None
        _cyclic_find = None

    def cyclic(length, n=4):
        """Generate a De Bruijn cyclic pattern (str)."""
        if _cyclic is None:
            raise RuntimeError("cyclic unavailable")
        return _cyclic(length, n)

    def cyclic_find(value, n=4):
        """Find the offset of a value in the cyclic pattern."""
        if _cyclic_find is None:
            raise RuntimeError("cyclic_find unavailable")
        return _cyclic_find(value, n)

    # -- pwntools overlay ----------------------------------------------
    # Merge pwntools FIRST (if present), then overlay OUR names so the
    # debuggee-bound send/recv/read/write/dbg take precedence.
    try:
        import pwn as _pwn
        for _name in dir(_pwn):
            if not _name.startswith("_"):
                ns[_name] = getattr(_pwn, _name)
    except Exception:
        pass

    ns.update({
        # RPC-backed
        "dbg": dbg,
        "read": read,
        "write": write,
        "read_mem": read,
        "write_mem": write,
        "regs": regs,
        "getreg": getreg,
        "setreg": setreg,
        "send": send,
        "sendline": sendline,
        "recv": recv,
        "recvuntil": recvuntil,
        "recvline": recvline,
        "shutdown_stdin": shutdown_stdin,
        "shutdown": shutdown_stdin,
        "eof": shutdown_stdin,
        "eval_addr": eval_addr,
        "state": state,
        "log": log,
        # Local
        "sh": sh,
        "read_file": read_file,
        "write_file": write_file,
        "patch_file": patch_file,
        "p8": p8, "p16": p16, "p32": p32, "p64": p64,
        "u8": u8, "u16": u16, "u32": u32, "u64": u64,
        "cyclic": cyclic,
        "cyclic_find": cyclic_find,
        # Convenience
        "struct": struct,
        "rpc": rpc_client,
    })

    return ns
