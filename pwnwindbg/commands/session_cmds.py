"""Session save / load — persist BPs, dprintfs, conditionals and watchpoints
across debugger restarts.

A session is a JSON file describing every breakpoint and hardware watchpoint
the user has set up, anchored to module-relative offsets so the right
addresses get re-applied even when the next run lands at a different ASLR
slide. The format is intentionally trivial:

    {
      "version": 1,
      "target":  "C:\\Users\\me\\foo.exe",
      "breakpoints": [
        {"anchor": "ntdll.dll!NtCreateFile", "offset": 0,
         "condition": null, "action": null, "enabled": true},
        {"anchor": "foo.exe+0x1234", "offset": 0,
         "condition": "rcx == 0",
         "action": "rax={rax:hex}",
         "enabled": true}
      ],
      "watchpoints": [
        {"anchor": "foo.exe+0x4000", "offset": 0,
         "access": "w", "length": 8}
      ]
    }

Anchors:
  - "module!symbol"   — symbol resolved at load time, then `+offset` added
  - "module+0xRVA"    — module base + RVA (the common case for app code)
  - "0xABS"           — raw absolute address (lossy across ASLR — only used
                        when no module covers the address at save time)

`session save [path]` and `session load [path]` are the user-facing commands.
Default path is `.pwnwindbg-session.json` in the current working directory.
"""

import json
import os

from ..display.formatters import banner, console, error, info, success, warn
from ..core.watchpoints import WATCH_EXEC, WATCH_READ_WRITE, WATCH_WRITE
from ..utils.addr_expr import eval_expr


SESSION_VERSION = 1
DEFAULT_SESSION_PATH = ".pwnwindbg-session.json"


# ---------------------------------------------------------------------------
# Anchor encoding / decoding
# ---------------------------------------------------------------------------

def _encode_anchor(debugger, addr):
    """Turn an absolute runtime address into a relocatable anchor string.

    Tries (in order): exact symbol match, module+RVA, raw absolute. The
    chosen format is the one that survives the most aggressive ASLR.
    """
    syms = debugger.symbols

    # Prefer an exact symbol — survives even module-base randomization plus
    # binary rebuilds, as long as the symbol still exists.
    if syms:
        try:
            label = syms.resolve_address(addr)
        except Exception:
            label = None
        if label and "+" not in label and "!" in label:
            # `module!sym` exact hit (no `+offset` suffix)
            return label, 0
        if label and "!" in label and "+" in label:
            # `module!sym+0x123` — split off the offset so it can be added
            # back when re-resolving against a freshly-loaded symbol.
            base_label, _, off_str = label.rpartition("+")
            try:
                off = int(off_str, 0)
            except ValueError:
                off = 0
            return base_label, off

    # Fallback: module+RVA
    if syms:
        mod = syms.get_module_at(addr)
        if mod:
            return f"{mod.name}+{mod.offset_of(addr):#x}", 0

    # Last resort: raw absolute
    return f"{addr:#x}", 0


def _decode_anchor(debugger, anchor, offset):
    """Resolve an anchor string back to an absolute address against the
    *current* process state. Returns None if the anchor can't be resolved.
    """
    base = eval_expr(debugger, anchor)
    if base is None:
        return None
    return base + offset


# ---------------------------------------------------------------------------
# Encode / decode the live state
# ---------------------------------------------------------------------------

_WP_ACCESS_TO_STR = {
    WATCH_WRITE:      "w",
    WATCH_READ_WRITE: "rw",
    WATCH_EXEC:       "x",
}
_STR_TO_WP_ACCESS = {v: k for k, v in _WP_ACCESS_TO_STR.items()}


def _snapshot(debugger):
    """Build a JSON-ready dict from the debugger's current BP/WP state."""
    bps_out = []
    for bp in debugger.bp_manager.list_all():
        if bp.temporary:
            continue  # `finish` / `until` scratch BPs are not part of session
        anchor, off = _encode_anchor(debugger, bp.address)
        bps_out.append({
            "anchor":    anchor,
            "offset":    off,
            "condition": bp.condition,
            "action":    bp.action,
            "enabled":   bp.enabled,
        })

    wps_out = []
    for wp in debugger.wp_manager.list_all():
        anchor, off = _encode_anchor(debugger, wp.address)
        wps_out.append({
            "anchor": anchor,
            "offset": off,
            "access": _WP_ACCESS_TO_STR[wp.access],
            "length": wp.length,
        })

    # The main exe is the first non-DLL module DbgHelp/Toolhelp gives us.
    # We just record it as a hint — load() doesn't enforce a match because
    # the user might rename or move the file between sessions.
    target = ""
    try:
        for m in debugger.symbols.modules:
            if m.path and m.path.lower().endswith(".exe"):
                target = m.path
                break
    except Exception:
        pass

    return {
        "version":     SESSION_VERSION,
        "target":      target,
        "breakpoints": bps_out,
        "watchpoints": wps_out,
    }


def _apply(debugger, data):
    """Re-create BPs and WPs from a session dict. Returns (bp_ok, bp_fail,
    wp_ok, wp_fail)."""
    bp_ok = bp_fail = wp_ok = wp_fail = 0

    for entry in data.get("breakpoints", []):
        anchor = entry.get("anchor", "")
        offset = entry.get("offset", 0) or 0
        addr = _decode_anchor(debugger, anchor, offset)
        if addr is None:
            warn(f"  ! cannot resolve BP anchor: {anchor}+{offset:#x}")
            bp_fail += 1
            continue
        try:
            bp = debugger.bp_manager.add(debugger.process_handle, addr)
        except Exception as e:
            warn(f"  ! cannot set BP @ {addr:#x}: {e}")
            bp_fail += 1
            continue
        bp.condition = entry.get("condition")
        bp.action = entry.get("action")
        if entry.get("enabled", True) is False:
            debugger.bp_manager._disable(debugger.process_handle, bp)
        debugger.bp_manager.save_address(addr)
        bp_ok += 1

    for entry in data.get("watchpoints", []):
        anchor = entry.get("anchor", "")
        offset = entry.get("offset", 0) or 0
        addr = _decode_anchor(debugger, anchor, offset)
        if addr is None:
            warn(f"  ! cannot resolve WP anchor: {anchor}+{offset:#x}")
            wp_fail += 1
            continue
        access = _STR_TO_WP_ACCESS.get(entry.get("access", "w"))
        length = int(entry.get("length", 8))
        if access is None:
            warn(f"  ! invalid WP access: {entry.get('access')}")
            wp_fail += 1
            continue
        try:
            debugger.add_watchpoint(addr, access, length)
        except Exception as e:
            warn(f"  ! cannot arm WP @ {addr:#x}: {e}")
            wp_fail += 1
            continue
        wp_ok += 1

    return bp_ok, bp_fail, wp_ok, wp_fail


# ---------------------------------------------------------------------------
# Command entrypoint
# ---------------------------------------------------------------------------

def cmd_session(debugger, args):
    """Save or load a debugger session.

    Usage:
        session save [path]   — write current BPs/WPs to <path>
        session load [path]   — restore from <path>
        session show [path]   — print the contents of <path> (no apply)

    Default <path> is `.pwnwindbg-session.json` in the current working
    directory.
    """
    parts = args.strip().split(None, 1)
    if not parts:
        error("Usage: session save [path] | session load [path] | session show [path]")
        return None

    sub = parts[0].lower()
    path = parts[1].strip() if len(parts) > 1 else DEFAULT_SESSION_PATH

    if sub == "save":
        return _do_save(debugger, path)
    if sub == "load":
        return _do_load(debugger, path)
    if sub == "show":
        return _do_show(path)
    error(f"Unknown subcommand: {sub}")
    return None


def _do_save(debugger, path):
    if not debugger.process_handle:
        error("No process attached — nothing to save")
        return None
    snap = _snapshot(debugger)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(snap, f, indent=2)
    except OSError as e:
        error(f"Cannot write {path}: {e}")
        return None
    success(
        f"Session saved to {path}  "
        f"({len(snap['breakpoints'])} BPs, {len(snap['watchpoints'])} WPs)"
    )
    return None


def _do_load(debugger, path):
    if not debugger.process_handle:
        error("No process attached — start the target before loading a session")
        return None
    if not os.path.exists(path):
        error(f"No session file at {path}")
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        error(f"Cannot read {path}: {e}")
        return None
    if not isinstance(data, dict) or data.get("version") != SESSION_VERSION:
        warn(f"Session version mismatch (got {data.get('version')}, "
             f"expected {SESSION_VERSION}) — trying anyway")
    bp_ok, bp_fail, wp_ok, wp_fail = _apply(debugger, data)
    success(
        f"Session loaded: BPs {bp_ok} ok / {bp_fail} failed, "
        f"WPs {wp_ok} ok / {wp_fail} failed"
    )
    return None


def _do_show(path):
    if not os.path.exists(path):
        error(f"No session file at {path}")
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        error(f"Cannot read {path}: {e}")
        return None

    bps = data.get("breakpoints", [])
    wps = data.get("watchpoints", [])
    banner(f"session — {path}")
    info(f"target: {data.get('target', '?')}   version: {data.get('version', '?')}")
    console.print(f"\n[bold]Breakpoints ({len(bps)}):[/]")
    for b in bps:
        suffix = ""
        if b.get("condition"):
            suffix += f"  if {b['condition']}"
        if b.get("action"):
            suffix += f'  do "{b["action"]}"'
        state = "" if b.get("enabled", True) else "  [bright_black](disabled)[/]"
        console.print(f"  {b['anchor']}+{b.get('offset', 0):#x}{suffix}{state}")
    console.print(f"\n[bold]Watchpoints ({len(wps)}):[/]")
    for w in wps:
        console.print(
            f"  {w['anchor']}+{w.get('offset', 0):#x}  "
            f"access={w.get('access')}  len={w.get('length')}"
        )
    return None
