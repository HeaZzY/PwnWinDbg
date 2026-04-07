"""Drive pwnWinDbg's REPL programmatically to test the new KD commands."""

import sys
import io

# Force UTF-8 stdout to avoid Windows console encoding issues with Rich
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# Disable Rich pretty terminal so we get plain text output
import os
os.environ["TERM"] = "dumb"
os.environ["NO_COLOR"] = "1"

from rich.console import Console
from pwnwindbg.display import common as dcommon
from pwnwindbg.display import formatters as dformatters

# Replace the global console with one that writes plain text to stdout
plain_console = Console(force_terminal=False, color_system=None, width=140, file=sys.stdout)
dcommon.console = plain_console
dformatters.console = plain_console

# Patch other modules that imported console at module load time
import pwnwindbg.commands.kd_cmds as kd_cmds
kd_cmds.console = plain_console
import pwnwindbg.commands.kd_ps_cmds as kd_ps
kd_ps.console = plain_console
import pwnwindbg.commands.kd_nav_cmds as kd_nav
kd_nav.console = plain_console
import pwnwindbg.commands.kd_search_cmds as kd_search
kd_search.console = plain_console
import pwnwindbg.commands.kd_pte_cmds as kd_pte
kd_pte.console = plain_console
import pwnwindbg.commands.kd_dt_cmds as kd_dt
kd_dt.console = plain_console

from pwnwindbg.commands.dispatcher import dispatch
from pwnwindbg.core.debugger import Debugger

debugger = Debugger()


def run(cmd):
    print(f"\n========== {cmd!r} ==========")
    try:
        result = dispatch(debugger, cmd)
        if result:
            print(f"[result: {result}]")
    except Exception as e:
        import traceback
        traceback.print_exc()


# Sequence of test commands — exercises auto-routing (no `kd` prefix)
commands = [
    "help",                              # userland help
    "kdconnect gdb:localhost:10000",
    "help",                              # kernel help (post-connect)
    "lm",                                # auto-routes to kdlm
    "ps",                                # auto-routes to kdps
    "threads 4",                         # auto-routes to kdthreads
    "token",                             # auto-routes to kdtoken
    "xinfo nt+0x1000",                   # auto-routes to kdxinfo
    "xinfo 0xfffff78000000000",
    "dt _EPROCESS",                      # already non-prefixed
    "pte 0xfffff80206ea3000",            # auto-routes to kdpte
    "checksec",                          # auto-routes to kdchecksec
    "kddisconnect",
    "lm",                                # back to userland — should NOT route
]

for c in commands:
    run(c)
