"""Display module facade: re-exports all display functions from sub-modules.

All command modules import from here so they don't need to know
the internal split. Each sub-module handles one display concern:
  - common.py         — console, colors, banners, messages
  - registers.py      — register display
  - disasm_view.py    — disassembly display
  - stack_view.py     — stack display
  - vmmap_view.py     — memory map display
  - telescope_view.py — pointer chain display
  - checksec_view.py  — checksec & IAT display
  - memory_view.py    — hex dump display (x/ commands)
  - misc_view.py      — process info, breakpoints, backtrace
"""

# Common
from .common import (
    console, banner, separator,
    error, info, success, warn,
    prot_color as _prot_color,
    ADDR_COLOR, SYMBOL_COLOR, BANNER_COLOR, ARROW_COLOR,
    CHAIN_ARROW_COLOR, STRING_COLOR,
)

# Feature displays
from .registers import display_registers
from .disasm_view import display_disasm
from .stack_view import display_stack
from .vmmap_view import display_vmmap
from .telescope_view import display_telescope
from .checksec_view import display_checksec, display_iat
from .memory_view import display_hex_bytes, display_hex_dwords
from .misc_view import display_process_info, display_breakpoints, display_backtrace
