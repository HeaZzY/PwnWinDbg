"""Checksec and IAT display rendering."""

from rich.text import Text

from .common import console, banner, ADDR_COLOR


def display_checksec(results):
    """Display PE security mitigations."""
    banner("CHECKSEC")

    for key, val in results.items():
        if key == "error":
            console.print(f"  [bright_red]Error: {val}[/]")
            continue

        text = Text()
        text.append(f"  {key:20s}", style="bold white")

        if isinstance(val, bool):
            if key in ("No SEH",):
                color = "bright_red" if val else "bright_green"
                text.append("Yes" if val else "No", style=color)
            elif key in ("ASLR", "DEP/NX", "CFG", "SafeSEH", "High Entropy VA"):
                color = "bright_green" if val else "bright_red"
                text.append("Enabled" if val else "Disabled", style=color)
            else:
                text.append(str(val), style="white")
        else:
            text.append(str(val), style="white")

        console.print(text)


def display_iat(entries, ptr_size):
    """Display Import Address Table entries."""
    banner("IAT / GOT")

    ptr_fmt = "0x{:016x}" if ptr_size == 8 else "0x{:08x}"
    current_dll = None

    for dll_name, func_name, address in entries:
        if dll_name != current_dll:
            current_dll = dll_name
            console.print(f"\n  [bold bright_cyan]{dll_name}[/]")

        text = Text()
        text.append(f"    {ptr_fmt.format(address)}", style=ADDR_COLOR)
        text.append(f"  {func_name}", style="white")
        console.print(text)
