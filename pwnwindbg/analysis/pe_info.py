"""PE analysis: checksec, IAT display, section info."""

import pefile
import os


def checksec(pe_path):
    """Analyze PE mitigations. Returns dict of findings."""
    try:
        pe = pefile.PE(pe_path)
    except Exception as e:
        return {"error": str(e)}

    results = {}

    # ASLR (Dynamic Base)
    if hasattr(pe, 'OPTIONAL_HEADER'):
        dll_chars = pe.OPTIONAL_HEADER.DllCharacteristics
        results["ASLR"] = bool(dll_chars & 0x0040)  # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        results["High Entropy VA"] = bool(dll_chars & 0x0020)  # IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
        results["DEP/NX"] = bool(dll_chars & 0x0100)  # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        results["SEH"] = not bool(dll_chars & 0x0400)  # IMAGE_DLLCHARACTERISTICS_NO_SEH (inverted)
        results["No SEH"] = bool(dll_chars & 0x0400)
        results["CFG"] = bool(dll_chars & 0x4000)  # IMAGE_DLLCHARACTERISTICS_GUARD_CF
        results["Force Integrity"] = bool(dll_chars & 0x0080)
        results["Isolation"] = not bool(dll_chars & 0x0200)  # IMAGE_DLLCHARACTERISTICS_NO_ISOLATION

        # SafeSEH - check LOAD_CONFIG directory
        results["SafeSEH"] = False
        if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
            lc = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
            if hasattr(lc, 'SEHandlerCount'):
                results["SafeSEH"] = True
                results["SEHandlerCount"] = lc.SEHandlerCount
            if hasattr(lc, 'GuardCFFunctionCount'):
                results["CFG Functions"] = lc.GuardCFFunctionCount

    # Architecture
    results["Arch"] = "x64" if pe.FILE_HEADER.Machine == 0x8664 else "x86"
    results["DLL"] = bool(pe.FILE_HEADER.Characteristics & 0x2000)

    pe.close()
    return results


def get_iat(pe_path):
    """Get Import Address Table entries. Returns list of (dll, func_name, address)."""
    try:
        pe = pefile.PE(pe_path)
    except Exception:
        return []

    entries = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for dll_entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = dll_entry.dll.decode('utf-8', errors='replace')
            for imp in dll_entry.imports:
                func_name = imp.name.decode('utf-8', errors='replace') if imp.name else f"ord:{imp.ordinal}"
                address = imp.address
                entries.append((dll_name, func_name, address))

    pe.close()
    return entries


def get_sections(pe_path):
    """Get section info. Returns list of dicts."""
    try:
        pe = pefile.PE(pe_path)
    except Exception:
        return []

    sections = []
    for s in pe.sections:
        name = s.Name.decode('utf-8', errors='replace').strip('\x00')
        chars = s.Characteristics
        perms = ""
        if chars & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
            perms += "x"
        if chars & 0x40000000:  # IMAGE_SCN_MEM_READ
            perms += "r"
        if chars & 0x80000000:  # IMAGE_SCN_MEM_WRITE
            perms += "w"

        sections.append({
            "name": name,
            "virtual_address": s.VirtualAddress,
            "virtual_size": s.Misc_VirtualSize,
            "raw_size": s.SizeOfRawData,
            "characteristics": chars,
            "perms": perms,
        })

    pe.close()
    return sections


def get_pe_info(pe_path):
    """Get basic PE info."""
    try:
        pe = pefile.PE(pe_path)
    except Exception:
        return {}

    info = {
        "machine": hex(pe.FILE_HEADER.Machine),
        "is_64bit": pe.FILE_HEADER.Machine == 0x8664,
        "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        "image_base": pe.OPTIONAL_HEADER.ImageBase,
        "section_alignment": pe.OPTIONAL_HEADER.SectionAlignment,
        "file_alignment": pe.OPTIONAL_HEADER.FileAlignment,
        "size_of_image": pe.OPTIONAL_HEADER.SizeOfImage,
        "subsystem": pe.OPTIONAL_HEADER.Subsystem,
        "num_sections": pe.FILE_HEADER.NumberOfSections,
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
    }

    pe.close()
    return info
