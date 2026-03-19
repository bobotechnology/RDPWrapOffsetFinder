from __future__ import annotations

from dataclasses import dataclass

import pefile


@dataclass(frozen=True)
class ImportFunction:
    dll: str
    name: str
    iat_rva: int


def find_iat_rva(pe: pefile.PE, dll_name: str, func_name: str) -> int | None:
    """Return IAT entry RVA for imported function, or None.

    C++ `_nosymbol` uses this to find imported `memset` and `VerifyVersionInfoW`.
    We return the RVA of the IAT slot.
    """

    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        try:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        except Exception:
            return None

    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = entry.dll.decode(errors="ignore") if entry.dll else ""
        if dll.lower() != dll_name.lower():
            continue
        for imp in entry.imports:
            if not imp.name:
                continue
            name = imp.name.decode(errors="ignore")
            if name.lower() == func_name.lower():
                # `imp.address` is the VA at runtime; convert to RVA.
                return int(imp.address) - int(pe.OPTIONAL_HEADER.ImageBase)
    return None
