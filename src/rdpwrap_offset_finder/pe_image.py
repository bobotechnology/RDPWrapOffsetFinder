from __future__ import annotations

from dataclasses import dataclass

import pefile


@dataclass(frozen=True)
class MemoryImage:
    """A PE loaded into memory as the Windows loader would map it.

    This mirrors what the C++ `_nosymbol` tool does via VirtualAlloc + section copies,
    enabling direct RVA/VA indexing for disassembly.
    """

    pe: pefile.PE
    image_base: int
    image: bytes
    is_64: bool


def load_memory_image(pe: pefile.PE) -> MemoryImage:
    size = int(pe.OPTIONAL_HEADER.SizeOfImage)
    img = bytearray(b"\x00" * size)
    for sec in pe.sections:
        va = int(sec.VirtualAddress)
        raw = sec.get_data()
        vsz = int(sec.Misc_VirtualSize)
        img[va:va + min(len(raw), vsz)] = raw[:vsz]

    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    is_64 = pe.OPTIONAL_HEADER.Magic == 0x20B
    return MemoryImage(pe=pe, image_base=image_base, image=bytes(img), is_64=is_64)
