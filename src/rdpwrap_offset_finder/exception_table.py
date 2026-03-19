from __future__ import annotations

from dataclasses import dataclass

import pefile


@dataclass(frozen=True)
class RuntimeFunction:
    begin_rva: int
    end_rva: int
    unwind_rva: int


@dataclass(frozen=True)
class UnwindInfo:
    version: int
    flags: int
    count_of_codes: int


UNW_FLAG_CHAININFO = 0x4
RUNTIME_FUNCTION_INDIRECT = 0x1


def _u32(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off + 4], "little", signed=False)


def parse_exception_directory_x64(pe: pefile.PE, image: bytes) -> list[RuntimeFunction]:
    """Parse IMAGE_DIRECTORY_ENTRY_EXCEPTION into runtime function entries (x64)."""

    dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]]
    rva = int(dd.VirtualAddress)
    size = int(dd.Size)
    if rva == 0 or size == 0:
        return []

    data = image[rva:rva + size]
    out: list[RuntimeFunction] = []
    for off in range(0, len(data) - 11, 12):
        begin_rva = _u32(data, off)
        end_rva = _u32(data, off + 4)
        unwind_rva = _u32(data, off + 8)
        if begin_rva == 0 and end_rva == 0 and unwind_rva == 0:
            continue
        out.append(RuntimeFunction(begin_rva=begin_rva, end_rva=end_rva, unwind_rva=unwind_rva))
    return out


def _read_runtime_function(image: bytes, rva: int) -> RuntimeFunction:
    begin_rva = _u32(image, rva)
    end_rva = _u32(image, rva + 4)
    unwind_rva = _u32(image, rva + 8)
    return RuntimeFunction(begin_rva=begin_rva, end_rva=end_rva, unwind_rva=unwind_rva)


def _parse_unwind_info(image: bytes, rva: int) -> UnwindInfo:
    b0 = image[rva]
    version = b0 & 0x7
    flags = (b0 >> 3) & 0x1F
    count = image[rva + 2]
    return UnwindInfo(version=version, flags=flags, count_of_codes=count)


def backtrace_x64(image: bytes, func: RuntimeFunction) -> RuntimeFunction:
    """Follow chained unwind info to the outermost RuntimeFunction."""

    # Indirect unwind data points to another RUNTIME_FUNCTION.
    if func.unwind_rva & RUNTIME_FUNCTION_INDIRECT:
        func = _read_runtime_function(image, func.unwind_rva & ~0x3)

    unwind = _parse_unwind_info(image, func.unwind_rva)
    while unwind.flags & UNW_FLAG_CHAININFO:
        # UNWIND_CODE array starts at +4. It's an array of 2-byte slots.
        code_slots = (unwind.count_of_codes + 1) & ~1
        chained_off = func.unwind_rva + 4 + (2 * code_slots)
        func = _read_runtime_function(image, chained_off)
        if func.unwind_rva & RUNTIME_FUNCTION_INDIRECT:
            func = _read_runtime_function(image, func.unwind_rva & ~0x3)
        unwind = _parse_unwind_info(image, func.unwind_rva)
    return func
