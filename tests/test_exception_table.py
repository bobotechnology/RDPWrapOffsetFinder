"""Tests for exception_table.py: x64 .pdata parsing and unwind chain backtrace.

The x64 PE exception directory (.pdata) is an array of 12-byte RUNTIME_FUNCTION
entries. Each entry's UnwindInfo may chain to another RUNTIME_FUNCTION via the
UNW_FLAG_CHAININFO flag, which is what backtrace_x64() follows to find the
"real" function start when the initial entry is just a fragment.
"""
from __future__ import annotations

import struct

import pytest

from exception_table import (
    UNW_FLAG_CHAININFO,
    backtrace_x64,
    parse_exception_directory_x64,
)


def _runtime_function_bytes(begin: int, end: int, unwind: int) -> bytes:
    return struct.pack("<III", begin, end, unwind)


def _unwind_info_bytes(flags: int, count_of_codes: int = 0) -> bytes:
    """Minimal UnwindInfo: 4-byte header + (count_of_codes+1)&~1 * 2 bytes of
    code slots (zeroed). Version is always 1."""
    version_flags = (1 & 0x7) | ((flags & 0x1F) << 3)
    header = bytes([version_flags, 0, count_of_codes & 0xFF, 0])
    code_slots = (count_of_codes + 1) & ~1
    return header + b"\x00" * (2 * code_slots)


# ---------------------------------------------------------------------------
# parse_exception_directory_x64
# ---------------------------------------------------------------------------

import pefile  # noqa: F401  (ensures DIRECTORY_ENTRY is populated)

# Index of the exception directory in DATA_DIRECTORY (IMAGE_DIRECTORY_ENTRY_EXCEPTION).
_EXC_DIR_INDEX = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]


def _make_fake_pe(exc_dd_rva: int, exc_dd_size: int):
    """Build a minimal fake PE-like object with a 16-entry DATA_DIRECTORY
    where only the exception directory (index 3) is populated."""
    class FakeDD:
        def __init__(self, va=0, size=0):
            self.VirtualAddress = va
            self.Size = size

    data_dirs = [FakeDD() for _ in range(16)]
    data_dirs[_EXC_DIR_INDEX] = FakeDD(va=exc_dd_rva, size=exc_dd_size)

    class FakeOptionalHeader:
        pass

    class FakePE:
        pass

    pe = FakePE()
    pe.OPTIONAL_HEADER = FakeOptionalHeader()
    pe.OPTIONAL_HEADER.DATA_DIRECTORY = data_dirs
    return pe


def test_parse_empty_directory():
    """No EXCEPTION directory (size=0) → empty list."""
    image = b"\x00" * 0x1000
    pe = _make_fake_pe(exc_dd_rva=0, exc_dd_size=0)
    result = parse_exception_directory_x64(pe, image)
    assert result == []


def test_parse_single_runtime_function():
    """One RUNTIME_FUNCTION entry is parsed correctly."""
    rdata_rva = 0x1000
    func_begin = 0x100
    func_end = 0x200
    unwind_rva = 0x500

    image = bytearray(0x2000)
    rf_bytes = _runtime_function_bytes(func_begin, func_end, unwind_rva)
    image[rdata_rva:rdata_rva + 12] = rf_bytes

    pe = _make_fake_pe(exc_dd_rva=rdata_rva, exc_dd_size=12)
    result = parse_exception_directory_x64(pe, bytes(image))
    assert len(result) == 1
    assert result[0].begin_rva == func_begin
    assert result[0].end_rva == func_end
    assert result[0].unwind_rva == unwind_rva


def test_parse_multiple_entries_with_zero_padding():
    """The parser skips all-zero entries (used as padding at the end)."""
    rdata_rva = 0x1000
    image = bytearray(0x2000)
    image[rdata_rva:rdata_rva + 12] = _runtime_function_bytes(0x100, 0x200, 0x500)
    image[rdata_rva + 12:rdata_rva + 24] = _runtime_function_bytes(0x300, 0x400, 0x600)
    image[rdata_rva + 24:rdata_rva + 36] = _runtime_function_bytes(0, 0, 0)

    pe = _make_fake_pe(exc_dd_rva=rdata_rva, exc_dd_size=36)
    result = parse_exception_directory_x64(pe, bytes(image))
    assert len(result) == 2
    assert result[0].begin_rva == 0x100
    assert result[1].begin_rva == 0x300


# ---------------------------------------------------------------------------
# backtrace_x64
# ---------------------------------------------------------------------------

def test_backtrace_no_chain_returns_same_function():
    """UnwindInfo without UNW_FLAG_CHAININFO → backtrace returns the input."""
    func_begin = 0x100
    func_end = 0x200
    unwind_rva = 0x500

    image = bytearray(0x1000)
    # UnwindInfo at unwind_rva with flags=0 (no chain), version=1.
    image[unwind_rva:unwind_rva + 4] = _unwind_info_bytes(flags=0, count_of_codes=0)

    from exception_table import RuntimeFunction
    func = RuntimeFunction(begin_rva=func_begin, end_rva=func_end, unwind_rva=unwind_rva)
    result = backtrace_x64(bytes(image), func)
    assert result.begin_rva == func_begin
    assert result.end_rva == func_end


def test_backtrace_follows_chain_to_root():
    """UNW_FLAG_CHAININFO → backtrace follows the chain to the root function.

    Layout:
      func_A (0x100-0x200, unwind@0x500, flags=CHAININFO → points to func_B)
      func_B (0x1000-0x1100, unwind@0x600, flags=0 — root)

    backtrace_x64(func_A) should return func_B.
    """
    image = bytearray(0x2000)

    # func_B (root): UnwindInfo at 0x600, no chain.
    unwind_b_rva = 0x600
    image[unwind_b_rva:unwind_b_rva + 4] = _unwind_info_bytes(flags=0, count_of_codes=0)

    func_b_begin = 0x1000
    func_b_end = 0x1100

    # func_A: UnwindInfo at 0x500, flags=CHAININFO.
    # Chained RUNTIME_FUNCTION is at offset unwind_rva + 4 + (count+1)&~1 * 2.
    # With count=0: offset = 0x500 + 4 + 0 = 0x504. Wait, (0+1)&~1 = 0. So +0.
    # Actually (count_of_codes + 1) & ~1: (0+1)&~1 = 1&~1 = 0. So chained RF at unwind+4+0=0x504.
    unwind_a_rva = 0x500
    count_a = 0
    image[unwind_a_rva:unwind_a_rva + 4] = _unwind_info_bytes(
        flags=UNW_FLAG_CHAININFO, count_of_codes=count_a
    )
    chained_rf_offset = unwind_a_rva + 4 + (2 * ((count_a + 1) & ~1))
    # (0+1)&~1 = 0, so chained_rf_offset = 0x500 + 4 + 0 = 0x504
    image[chained_rf_offset:chained_rf_offset + 12] = _runtime_function_bytes(
        func_b_begin, func_b_end, unwind_b_rva
    )

    from exception_table import RuntimeFunction
    func_a = RuntimeFunction(begin_rva=0x100, end_rva=0x200, unwind_rva=unwind_a_rva)
    result = backtrace_x64(bytes(image), func_a)
    assert result.begin_rva == func_b_begin
    assert result.end_rva == func_b_end


def test_backtrace_handles_indirect_unwind_rva():
    """When unwind_rva has bit 0 set (RUNTIME_FUNCTION_INDIRECT), the actual
    RUNTIME_FUNCTION is read from unwind_rva & ~3."""
    image = bytearray(0x2000)

    # Indirect: unwind_rva = 0x501 (bit 0 set) → read RF from 0x500.
    indirect_rva = 0x501
    real_rf_rva = 0x500

    func_b_begin = 0x1000
    func_b_end = 0x1100
    unwind_b_rva = 0x600
    image[unwind_b_rva:unwind_b_rva + 4] = _unwind_info_bytes(flags=0, count_of_codes=0)

    # Write the real RUNTIME_FUNCTION at 0x500.
    image[real_rf_rva:real_rf_rva + 12] = _runtime_function_bytes(
        func_b_begin, func_b_end, unwind_b_rva
    )

    from exception_table import RuntimeFunction
    func = RuntimeFunction(begin_rva=0x100, end_rva=0x200, unwind_rva=indirect_rva)
    result = backtrace_x64(bytes(image), func)
    assert result.begin_rva == func_b_begin
