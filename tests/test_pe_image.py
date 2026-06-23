"""Tests for pe_image.load_memory_image.

load_memory_image takes a parsed PE and produces a flat byte buffer of
SizeOfImage bytes with each section copied to its VirtualAddress. This is the
"memory image" that all subsequent disassembly/xref scans operate on.

Rather than constructing a full valid PE byte stream (fragile and tests pefile
more than our code), we build a lightweight mock PE with the fields
load_memory_image actually touches: OPTIONAL_HEADER.SizeOfImage / ImageBase /
Magic, and a sections list where each entry exposes VirtualAddress,
Misc_VirtualSize, and get_data().
"""
from __future__ import annotations

import struct

import pytest

from pe_image import load_memory_image


# ---------------------------------------------------------------------------
# Mock PE builder
# ---------------------------------------------------------------------------

class _MockSection:
    """Mimics pefile.SectionStructure for the fields load_memory_image reads."""
    def __init__(self, virtual_address: int, virtual_size: int, data: bytes):
        self.VirtualAddress = virtual_address
        self.Misc_VirtualSize = virtual_size
        self._data = data

    def get_data(self) -> bytes:
        return self._data


class _MockOptionalHeader:
    def __init__(self, size_of_image: int, image_base: int, magic: int):
        self.SizeOfImage = size_of_image
        self.ImageBase = image_base
        self.Magic = magic


class _MockPE:
    def __init__(self, sections, size_of_image, image_base, is_64):
        self.sections = sections
        self.OPTIONAL_HEADER = _MockOptionalHeader(
            size_of_image=size_of_image,
            image_base=image_base,
            magic=0x20B if is_64 else 0x10B,
        )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_load_memory_image_basic_x64():
    """Single .text section is mapped to its RVA in the image buffer."""
    text_data = b"\x48\x89\xC8"  # MOV RAX, RCX
    text_rva = 0x1000
    pe = _MockPE(
        sections=[_MockSection(text_rva, len(text_data), text_data)],
        size_of_image=0x2000,
        image_base=0x180000000,
        is_64=True,
    )
    mem = load_memory_image(pe)

    assert mem.is_64 is True
    assert mem.image_base == 0x180000000
    assert len(mem.image) == 0x2000
    # .text data appears at its VirtualAddress.
    assert mem.image[text_rva:text_rva + len(text_data)] == text_data


def test_load_memory_image_basic_x86():
    """x86 PE (Magic=0x10B) → is_64 is False."""
    text_data = b"\x89\xC8"  # MOV EAX, ECX
    pe = _MockPE(
        sections=[_MockSection(0x1000, len(text_data), text_data)],
        size_of_image=0x2000,
        image_base=0x10000000,
        is_64=False,
    )
    mem = load_memory_image(pe)
    assert mem.is_64 is False
    assert mem.image_base == 0x10000000


def test_load_memory_image_multiple_sections():
    """Two sections (.text + .rdata) are each mapped to their own RVA."""
    text_data = b"\xCC" * 16
    rdata_data = b"Hello, World!\x00"
    text_rva = 0x1000
    rdata_rva = 0x2000
    pe = _MockPE(
        sections=[
            _MockSection(text_rva, len(text_data), text_data),
            _MockSection(rdata_rva, len(rdata_data), rdata_data),
        ],
        size_of_image=0x3000,
        image_base=0x10000000,
        is_64=True,
    )
    mem = load_memory_image(pe)
    assert mem.image[text_rva:text_rva + len(text_data)] == text_data
    assert mem.image[rdata_rva:rdata_rva + len(rdata_data)] == rdata_data


def test_load_memory_image_size_matches_sizeofimage():
    """Image buffer length equals OPTIONAL_HEADER.SizeOfImage exactly."""
    pe = _MockPE(
        sections=[_MockSection(0x1000, 0x500, b"\x90" * 0x500)],
        size_of_image=0x4000,
        image_base=0x10000000,
        is_64=True,
    )
    mem = load_memory_image(pe)
    assert len(mem.image) == 0x4000


def test_load_memory_image_uninitialized_regions_are_zero():
    """Bytes outside any section (headers, gaps) are zero-filled."""
    pe = _MockPE(
        sections=[_MockSection(0x1000, 0x100, b"\xAA" * 0x100)],
        size_of_image=0x3000,
        image_base=0x10000000,
        is_64=True,
    )
    mem = load_memory_image(pe)
    # Header region (RVA 0..0x1000) should be zero.
    assert mem.image[0:0x1000] == b"\x00" * 0x1000
    # Gap after section (0x1100..0x3000) should be zero.
    assert mem.image[0x1100:0x3000] == b"\x00" * (0x3000 - 0x1100)


def test_load_memory_image_truncates_to_virtual_size():
    """When raw data is longer than VirtualSize, only VirtualSize bytes are
    copied (matching Windows loader behavior)."""
    raw = b"\xBB" * 0x200
    virtual_size = 0x100  # shorter than raw
    pe = _MockPE(
        sections=[_MockSection(0x1000, virtual_size, raw)],
        size_of_image=0x2000,
        image_base=0x10000000,
        is_64=True,
    )
    mem = load_memory_image(pe)
    # Only virtual_size bytes copied; rest is zero.
    assert mem.image[0x1000:0x1000 + virtual_size] == b"\xBB" * virtual_size
    assert mem.image[0x1000 + virtual_size:0x1200] == b"\x00" * (0x200 - virtual_size)


def test_load_memory_image_zero_virtual_size_copies_nothing():
    """When Misc_VirtualSize is 0, copy_len = min(len(raw), 0) = 0, so no
    bytes are copied. This matches the implementation's min() contract; real
    PEs always have VirtualSize > 0, but we lock down the edge case."""
    raw = b"\xCC" * 0x100
    pe = _MockPE(
        sections=[_MockSection(0x1000, 0, raw)],  # VirtualSize=0
        size_of_image=0x2000,
        image_base=0x10000000,
        is_64=True,
    )
    mem = load_memory_image(pe)
    # No data copied — region stays zero.
    assert mem.image[0x1000:0x1100] == b"\x00" * 0x100
