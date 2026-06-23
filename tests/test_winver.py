"""Tests for winver.FileVersion and to_ini_section() formatting."""
from __future__ import annotations

import pytest

from winver import FileVersion


def _ms(major: int, minor: int) -> int:
    return (major << 16) | minor


def _ls(build: int, patch: int) -> int:
    return (build << 16) | patch


@pytest.mark.parametrize(
    "major,minor,build,patch",
    [
        (10, 0, 19041, 4506),   # Win10 22H2 shape
        (6, 1, 7601, 24545),    # Win7 SP1 shape
        (6, 3, 9600, 19685),    # Win8.1 shape
        (6, 2, 9200, 1),        # Win8.0 shape
        (6, 0, 6002, 2),        # Vista shape
        (0, 0, 0, 0),           # zero
        (0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF),  # max 16-bit fields
    ],
)
def test_file_version_roundtrip(major, minor, build, patch):
    fv = FileVersion(ms=_ms(major, minor), ls=_ls(build, patch))
    assert fv.major == major
    assert fv.minor == minor
    assert fv.build == build
    assert fv.patch == patch
    assert fv.to_ini_section() == f"{major}.{minor}.{build}.{patch}"


def test_file_version_ms_used_for_branching():
    # termsrv.py / nosymbol.py branch on ver.ms for Vista/Win7/Win8 paths.
    # Lock down the encoding so a future refactor doesn't silently break it.
    assert FileVersion(ms=0x00060000, ls=0).ms == 0x00060000  # Vista
    assert FileVersion(ms=0x00060001, ls=0).ms == 0x00060001  # Win7
    assert FileVersion(ms=0x00060002, ls=0).ms == 0x00060002  # Win8
    assert FileVersion(ms=0x00060003, ls=0).ms == 0x00060003  # Win8.1
    assert FileVersion(ms=0x000A0000, ls=0).ms == 0x000A0000  # Win10/11


def test_file_version_is_frozen():
    fv = FileVersion(ms=1, ls=2)
    with pytest.raises(Exception):
        fv.ms = 99  # type: ignore[misc]
