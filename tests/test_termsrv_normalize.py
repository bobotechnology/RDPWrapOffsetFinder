"""Tests for termsrv._normalize_ini_output.

This is the INI formatting layer that takes scattered key=value lines from
either analyzer (symbol/nosymbol) and produces the canonical rdpwrap.ini
section layout with fixed key ordering and SLInit subsection alignment.
"""
from __future__ import annotations

from termsrv import _normalize_ini_output


# Canonical key order produced by _normalize_ini_output, locked down so a
# future refactor doesn't silently reorder rdpwrap.ini keys.
_MAIN_KEYS = [
    "LocalOnlyPatch", "LocalOnlyOffset", "LocalOnlyCode",
    "SingleUserPatch", "SingleUserOffset", "SingleUserCode",
    "DefPolicyPatch", "DefPolicyOffset", "DefPolicyCode",
    "SLInitHook", "SLInitOffset", "SLInitFunc",
]
_SLINIT_KEYS = [
    "bInitialized", "bServerSku", "lMaxUserSessions", "bAppServerAllowed",
    "bRemoteConnAllowed", "bMultimonAllowed", "ulMaxDebugSessions", "bFUSEnabled",
]


def _build_main_input(arch: str, **overrides: str) -> str:
    """Build raw input lines for a main section. Defaults to all-empty so the
    caller only specifies the keys they care about."""
    lines = [f"[10.0.19041.4506]"]
    for k in _MAIN_KEYS:
        full = f"{k}.{arch}"
        val = overrides.get(k, "")
        if val:
            lines.append(f"{full}={val}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Happy path: a full modern (Win10+) x64 section is reordered & aligned.
# ---------------------------------------------------------------------------

def test_normalize_full_modern_x64():
    raw = "\n".join([
        "[10.0.19041.4506]",
        # Intentionally shuffled — output must be in canonical order.
        "SingleUserPatch.x64=1",
        "SingleUserOffset.x64=AAAA",
        "SingleUserCode.x64=nop_3",
        "LocalOnlyPatch.x64=1",
        "LocalOnlyOffset.x64=BBBB",
        "LocalOnlyCode.x64=nopjmp",
        "DefPolicyPatch.x64=1",
        "DefPolicyOffset.x64=CCCC",
        "DefPolicyCode.x64=CDefPolicy_Query_eax_rcx",
        "SLInitHook.x64=1",
        "SLInitOffset.x64=DDDD",
        "SLInitFunc.x64=New_CSLQuery_Initialize",
        "",
        "[10.0.19041.4506-SLInit]",
        "bInitialized.x64=1ABC",
        "bServerSku.x64=2DEF",
        "lMaxUserSessions.x64=3",
        "bAppServerAllowed.x64=4",
        "bRemoteConnAllowed.x64=5",
        "bMultimonAllowed.x64=6",
        "ulMaxDebugSessions.x64=7",
        "bFUSEnabled.x64=8",
        "",
    ])

    out = _normalize_ini_output(raw, arch="x64")

    # Main section keys appear in canonical order.
    main_block = out.split("[10.0.19041.4506]\n", 1)[1]
    main_block = main_block.split("\n[10.0.19041.4506-SLInit]", 1)[0]
    main_keys = [ln.split("=", 1)[0] for ln in main_block.splitlines() if "=" in ln]
    expected_main_keys = [f"{k}.x64" for k in _MAIN_KEYS]
    assert main_keys == expected_main_keys, f"main keys out of order: {main_keys}"

    # Values preserved.
    assert "LocalOnlyOffset.x64=BBBB" in out
    assert "SingleUserOffset.x64=AAAA" in out
    assert "DefPolicyCode.x64=CDefPolicy_Query_eax_rcx" in out

    # SLInit subsection: keys aligned to the longest key width.
    slinit_block = out.split("[10.0.19041.4506-SLInit]\n", 1)[1]
    slinit_lines = [ln for ln in slinit_block.splitlines() if "=" in ln]
    # Keys are ljust-padded; strip trailing spaces before comparing.
    keys = [ln.split("=", 1)[0].rstrip() for ln in slinit_lines]
    expected_slinit_keys = [f"{k}.x64" for k in _SLINIT_KEYS]
    assert keys == expected_slinit_keys, f"slinit keys out of order: {keys}"

    # Every key padded to the width of the longest one.
    expected_width = max(len(k) for k in expected_slinit_keys)
    for ln in slinit_lines:
        key = ln.split("=", 1)[0]
        assert len(key) == expected_width, f"key {key!r} (len={len(key)}) not padded to {expected_width}"


# ---------------------------------------------------------------------------
# Missing keys default to empty / "0" per the documented contract.
# ---------------------------------------------------------------------------

def test_normalize_missing_keys_get_defaults():
    raw = _build_main_input("x86", DefPolicyPatch="1", DefPolicyOffset="ABCD",
                            DefPolicyCode="CDefPolicy_Query_eax_edx")
    out = _normalize_ini_output(raw, arch="x86")
    # Patch flags default to "0" when absent.
    assert "LocalOnlyPatch.x86=0" in out
    assert "SingleUserPatch.x86=0" in out
    assert "SLInitHook.x86=0" in out
    # Offset/Code/Func keys default to empty.
    assert "LocalOnlyOffset.x86=" in out
    assert "SingleUserCode.x86=" in out
    assert "SLInitFunc.x86=" in out


def test_normalize_empty_slinit_section_is_emitted():
    """Even if the analyzer found no SLInit globals, the section header must
    still be emitted so the rdpwrap.ini parser sees a well-formed block."""
    raw = _build_main_input("x64", DefPolicyPatch="1", DefPolicyOffset="1", DefPolicyCode="x")
    out = _normalize_ini_output(raw, arch="x64")
    assert "[10.0.19041.4506-SLInit]" in out


# ---------------------------------------------------------------------------
# Garbage resilience: ERROR lines, blank lines, stray text are dropped.
# ---------------------------------------------------------------------------

def test_normalize_drops_error_and_blank_lines():
    raw = "\n".join([
        "",
        "ERROR: something failed",
        "[10.0.19041.1]",
        "",
        "DefPolicyPatch.x64=1",
        "garbage line without equals",
        "DefPolicyOffset.x64=42",
        "DefPolicyCode.x64=xx",
    ])
    out = _normalize_ini_output(raw, arch="x64")
    assert "ERROR" not in out
    assert "garbage" not in out
    assert "DefPolicyPatch.x64=1" in out


def test_normalize_passthrough_when_no_sections():
    """If the input has no section headers, the function returns the raw text
    unchanged (with trailing newline normalization)."""
    raw = "just some text\nwithout sections"
    out = _normalize_ini_output(raw, arch="x64")
    assert out == "just some text\nwithout sections\n"


def test_normalize_trailing_newline_normalized():
    raw = _build_main_input("x64", DefPolicyPatch="1", DefPolicyOffset="1", DefPolicyCode="x").rstrip("\n")
    out = _normalize_ini_output(raw, arch="x64")
    assert out.endswith("\n")
    assert not out.endswith("\n\n")  # no double trailing newline


def test_normalize_preserves_multiple_versions():
    """When the analyzer emits multiple version blocks (e.g. combined output),
    each is normalized independently and the order is preserved."""
    raw = "\n".join([
        "[6.1.7601.1]",
        "DefPolicyPatch.x86=1",
        "DefPolicyOffset.x86=A",
        "DefPolicyCode.x86=x",
        "",
        "[6.1.7601.1-SLInit]",
        "bServerSku.x86=1",
        "",
        "[10.0.19041.1]",
        "DefPolicyPatch.x64=1",
        "DefPolicyOffset.x64=B",
        "DefPolicyCode.x64=y",
        "",
        "[10.0.19041.1-SLInit]",
        "bServerSku.x64=2",
        "",
    ])
    out = _normalize_ini_output(raw, arch="x64")
    # Both main sections present, in original order.
    assert out.index("[6.1.7601.1]") < out.index("[10.0.19041.1]")
    # Both SLInit sections present.
    assert "[6.1.7601.1-SLInit]" in out
    assert "[10.0.19041.1-SLInit]" in out
