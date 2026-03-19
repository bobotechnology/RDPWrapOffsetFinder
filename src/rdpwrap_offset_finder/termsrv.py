"""Module for analyzing termsrv.dll and extracting RDPWrap offsets.

This module handles loading the PE file, performing analysis with either
symbol-based or heuristic approaches, and formatting the output for RDPWrap.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import pefile

from .winver import get_file_version_from_vs_version_info


@dataclass(frozen=True)
class TermsrvContext:
    """Container for termsrv.dll analysis context data.
    
    Attributes:
        path: Path to the DLL file
        pe: Loaded PE file object
        is_64: True if the DLL is 64-bit, False if 32-bit
        image_base: Base address of the loaded image
    """
    path: Path
    pe: pefile.PE
    is_64: bool
    image_base: int


def _get_default_termsrv_path() -> Path:
    """Get the default path for termsrv.dll.
    
    Returns:
        Path to termsrv.dll in System32 directory.
    """
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    return Path(sysroot) / "System32" / "termsrv.dll"


def _load_pe_file(path: Path) -> TermsrvContext:
    """Load a PE file and extract basic information.
    
    Args:
        path: Path to the PE file to load
        
    Returns:
        TermsrvContext object with loaded PE information
    """
    pe = pefile.PE(str(path), fast_load=False)
    is_64 = pe.OPTIONAL_HEADER.Magic == 0x20B  # IMAGE_NT_OPTIONAL_HDR64_MAGIC
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    return TermsrvContext(path=path, pe=pe, is_64=is_64, image_base=image_base)


def analyze_termsrv(
    path: str | os.PathLike[str] | None,
    use_symbols: bool = True,
) -> str:
    """Analyze termsrv.dll to extract RDPWrap offsets.
    
    Args:
        path: Path to termsrv.dll. If None, uses default system path.
        use_symbols: If True, use PDB symbol-based analysis. If False, use heuristic search.
        
    Returns:
        Formatted INI content with extracted offsets.
        
    Raises:
        FileNotFoundError: If the specified termsrv.dll file is not found.
    """
    dll_path = Path(path) if path else _get_default_termsrv_path()
    if not dll_path.exists():
        raise FileNotFoundError(f"termsrv.dll not found: {dll_path}")

    ctx = _load_pe_file(dll_path)
    ver = get_file_version_from_vs_version_info(ctx.pe)
    arch = "x64" if ctx.is_64 else "x86"

    if use_symbols:
        from .symbols import analyze as analyze_symbols
        raw = analyze_symbols(ctx.pe, dll_path, ver).text
    else:
        from .nosymbol import analyze as analyze_nosymbol
        log_name = f"{ver.to_ini_section()}_{arch}.log"
        log_path = Path.cwd() / "log" / log_name
        raw = analyze_nosymbol(ctx.pe, dll_path, ver, log_path=log_path).text

    return _normalize_ini_output(raw, arch=arch)


def _normalize_ini_output(raw: str, *, arch: str) -> str:
    """Normalize raw analysis output to standardized INI format.
    
    Args:
        raw: Raw output from analysis modules
        arch: Architecture string ("x64" or "x86")
        
    Returns:
        Formatted INI content with consistent structure.
    """
    sections: dict[str, dict[str, str]] = {}
    section_order: list[str] = []
    current_section: str | None = None

    # Parse raw output into sections dictionary
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("ERROR:"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            current_section = stripped[1:-1]
            if current_section not in sections:
                sections[current_section] = {}
                section_order.append(current_section)
            continue
        if current_section is None or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        sections[current_section][key.strip()] = value.strip()

    def _get_value(section: str, key: str) -> str | None:
        """Get value from section, returning None if not found."""
        return sections.get(section, {}).get(key)

    def _get_flag(section: str, key: str) -> str:
        """Get flag value from section, defaulting to '0' if not found."""
        value = _get_value(section, key)
        return value if value is not None else "0"

    # Get base versions (excluding SLInit variants)
    base_versions = [section for section in section_order if not section.endswith("-SLInit")]

    output_lines: list[str] = []
    for version in base_versions:
        main_section = version
        slinit_section = f"{version}-SLInit"

        # Add main version section
        output_lines.append(f"[{version}]")
        output_lines.append(f"LocalOnlyPatch.{arch}={_get_flag(main_section, f'LocalOnlyPatch.{arch}')}")
        output_lines.append(f"LocalOnlyOffset.{arch}={_get_value(main_section, f'LocalOnlyOffset.{arch}') or ''}")
        output_lines.append(f"LocalOnlyCode.{arch}={_get_value(main_section, f'LocalOnlyCode.{arch}') or ''}")
        output_lines.append(f"SingleUserPatch.{arch}={_get_flag(main_section, f'SingleUserPatch.{arch}')}")
        output_lines.append(f"SingleUserOffset.{arch}={_get_value(main_section, f'SingleUserOffset.{arch}') or ''}")
        output_lines.append(f"SingleUserCode.{arch}={_get_value(main_section, f'SingleUserCode.{arch}') or ''}")
        output_lines.append(f"DefPolicyPatch.{arch}={_get_flag(main_section, f'DefPolicyPatch.{arch}')}")
        output_lines.append(f"DefPolicyOffset.{arch}={_get_value(main_section, f'DefPolicyOffset.{arch}') or ''}")
        output_lines.append(f"DefPolicyCode.{arch}={_get_value(main_section, f'DefPolicyCode.{arch}') or ''}")
        output_lines.append(f"SLInitHook.{arch}={_get_flag(main_section, f'SLInitHook.{arch}')}")
        output_lines.append(f"SLInitOffset.{arch}={_get_value(main_section, f'SLInitOffset.{arch}') or ''}")
        output_lines.append(f"SLInitFunc.{arch}={_get_value(main_section, f'SLInitFunc.{arch}') or ''}")
        output_lines.append("")
        
        # Add SLInit section
        output_lines.append(f"[{slinit_section}]")

        # Define global variable keys for SLInit section
        global_var_keys = (
            "bInitialized", "bServerSku", "lMaxUserSessions", "bAppServerAllowed",
            "bRemoteConnAllowed", "bMultimonAllowed", "ulMaxDebugSessions", "bFUSEnabled",
        )
        global_full_keys = [f"{key}.{arch}" for key in global_var_keys]
        padding_width = max((len(full_key) for full_key in global_full_keys), default=0)
        
        # Add global variables with consistent padding
        for full_key in global_full_keys:
            output_lines.append(f"{full_key.ljust(padding_width)}={_get_value(slinit_section, full_key) or ''}")
        output_lines.append("")

    # If no base versions were found, return raw output
    if not base_versions:
        return raw if raw.endswith("\n") else raw + "\n"

    # Remove trailing empty lines
    while output_lines and output_lines[-1] == "":
        output_lines.pop()
    
    return "\n".join(output_lines) + "\n"
