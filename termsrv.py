from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pefile

from winver import get_file_version_from_vs_version_info


@dataclass(frozen=True)
class TermsrvContext:
    path: Path
    pe: pefile.PE
    is_64: bool
    image_base: int


def _get_default_termsrv_path() -> Path:
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    return Path(sysroot) / "System32" / "termsrv.dll"


def _load_pe_file(path: Path) -> TermsrvContext:
    pe = pefile.PE(str(path), fast_load=False)
    is_64 = pe.OPTIONAL_HEADER.Magic == 0x20B
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    return TermsrvContext(path=path, pe=pe, is_64=is_64, image_base=image_base)


def analyze_termsrv(
    path: str | os.PathLike[str] | None,
    use_symbols: bool = True,
    progress_callback: Callable[[str], None] | None = None,
) -> str:
    dll_path = Path(path) if path else _get_default_termsrv_path()
    if not dll_path.exists():
        raise FileNotFoundError(f"termsrv.dll not found: {dll_path}")

    ctx = _load_pe_file(dll_path)
    ver = get_file_version_from_vs_version_info(ctx.pe)
    arch = "x64" if ctx.is_64 else "x86"

    if use_symbols:
        from symbols import analyze as analyze_symbols
        raw = analyze_symbols(ctx.pe, dll_path, ver, progress_callback=progress_callback).text
    else:
        from nosymbol import analyze as analyze_nosymbol
        log_name = f"{ver.to_ini_section()}_{arch}.log"
        log_path = Path.cwd() / "log" / log_name
        raw = analyze_nosymbol(
            ctx.pe, dll_path, ver,
            log_path=log_path,
            progress_callback=progress_callback,
        ).text

    return _normalize_ini_output(raw, arch=arch)


def _normalize_ini_output(raw: str, *, arch: str) -> str:
    sections: dict[str, dict[str, str]] = {}
    section_order: list[str] = []
    current_section: str | None = None

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
        return sections.get(section, {}).get(key)

    def _get_flag(section: str, key: str) -> str:
        value = _get_value(section, key)
        return value if value is not None else "0"

    base_versions = [section for section in section_order if not section.endswith("-SLInit")]

    output_lines: list[str] = []
    for version in base_versions:
        main_section = version
        slinit_section = f"{version}-SLInit"

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

        output_lines.append(f"[{slinit_section}]")

        global_var_keys = (
            "bInitialized", "bServerSku", "lMaxUserSessions", "bAppServerAllowed",
            "bRemoteConnAllowed", "bMultimonAllowed", "ulMaxDebugSessions", "bFUSEnabled",
        )
        global_full_keys = [f"{key}.{arch}" for key in global_var_keys]
        padding_width = max((len(full_key) for full_key in global_full_keys), default=0)

        for full_key in global_full_keys:
            output_lines.append(f"{full_key.ljust(padding_width)}={_get_value(slinit_section, full_key) or ''}")
        output_lines.append("")

    if not base_versions:
        return raw if raw.endswith("\n") else raw + "\n"

    while output_lines and output_lines[-1] == "":
        output_lines.pop()

    return "\n".join(output_lines) + "\n"
