from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import pefile

from .dbghelp import DbgHelp
from .disasm import DisasmContext, decode_linear
from .imports import find_iat_rva
from .patches import def_policy_patch, local_only_patch, single_user_patch
from .pe_image import load_memory_image
from .pdb import ensure_pdb_downloaded, get_pdb_info
from .winver import FileVersion


@dataclass(frozen=True)
class SymbolResult:
    text: str


def _default_sym_path() -> str:
    if os.environ.get("_NT_SYMBOL_PATH"):
        return os.environ["_NT_SYMBOL_PATH"]
    return "cache*;srv*https://msdl.microsoft.com/download/symbols"


def _sl_policy_cp(ctx: DisasmContext, start_rva: int) -> bool:
    # Port of RDPWrapOffsetFinder.cpp::SLPolicyCP (only meaningful for x86).
    if ctx.bitness != 32:
        return False
    start_va = ctx.rva_to_va(start_rva)
    insns = decode_linear(ctx, start_va, 128)
    # iced-x86 exposes enums (Mnemonic/OpKind/Register), not strings.
    from iced_x86 import Mnemonic, OpKind, Register

    for insn in insns:
        if insn.mnemonic == Mnemonic.TEST:
            break
        if insn.mnemonic == Mnemonic.MOV and insn.op1_kind == OpKind.MEMORY:
            if insn.memory_base == Register.EBP and insn.memory_displacement > 0 and insn.op0_kind == OpKind.REGISTER:
                return True
    return False


def analyze(pe: pefile.PE, dll_path: Path, ver: FileVersion) -> SymbolResult:
    mem = load_memory_image(pe)
    bitness = 64 if mem.is_64 else 32
    arch = "x64" if mem.is_64 else "x86"
    ctx = DisasmContext(bitness=bitness, image_base=mem.image_base, image=mem.image)

    size_of_image = int(pe.OPTIONAL_HEADER.SizeOfImage)

    sym_path = _default_sym_path()
    with DbgHelp(search_path=sym_path) as dbg:
        # Make symbol resolution more reliable by pre-downloading the exact PDB
        # and adding it to the search path.
        try:
            pdb = get_pdb_info(pe)
            cache_root = Path(".symcache")
            pdb_path = ensure_pdb_downloaded(pdb, cache_root)
            dbg.add_symbol_path(str(pdb_path.parent))
        except Exception:
            # Best-effort: fallback to SymFromName through normal symbol path.
            pass

        dbg.load_module(dll_path, mem.image_base, size_of_image)
        dbg.set_undname(True)

        # Resolve RVAs needed by the patch logic.
        memset_iat = (
            find_iat_rva(pe, "msvcrt.dll", "memset")
            or find_iat_rva(pe, "ucrtbase.dll", "memset")
            or find_iat_rva(pe, "api-ms-win-crt-string-l1-1-0.dll", "memset")
        )
        if memset_iat is None:
            raise RuntimeError("memset import not found")

        # VerifyVersionInfoW slot name differs across builds; try common import library variants.
        verify_iat = (
            find_iat_rva(pe, "api-ms-win-core-kernel32-legacy-l1-1-1.dll", "VerifyVersionInfoW")
            or find_iat_rva(pe, "kernel32.dll", "VerifyVersionInfoW")
            or find_iat_rva(pe, "kernel32.dll", "__imp_VerifyVersionInfoW")
            or find_iat_rva(pe, "kernel32.dll", "__imp__VerifyVersionInfoW@16")
        )

        # Function entrypoints
        # Prefer the CUtils implementation when present; the helper variant may
        # resolve to a thin wrapper/dispatcher in some builds.
        su_rva = dbg.sym_rva("CUtils::IsSingleSessionPerUser")
        if su_rva is None:
            su_rva = dbg.sym_rva("CSessionArbitrationHelper::IsSingleSessionPerUserEnabled")

        dp_rva = dbg.sym_rva("CDefPolicy::Query")

        # Post Win7 items
        getlic_rva = dbg.sym_rva("CEnforcementCore::GetInstanceOfTSLicense")
        islocal_rva = dbg.sym_rva("CSLQuery::IsLicenseTypeLocalOnly")
        cslinit_rva = dbg.sym_rva("CSLQuery::Initialize")

        lines: list[str] = [f"[{ver.to_ini_section()}]"]

        if su_rva is not None:
            su = single_user_patch(
                ctx,
                start_rva=su_rva,
                memset_target_rva=memset_iat,
                verifyversion_iat_rva=verify_iat,
                direct_call=False,
            )
            if su:
                lines.extend(su.lines)
            else:
                lines.append("ERROR: SingleUserPatch not found")

        if dp_rva is not None:
            dp = def_policy_patch(ctx, start_rva=dp_rva)
            if dp:
                lines.extend(dp.lines)
            else:
                lines.append("ERROR: DefPolicyPatch patten not found")
        else:
            lines.append("ERROR: CDefPolicy_Query not found")

        # Version gating like the C++ tool
        if ver.ms <= 0x00060001:
            return SymbolResult(text="\n".join(lines) + "\n")

        if ver.ms == 0x00060002:
            sl_rva = dbg.sym_rva("SLGetWindowsInformationDWORDWrapper")
            if sl_rva is None:
                lines.append("ERROR: SLGetWindowsInformationDWORDWrapper not found")
                return SymbolResult(text="\n".join(lines) + "\n")

            func = "New_Win8SL_CP" if _sl_policy_cp(ctx, sl_rva) else "New_Win8SL"
            lines.extend(
                [
                    f"SLPolicyInternal.{arch}=1",
                    f"SLPolicyOffset.{arch}={sl_rva:X}",
                    f"SLPolicyFunc.{arch}={func}",
                ]
            )
            return SymbolResult(text="\n".join(lines) + "\n")

        if getlic_rva is None:
            lines.append("ERROR: GetInstanceOfTSLicense not found")
        elif islocal_rva is None:
            lines.append("ERROR: IsLicenseTypeLocalOnly not found")
        else:
            lo = local_only_patch(ctx, start_rva=getlic_rva, target_rva=islocal_rva)
            if lo:
                lines.extend(lo.lines)
            else:
                lines.append("ERROR: LocalOnlyPatch patten not found")

        if cslinit_rva is None:
            lines.append("ERROR: CSLQuery_Initialize not found")
            return SymbolResult(text="\n".join(lines) + "\n")

        lines.extend(
            [
                f"SLInitHook.{arch}=1",
                f"SLInitOffset.{arch}={cslinit_rva:X}",
                f"SLInitFunc.{arch}=New_CSLQuery_Initialize",
                "",
                f"[{ver.to_ini_section()}-SLInit]",
            ]
        )

        # Global vars needed by rdpwrap.ini
        globals_ = [
            ("bServerSku", "CSLQuery::bServerSku"),
            ("bRemoteConnAllowed", "CSLQuery::bRemoteConnAllowed"),
            ("bFUSEnabled", "CSLQuery::bFUSEnabled"),
            ("bAppServerAllowed", "CSLQuery::bAppServerAllowed"),
            ("bMultimonAllowed", "CSLQuery::bMultimonAllowed"),
            ("lMaxUserSessions", "CSLQuery::lMaxUserSessions"),
            ("ulMaxDebugSessions", "CSLQuery::ulMaxDebugSessions"),
            ("bInitialized", "CSLQuery::bInitialized"),
        ]
        for key, sym in globals_:
            rva = dbg.sym_rva(sym)
            if rva is None:
                lines.append(f"ERROR: {key} not found")
            else:
                lines.append(f"{key}.{arch}={rva:X}")

        return SymbolResult(text="\n".join(lines) + "\n")
