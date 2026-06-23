from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import pefile

from dbghelp import DbgHelp
from disasm import DisasmContext, decode_linear
from imports import find_iat_rva
from nosymbol import _log_disasm_context, _fmt_insn
from patches import def_policy_patch, local_only_patch, single_user_patch
from pe_image import load_memory_image
from ms_pdb import ensure_pdb_downloaded, get_pdb_info
from winver import FileVersion
from iced_x86 import Decoder


@dataclass(frozen=True)
class SymbolResult:
    text: str


def _default_sym_path() -> str:
    if os.environ.get("_NT_SYMBOL_PATH"):
        return os.environ["_NT_SYMBOL_PATH"]
    return "cache*;srv*https://msdl.microsoft.com/download/symbols"


def _sl_policy_cp(ctx: DisasmContext, start_rva: int) -> bool:
    if ctx.bitness != 32:
        return False
    start_va = ctx.rva_to_va(start_rva)
    insns = decode_linear(ctx, start_va, 128)
    from iced_x86 import Mnemonic, OpKind, Register

    for insn in insns:
        if insn.mnemonic == Mnemonic.TEST:
            break
        if insn.mnemonic == Mnemonic.MOV and insn.op1_kind == OpKind.MEMORY:
            if insn.memory_base == Register.EBP and insn.memory_displacement > 0 and insn.op0_kind == OpKind.REGISTER:
                return True
    return False


def _log(msg: str, callback: Callable[[str], None] | None) -> None:
    """Emit a timestamped log line — to callback if provided."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted = f"[{ts}] {msg}"
    if callback is not None:
        try:
            callback(formatted)
        except Exception:
            pass


def _log_disasm_ctx_cb(
    ctx: DisasmContext,
    *,
    func_start_rva: int,
    target_rva: int,
    label: str,
    callback: Callable[[str], None] | None,
    decode_len: int = 0x3000,
    before: int = 3,
    after: int = 3,
) -> None:
    """Log disassembly context around target_rva — callback variant of nosymbol._log_disasm_context."""
    try:
        start_va = ctx.rva_to_va(func_start_rva)
        insns = list(Decoder(ctx.bitness, ctx.image[func_start_rva:func_start_rva + decode_len], ip=start_va))
    except Exception as e:
        _log(f"{label}: disasm failed: {e}", callback)
        return

    target_va = ctx.rva_to_va(target_rva)
    idx = next((i for i, x in enumerate(insns) if int(x.ip) == target_va), None)
    if idx is None:
        idx = next((i for i, x in enumerate(insns) if int(x.ip) > target_va), None)
        if idx is None:
            _log(f"{label}: disasm context not available (target not in decode window)", callback)
            return

    lo = max(0, int(idx) - int(before))
    hi = min(len(insns), int(idx) + int(after) + 1)

    _log(f"{label}: disasm context (func RVA 0x{int(func_start_rva):X}, target RVA 0x{int(target_rva):X})", callback)
    for i in range(lo, hi):
        mark = ">" if i == idx else " "
        _log(f"{mark} {_fmt_insn(ctx, insns[i])}", callback)


def analyze(
    pe: pefile.PE,
    dll_path: Path,
    ver: FileVersion,
    progress_callback: Callable[[str], None] | None = None,
) -> SymbolResult:
    _log(f"symbol analyze start: {dll_path}", progress_callback)
    _log(f"version: {ver.to_ini_section()}", progress_callback)

    mem = load_memory_image(pe)
    bitness = 64 if mem.is_64 else 32
    arch = "x64" if mem.is_64 else "x86"
    ctx = DisasmContext(bitness=bitness, image_base=mem.image_base, image=mem.image)
    _log(f"image_base: 0x{mem.image_base:X}, is_64: {mem.is_64}", progress_callback)

    size_of_image = int(pe.OPTIONAL_HEADER.SizeOfImage)

    sym_path = _default_sym_path()
    _log(f"symbol path: {sym_path}", progress_callback)

    with DbgHelp(search_path=sym_path) as dbg:
        # --- 1. PDB download / load ---
        try:
            pdb = get_pdb_info(pe)
            _log(f"PDB info: guid={pdb.guid_hex}, age={pdb.age}, name={pdb.pdb_name}", progress_callback)
            cache_root = Path(".symcache")
            _log("downloading PDB...", progress_callback)
            pdb_path = ensure_pdb_downloaded(pdb, cache_root)
            _log(f"PDB cached: {pdb_path}", progress_callback)
            dbg.add_symbol_path(str(pdb_path.parent))
        except Exception as e:
            _log(f"PDB download/load failed: {e}", progress_callback)
            # Continue — DbgHelp may still resolve via local cache or _NT_SYMBOL_PATH

        _log("loading module symbols...", progress_callback)
        dbg.load_module(dll_path, mem.image_base, size_of_image)
        dbg.set_undname(True)
        _log("module loaded", progress_callback)

        # --- 2. IAT slots ---
        memset_iat = (
            find_iat_rva(pe, "msvcrt.dll", "memset")
            or find_iat_rva(pe, "ucrtbase.dll", "memset")
            or find_iat_rva(pe, "api-ms-win-crt-string-l1-1-0.dll", "memset")
        )
        if memset_iat is None:
            _log("ERROR: memset import not found", progress_callback)
            raise RuntimeError("memset import not found")
        _log(f"IAT RVAs: memset=0x{memset_iat:X}", progress_callback)

        verify_iat = (
            find_iat_rva(pe, "api-ms-win-core-kernel32-legacy-l1-1-1.dll", "VerifyVersionInfoW")
            or find_iat_rva(pe, "kernel32.dll", "VerifyVersionInfoW")
            or find_iat_rva(pe, "kernel32.dll", "__imp_VerifyVersionInfoW")
            or find_iat_rva(pe, "kernel32.dll", "__imp__VerifyVersionInfoW@16")
        )
        _log(f"IAT RVAs: VerifyVersionInfoW={(hex(verify_iat) if verify_iat is not None else None)}", progress_callback)

        # --- 3. Symbol resolution ---
        _log("resolving symbols...", progress_callback)

        su_rva = dbg.sym_rva("CUtils::IsSingleSessionPerUser")
        if su_rva is None:
            su_rva = dbg.sym_rva("CSessionArbitrationHelper::IsSingleSessionPerUserEnabled")
        _log(f"symbol: IsSingleSessionPerUser = {(hex(su_rva) if su_rva is not None else None)}", progress_callback)

        dp_rva = dbg.sym_rva("CDefPolicy::Query")
        _log(f"symbol: CDefPolicy::Query = {(hex(dp_rva) if dp_rva is not None else None)}", progress_callback)

        getlic_rva = dbg.sym_rva("CEnforcementCore::GetInstanceOfTSLicense")
        _log(f"symbol: GetInstanceOfTSLicense = {(hex(getlic_rva) if getlic_rva is not None else None)}", progress_callback)

        islocal_rva = dbg.sym_rva("CSLQuery::IsLicenseTypeLocalOnly")
        _log(f"symbol: IsLicenseTypeLocalOnly = {(hex(islocal_rva) if islocal_rva is not None else None)}", progress_callback)

        cslinit_rva = dbg.sym_rva("CSLQuery::Initialize")
        _log(f"symbol: CSLQuery::Initialize = {(hex(cslinit_rva) if cslinit_rva is not None else None)}", progress_callback)

        lines: list[str] = [f"[{ver.to_ini_section()}]"]

        # --- 4. SingleUserPatch ---
        if su_rva is not None:
            _log(f"SingleUserPatch: scanning func RVA 0x{su_rva:X}", progress_callback)
            su = single_user_patch(
                ctx,
                start_rva=su_rva,
                memset_target_rva=memset_iat,
                verifyversion_iat_rva=verify_iat,
                direct_call=False,
            )
            if su:
                lines.extend(su.lines)
                _log("SingleUserPatch: found", progress_callback)
                for line in su.lines:
                    _log(f"SingleUserPatch: {line}", progress_callback)
                off_line = next((line for line in su.lines if line.startswith(f"SingleUserOffset.{arch}=")), "")
                if off_line:
                    try:
                        off_rva = int(off_line.split("=", 1)[1], 16)
                        _log_disasm_ctx_cb(ctx, func_start_rva=su_rva, target_rva=off_rva,
                                           label="SingleUserPatch", callback=progress_callback,
                                           decode_len=0x800, before=20, after=15)
                    except Exception as e:
                        _log(f"SingleUserPatch: disasm context parse failed: {e}", progress_callback)
            else:
                lines.append("ERROR: SingleUserPatch not found")
                _log("SingleUserPatch: NOT found", progress_callback)
        else:
            _log("SingleUserPatch: skipped (symbol not resolved)", progress_callback)

        # --- 5. DefPolicyPatch ---
        if dp_rva is not None:
            _log(f"DefPolicyPatch: scanning func RVA 0x{dp_rva:X}", progress_callback)
            dp = def_policy_patch(ctx, start_rva=dp_rva)
            if dp:
                lines.extend(dp.lines)
                _log("DefPolicyPatch: found", progress_callback)
                for line in dp.lines:
                    _log(f"DefPolicyPatch: {line}", progress_callback)
                off_line = next((line for line in dp.lines if line.startswith(f"DefPolicyOffset.{arch}=")), "")
                if off_line:
                    try:
                        off_rva = int(off_line.split("=", 1)[1], 16)
                        _log_disasm_ctx_cb(ctx, func_start_rva=dp_rva, target_rva=off_rva,
                                           label="DefPolicyPatch", callback=progress_callback,
                                           decode_len=0x800)
                    except Exception as e:
                        _log(f"DefPolicyPatch: disasm context parse failed: {e}", progress_callback)
            else:
                lines.append("ERROR: DefPolicyPatch patten not found")
                _log("DefPolicyPatch: NOT found", progress_callback)
        else:
            lines.append("ERROR: CDefPolicy_Query not found")
            _log("DefPolicyPatch: skipped (symbol not resolved)", progress_callback)

        # --- 6. Vista / Win7: no SLInit, return early ---
        if ver.ms <= 0x00060001:
            _log("version <= Win7: no SLInit needed, returning early", progress_callback)
            _log("symbol analyze complete", progress_callback)
            return SymbolResult(text="\n".join(lines) + "\n")

        # --- 7. Win8: SL hook ---
        if ver.ms == 0x00060002:
            sl_rva = dbg.sym_rva("SLGetWindowsInformationDWORDWrapper")
            _log(f"symbol: SLGetWindowsInformationDWORDWrapper = {(hex(sl_rva) if sl_rva is not None else None)}", progress_callback)
            if sl_rva is None:
                lines.append("ERROR: SLGetWindowsInformationDWORDWrapper not found")
                _log("ERROR: SLGetWindowsInformationDWORDWrapper not found", progress_callback)
                _log("symbol analyze complete", progress_callback)
                return SymbolResult(text="\n".join(lines) + "\n")

            func = "New_Win8SL_CP" if _sl_policy_cp(ctx, sl_rva) else "New_Win8SL"
            _log(f"SLPolicy: func={func} (CP detection: {func.endswith('_CP')})", progress_callback)
            lines.extend(
                [
                    f"SLPolicyInternal.{arch}=1",
                    f"SLPolicyOffset.{arch}={sl_rva:X}",
                    f"SLPolicyFunc.{arch}={func}",
                ]
            )
            _log("symbol analyze complete", progress_callback)
            return SymbolResult(text="\n".join(lines) + "\n")

        # --- 8. LocalOnlyPatch ---
        if getlic_rva is None:
            lines.append("ERROR: GetInstanceOfTSLicense not found")
            _log("LocalOnlyPatch: skipped (GetInstanceOfTSLicense not resolved)", progress_callback)
        elif islocal_rva is None:
            lines.append("ERROR: IsLicenseTypeLocalOnly not found")
            _log("LocalOnlyPatch: skipped (IsLicenseTypeLocalOnly not resolved)", progress_callback)
        else:
            _log(f"LocalOnlyPatch: scanning func RVA 0x{getlic_rva:X}, target RVA 0x{islocal_rva:X}", progress_callback)
            lo = local_only_patch(ctx, start_rva=getlic_rva, target_rva=islocal_rva)
            if lo:
                lines.extend(lo.lines)
                _log("LocalOnlyPatch: found", progress_callback)
                for line in lo.lines:
                    _log(f"LocalOnlyPatch: {line}", progress_callback)
                off_line = next((line for line in lo.lines if line.startswith(f"LocalOnlyOffset.{arch}=")), "")
                if off_line:
                    try:
                        off_rva = int(off_line.split("=", 1)[1], 16)
                        _log_disasm_ctx_cb(ctx, func_start_rva=getlic_rva, target_rva=off_rva,
                                           label="LocalOnlyPatch", callback=progress_callback,
                                           decode_len=0x1200)
                    except Exception as e:
                        _log(f"LocalOnlyPatch: disasm context parse failed: {e}", progress_callback)
            else:
                lines.append("ERROR: LocalOnlyPatch patten not found")
                _log("LocalOnlyPatch: NOT found", progress_callback)

        # --- 9. SLInitHook ---
        if cslinit_rva is None:
            lines.append("ERROR: CSLQuery_Initialize not found")
            _log("SLInitHook: skipped (CSLQuery::Initialize not resolved)", progress_callback)
            _log("symbol analyze complete", progress_callback)
            return SymbolResult(text="\n".join(lines) + "\n")

        _log(f"SLInitHook: CSLQuery::Initialize RVA 0x{cslinit_rva:X}", progress_callback)
        _log_disasm_ctx_cb(ctx, func_start_rva=cslinit_rva, target_rva=cslinit_rva,
                           label="SLInitHook", callback=progress_callback,
                           decode_len=0x200, before=0, after=10)
        lines.extend(
            [
                f"SLInitHook.{arch}=1",
                f"SLInitOffset.{arch}={cslinit_rva:X}",
                f"SLInitFunc.{arch}=New_CSLQuery_Initialize",
                "",
                f"[{ver.to_ini_section()}-SLInit]",
            ]
        )

        # --- 10. SLInit global variables ---
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
        _log("resolving SLInit global variables...", progress_callback)
        for key, sym in globals_:
            rva = dbg.sym_rva(sym)
            if rva is None:
                lines.append(f"ERROR: {key} not found")
                _log(f"SLInit: {key} = NOT found", progress_callback)
            else:
                lines.append(f"{key}.{arch}={rva:X}")
                _log(f"SLInit: {key} = 0x{rva:X}", progress_callback)

        _log("symbol analyze complete", progress_callback)
        return SymbolResult(text="\n".join(lines) + "\n")
