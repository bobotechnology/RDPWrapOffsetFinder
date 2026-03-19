from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from datetime import datetime

import pefile
from iced_x86 import Decoder, Mnemonic, OpKind, Register

from .disasm import DisasmContext
from .exception_table import backtrace_x64, parse_exception_directory_x64
from .imports import find_iat_rva
from .patches import PatchResult, def_policy_patch, local_only_patch, single_user_patch
from .pe_image import load_memory_image
from .winver import FileVersion


def _find_section(pe: pefile.PE, name: bytes) -> pefile.SectionStructure | None:
    for sec in pe.sections:
        if sec.Name.rstrip(b"\x00") == name:
            return sec
    return None


def _pattern_match_in_section(image: bytes, sec: pefile.SectionStructure, pat: bytes) -> int | None:
    try:
        raw = sec.get_data()
    except Exception:
        raw = b""

    idx = -1
    if pat:
        if b"\x00" not in pat:
            idx = raw.find(pat + b"\x00")
        else:
            idx = raw.find(pat + b"\x00\x00")
            if idx < 0:
                idx = raw.find(pat)

    if idx < 0:
        idx = raw.find(pat)
    if idx >= 0:
        return int(sec.VirtualAddress) + idx

    start = int(sec.VirtualAddress)
    size = int(getattr(sec, "Misc_VirtualSize", 0) or 0)
    if size <= 0:
        size = int(sec.SizeOfRawData)
    hay = image[start:start + size]
    idx = hay.find(pat)
    if idx < 0:
        return None
    return start + idx


def _xref_lea_rip(image: bytes, image_base: int, bitness: int, func_rva: int, func_len: int, target_rva: int) -> int | None:
    target_va = image_base + target_rva
    start_va = image_base + func_rva
    code = image[func_rva:func_rva + func_len]
    dec = Decoder(bitness, code, ip=start_va)
    for insn in dec:
        if insn.mnemonic == Mnemonic.LEA:
            if insn.op0_kind != OpKind.REGISTER or insn.op1_kind != OpKind.MEMORY:
                continue
            if insn.memory_base != Register.RIP:
                continue
            if insn.is_ip_rel_memory_operand and insn.ip_rel_memory_address == target_va:
                return int(insn.next_ip - image_base)

        if insn.mnemonic == Mnemonic.MOV:
            if insn.op0_kind == OpKind.REGISTER and insn.op1_kind in (OpKind.IMMEDIATE64, OpKind.IMMEDIATE32):
                imm = int(insn.immediate64 if insn.op1_kind == OpKind.IMMEDIATE64 else insn.immediate32)
                if imm == target_va:
                    return int(insn.next_ip - image_base)
    return None


@dataclass(frozen=True)
class NoSymbolResult:
    text: str


def _log_append(log: list[str], msg: str) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log.append(f"[{ts}] {msg}")


def _write_log(path: str | Path | None, lines: list[str]) -> None:
    if not path:
        return
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _fmt_insn(ctx: DisasmContext, insn) -> str:
    rva = int(insn.ip - ctx.image_base)
    b = ctx.image[rva:rva + insn.len]
    bhex = " ".join(f"{x:02X}" for x in b)
    return f"{rva:08X}  {bhex:<24}  {insn}"


def _log_disasm_context(
    log: list[str],
    ctx: DisasmContext,
    *,
    func_start_rva: int,
    target_rva: int,
    label: str,
    decode_len: int = 0x3000,
    before: int = 3,
    after: int = 3,
) -> None:
    try:
        start_va = ctx.rva_to_va(int(func_start_rva))
        insns = list(Decoder(ctx.bitness, ctx.image[func_start_rva:func_start_rva + decode_len], ip=start_va))
    except Exception as e:
        _log_append(log, f"{label}: disasm failed: {e}")
        return

    target_va = ctx.rva_to_va(int(target_rva))
    idx = next((i for i, x in enumerate(insns) if int(x.ip) == target_va), None)
    if idx is None:
        idx = next((i for i, x in enumerate(insns) if int(x.ip) > target_va), None)
        if idx is None:
            _log_append(log, f"{label}: disasm context not available (target not in decode window)")
            return

    lo = max(0, int(idx) - int(before))
    hi = min(len(insns), int(idx) + int(after) + 1)

    _log_append(log, f"{label}: disasm context (func RVA 0x{int(func_start_rva):X}, target RVA 0x{int(target_rva):X})")
    for i in range(lo, hi):
        mark = ">" if i == idx else " "
        _log_append(log, f"{mark} {_fmt_insn(ctx, insns[i])}")


def _scan_text_functions_x86(pe: pefile.PE, image: bytes, image_base: int) -> list[tuple[int, int]]:
    text_sec = _find_section(pe, b".text")
    if text_sec is None:
        for sec in pe.sections:
            if sec.Characteristics & 0x20000000:
                text_sec = sec
                break
    if text_sec is None:
        return []

    sec_rva = int(text_sec.VirtualAddress)
    sec_size = int(getattr(text_sec, "Misc_VirtualSize", 0) or text_sec.SizeOfRawData)
    data = image[sec_rva:sec_rva + sec_size]

    starts: list[int] = []
    i = 0
    while i < len(data) - 3:
        if data[i] == 0x55 and data[i + 1] == 0x8B and data[i + 2] == 0xEC:
            starts.append(sec_rva + i)
            i += 3
            continue
        if data[i] == 0x8B and data[i + 1] == 0xFF and data[i + 2] == 0x55 and i + 3 < len(data) and data[i + 3] == 0x8B and i + 4 < len(data) and data[i + 4] == 0xEC:
            starts.append(sec_rva + i)
            i += 5
            continue
        i += 1

    if not starts:
        return []

    funcs: list[tuple[int, int]] = []
    for j, begin in enumerate(starts):
        end = starts[j + 1] if j + 1 < len(starts) else sec_rva + sec_size
        funcs.append((begin, end))
    return funcs


def _xref_imm32_x86(image: bytes, image_base: int, func_rva: int, func_len: int, target_rva: int) -> int | None:
    target_va = image_base + target_rva
    start_va = image_base + func_rva
    code = image[func_rva:func_rva + func_len]
    dec = Decoder(32, code, ip=start_va)
    for insn in dec:
        # PUSH imm32
        if insn.mnemonic == Mnemonic.PUSH and insn.op0_kind == OpKind.IMMEDIATE32:
            if int(insn.immediate32) == target_va:
                return int(insn.next_ip - image_base)
        # MOV reg, imm32  (covers MOV ECX, imm32 and others)
        if insn.mnemonic == Mnemonic.MOV:
            if insn.op0_kind == OpKind.REGISTER and insn.op1_kind == OpKind.IMMEDIATE32:
                if int(insn.immediate32) == target_va:
                    return int(insn.next_ip - image_base)
    return None


def _find_func_start_x86(image: bytes, image_base: int, xref_rva: int, text_funcs: list[tuple[int, int]]) -> tuple[int, int] | None:
    """Return (begin_rva, end_rva) of the function containing xref_rva."""
    for begin, end in text_funcs:
        if begin <= xref_rva < end:
            return (begin, end)
    return None


def _resolve_jmp_stub_x86(image: bytes, image_base: int, func_rva: int, text_funcs: list[tuple[int, int]], max_depth: int = 3) -> int:
    """If func_rva is a small stub that ends with JMP rel32, follow the JMP to find
    the real function start. Returns the resolved function RVA (may be the same as
    func_rva if it's not a stub).

    This handles the MSVC pattern where a small error-reporting stub jumps into the
    middle of the real function body, and we need to find the function that contains
    that target address.
    """
    for _ in range(max_depth):
        # Find the function boundaries
        func_info = _find_func_start_x86(image, image_base, func_rva, text_funcs)
        if func_info is None:
            break
        begin, end = func_info
        func_len = end - begin
        # Only follow stubs (small functions, < 64 bytes)
        if func_len > 64:
            break
        start_va = image_base + begin
        code = image[begin:begin + func_len]
        dec = Decoder(32, code, ip=start_va)
        jmp_target: int | None = None
        for insn in dec:
            if insn.mnemonic == Mnemonic.JMP and insn.op0_kind in (OpKind.NEAR_BRANCH32, OpKind.NEAR_BRANCH16):
                jmp_target = int(insn.near_branch_target - image_base)
                break
        if jmp_target is None:
            break
        # Find the function that contains the JMP target
        target_func = _find_func_start_x86(image, image_base, jmp_target, text_funcs)
        if target_func is None:
            break
        func_rva = target_func[0]
    return func_rva


def _analyze_x86(
    pe: pefile.PE,
    dll_path: Path,
    ver: FileVersion,
    mem,
    ctx: DisasmContext,
    log: list[str],
    log_path,
) -> NoSymbolResult:
    """x86-specific nosymbol analysis."""

    arch = "x86"
    bitness = 32

    # For x86, strings may be in .rdata or .text (some builds embed them inline).
    # Search all read-only data sections.

    def _find_str(pat: bytes) -> int | None:
        for sec in pe.sections:
            rva = _pattern_match_in_section(mem.image, sec, pat)
            if rva is not None:
                return rva
        return None

    # ASCII strings
    q = _find_str(b"CDefPolicy::Query")
    local_only = _find_str(b"CSLQuery::IsTerminalTypeLocalOnly")
    single_enabled = _find_str(b"CSessionArbitrationHelper::IsSingleSessionPerUserEnabled")
    if single_enabled is None:
        single_enabled = _find_str(b"IsSingleSessionPerUserEnabled")
    inst_license = _find_str(b"CEnforcementCore::GetInstanceOfTSLicense ")
    if inst_license is None:
        inst_license = _find_str(b"CEnforcementCore::GetInstanceOfTSLicense")
    single_user = _find_str(b"CUtils::IsSingleSessionPerUser")
    if single_user is None:
        single_user = _find_str(b"IsSingleSessionPerUser")

    _log_append(log, f"string RVAs: CDefPolicy::Query={q and hex(q)}")
    _log_append(log, f"string RVAs: CSLQuery::IsTerminalTypeLocalOnly={local_only and hex(local_only)}")
    _log_append(log, f"string RVAs: IsSingleSessionPerUserEnabled={single_enabled and hex(single_enabled)}")
    _log_append(log, f"string RVAs: GetInstanceOfTSLicense={inst_license and hex(inst_license)}")
    _log_append(log, f"string RVAs: IsSingleSessionPerUser={single_user and hex(single_user)}")

    # Wide strings for SLInit scanning
    def _find_wide(s: str) -> int | None:
        return _find_str(s.encode("utf-16le"))

    allow_remote_str = _find_wide("TerminalServices-RemoteConnectionManager-AllowRemoteConnections")

    _log_append(log, f"string RVAs: AllowRemoteConnections={allow_remote_str and hex(allow_remote_str)}")

    if None in (q, local_only, single_enabled, inst_license, single_user, allow_remote_str):
        missing_strs = [n for n, v in [
            ("CDefPolicy::Query", q),
            ("IsTerminalTypeLocalOnly", local_only),
            ("IsSingleSessionPerUserEnabled", single_enabled),
            ("GetInstanceOfTSLicense", inst_license),
            ("IsSingleSessionPerUser", single_user),
            ("AllowRemoteConnections", allow_remote_str),
        ] if v is None]
        _log_append(log, f"ERROR: required strings missing: {', '.join(missing_strs)}")
        _write_log(log_path, log)
        raise RuntimeError(f"Failed to locate required strings (x86 nosymbol): {', '.join(missing_strs)}")

    # Import/IAT RVAs
    memset_iat = (
        find_iat_rva(pe, "msvcrt.dll", "memset")
        or find_iat_rva(pe, "ucrtbase.dll", "memset")
        or find_iat_rva(pe, "api-ms-win-crt-string-l1-1-0.dll", "memset")
    )
    if memset_iat is None:
        _log_append(log, "ERROR: memset import not found")
        _write_log(log_path, log)
        raise RuntimeError("memset import not found (x86)")

    _log_append(log, f"IAT RVAs: memset=0x{memset_iat:X}")

    verify_iat = find_iat_rva(pe, "kernel32.dll", "VerifyVersionInfoW")
    if verify_iat is None:
        verify_iat = find_iat_rva(pe, "api-ms-win-core-kernel32-legacy-l1-1-1.dll", "VerifyVersionInfoW")
    _log_append(log, f"IAT RVAs: VerifyVersionInfoW={(hex(verify_iat) if verify_iat is not None else None)}")

    # Enumerate x86 functions by scanning for prologues in .text
    text_funcs = _scan_text_functions_x86(pe, mem.image, mem.image_base)
    _log_append(log, f"x86 text functions found: {len(text_funcs)}")

    if not text_funcs:
        _log_append(log, "ERROR: no x86 functions found in .text")
        _write_log(log_path, log)
        raise RuntimeError("No x86 functions found in .text section")

    # Find functions by scanning for xrefs to key strings
    addrs: dict[str, int] = {}
    func_sizes: dict[str, int] = {}
    allow_remote_xref: int | None = None

    # CDefPolicy_Query is special: the string "CDefPolicy::Query" may be embedded in
    # .text and referenced only from an error stub, not from the real function body.
    # Instead, find CDefPolicy::Query by scanning for the CMP [ecx+320h] or CMP [ecx+63Ch]
    # pattern that is the actual patch site.
    targets_required = {
        "GetInstanceOfTSLicense": inst_license,
        "IsSingleSessionPerUserEnabled": single_enabled,
        "IsLicenseTypeLocalOnly": local_only,
        "CSLQuery_Initialize": allow_remote_str,
    }
    targets_optional = {
        "IsSingleSessionPerUser": single_user,
    }
    targets = dict(targets_required)
    targets.update(targets_optional)

    for begin_rva, end_rva in text_funcs:
        func_len = end_rva - begin_rva
        if func_len <= 0:
            continue
        for key, target_rva in list(targets.items()):
            if key in addrs:
                continue
            xref = _xref_imm32_x86(mem.image, mem.image_base, begin_rva, func_len, target_rva)
            if xref is None:
                continue
            addrs[key] = begin_rva
            func_sizes[key] = func_len
            _log_append(log, f"xref found: {key} -> function RVA 0x{begin_rva:X} (size 0x{func_len:X})")
            if key == "CSLQuery_Initialize":
                allow_remote_xref = xref
        if len(addrs) == len(targets):
            break

    missing = [k for k in targets_required if k not in addrs]
    if missing:
        _log_append(log, f"ERROR: missing function xrefs: {', '.join(missing)}")
        _write_log(log_path, log)
        raise RuntimeError(f"Failed to find x86 function xrefs: {', '.join(missing)}")
    if allow_remote_xref is None:
        _log_append(log, "ERROR: CSLQuery::Initialize not located")
        _write_log(log_path, log)
        raise RuntimeError("Failed to locate CSLQuery::Initialize (x86)")

    # Find CDefPolicy::Query by scanning for the CMP [ecx+320h] or CMP [ecx+63Ch] pattern.
    # This is more reliable than string xref for x86 since the string may be in .text.
    def _find_def_policy_query_x86() -> int | None:
        """Find CDefPolicy::Query by scanning for the characteristic CMP pattern.

        CDefPolicy::Query uses ECX as the 'this' pointer (thiscall convention),
        so we look for CMP reg, [ecx+320h] or CMP [ecx+63Ch], reg.
        We also verify that def_policy_patch succeeds on the candidate.
        """
        candidates: list[int] = []
        for begin_rva, end_rva in text_funcs:
            func_len = end_rva - begin_rva
            if func_len <= 0 or func_len > 0x800:
                continue
            start_va = mem.image_base + begin_rva
            code = mem.image[begin_rva:begin_rva + func_len]
            dec = Decoder(32, code, ip=start_va)
            for insn in dec:
                if insn.mnemonic != Mnemonic.CMP:
                    continue
                # CMP reg, [ecx+320h]  (thiscall: ECX is 'this')
                if (
                    insn.op1_kind == OpKind.MEMORY
                    and insn.memory_base == Register.ECX
                    and insn.memory_displacement in (0x320, 0x63C)
                    and insn.op0_kind == OpKind.REGISTER
                ):
                    candidates.append(begin_rva)
                    break
                # CMP [ecx+63Ch], reg
                if (
                    insn.op0_kind == OpKind.MEMORY
                    and insn.memory_base == Register.ECX
                    and insn.memory_displacement in (0x320, 0x63C)
                    and insn.op1_kind == OpKind.REGISTER
                ):
                    candidates.append(begin_rva)
                    break

        # Verify each candidate with def_policy_patch
        for rva in candidates:
            result = def_policy_patch(ctx, start_rva=rva)
            if result is not None:
                return rva
        # If none verified, return first candidate anyway
        return candidates[0] if candidates else None

    dp_query_rva = _find_def_policy_query_x86()
    if dp_query_rva is not None:
        addrs["CDefPolicy_Query"] = dp_query_rva
        _log_append(log, f"CDefPolicy_Query: found via CMP pattern at RVA 0x{dp_query_rva:X}")
    else:
        # Fallback: use string xref (may be wrong but better than nothing)
        for begin_rva, end_rva in text_funcs:
            func_len = end_rva - begin_rva
            if func_len <= 0:
                continue
            xref = _xref_imm32_x86(mem.image, mem.image_base, begin_rva, func_len, q)
            if xref is not None:
                resolved = _resolve_jmp_stub_x86(mem.image, mem.image_base, begin_rva, text_funcs)
                addrs["CDefPolicy_Query"] = resolved
                _log_append(log, f"CDefPolicy_Query: found via string xref fallback at RVA 0x{resolved:X}")
                break
        if "CDefPolicy_Query" not in addrs:
            _log_append(log, "ERROR: CDefPolicy_Query not found")
            _write_log(log_path, log)
            raise RuntimeError("Failed to find CDefPolicy_Query (x86)")

    lines: list[str] = []
    lines.append(f"[{ver.to_ini_section()}]")

    # SingleUserPatch
    su_start = addrs.get("IsSingleSessionPerUserEnabled") or addrs.get("IsSingleSessionPerUser")
    su_func_start: int | None = su_start
    su = None
    if su_start is not None:
        _log_append(log, f"SingleUser scan start RVA: 0x{su_start:X}")
        su = single_user_patch(
            ctx,
            start_rva=su_start,
            memset_target_rva=memset_iat,
            verifyversion_iat_rva=verify_iat,
            direct_call=False,
        )

    # Fallback: scan all functions for VerifyVersionInfoW call
    if su is None and verify_iat is not None:
        best: PatchResult | None = None
        best_func_start: int | None = None
        for begin_rva, end_rva in text_funcs:
            res = single_user_patch(
                ctx,
                start_rva=begin_rva,
                memset_target_rva=memset_iat,
                verifyversion_iat_rva=verify_iat,
                direct_call=False,
            )
            if res is None:
                continue
            code_line = next((line for line in res.lines if line.startswith(f"SingleUserCode.{arch}=")), "")
            if "pop_eax_add_esp_12_nop_" in code_line:
                best = res
                best_func_start = begin_rva
                break
            if best is None:
                best = res
                best_func_start = begin_rva
        su = best
        if best_func_start is not None:
            su_func_start = best_func_start

    if su:
        lines.extend(su.lines)
        _log_append(log, "SingleUserPatch: found")
        off_line = next((line for line in su.lines if line.startswith(f"SingleUserOffset.{arch}=")), "")
        code_line = next((line for line in su.lines if line.startswith(f"SingleUserCode.{arch}=")), "")
        if off_line:
            _log_append(log, f"SingleUserPatch: {off_line}")
        if code_line:
            _log_append(log, f"SingleUserPatch: {code_line}")
        if off_line and su_func_start is not None:
            try:
                off_rva = int(off_line.split("=", 1)[1], 16)
                _log_disasm_context(log, ctx, func_start_rva=su_func_start, target_rva=off_rva, label="SingleUserPatch")
            except Exception as e:
                _log_append(log, f"SingleUserPatch: disasm context parse failed: {e}")
    else:
        lines.append("ERROR: SingleUserPatch not found")
        _log_append(log, "SingleUserPatch: NOT found")

    # DefPolicyPatch
    # The xref scan may find a small error-reporting stub that jumps into the real
    # CDefPolicy::Query body. Resolve any such stub before calling def_policy_patch.
    dp_func_rva = _resolve_jmp_stub_x86(mem.image, mem.image_base, addrs["CDefPolicy_Query"], text_funcs)
    _log_append(log, f"DefPolicyPatch: resolved func RVA 0x{dp_func_rva:X} (from xref RVA 0x{addrs['CDefPolicy_Query']:X})")
    dp = def_policy_patch(ctx, start_rva=dp_func_rva)
    if dp:
        lines.extend(dp.lines)
        _log_append(log, "DefPolicyPatch: found")
        try:
            off_line = next((line for line in dp.lines if line.startswith(f"DefPolicyOffset.{arch}=")), "")
            if off_line:
                off_rva = int(off_line.split("=", 1)[1], 16)
                _log_disasm_context(
                    log, ctx,
                    func_start_rva=dp_func_rva,
                    target_rva=off_rva,
                    label="DefPolicyPatch",
                    decode_len=0x800,
                )
        except Exception as e:
            _log_append(log, f"DefPolicyPatch: disasm context failed: {e}")
    else:
        lines.append("ERROR: DefPolicyPatch patten not found")
        _log_append(log, "DefPolicyPatch: NOT found")

    # Version gating
    if ver.ms <= 0x00060001:
        _write_log(log_path, log)
        return NoSymbolResult(text="\n".join(lines) + "\n")

    if ver.ms == 0x00060002:
        # Win8: SLPolicy hook is the first CALL after the allow-remote xref
        start_va = mem.image_base + allow_remote_xref
        data = mem.image[allow_remote_xref:allow_remote_xref + 0x400]
        dec = Decoder(bitness, data, ip=start_va)
        for insn in dec:
            if insn.mnemonic == Mnemonic.CALL and insn.op0_kind in (OpKind.NEAR_BRANCH32, OpKind.NEAR_BRANCH64):
                off = int(insn.near_branch_target - mem.image_base)
                lines.append(f"SLPolicyInternal.{arch}=1")
                lines.append(f"SLPolicyOffset.{arch}={off:X}")
                lines.append(f"SLPolicyFunc.{arch}=New_Win8SL")
                _write_log(log_path, log)
                return NoSymbolResult(text="\n".join(lines) + "\n")
        lines.append("ERROR: SLGetWindowsInformationDWORDWrapper not found")
        _write_log(log_path, log)
        return NoSymbolResult(text="\n".join(lines) + "\n")

    # LocalOnlyPatch
    lo = local_only_patch(
        ctx,
        start_rva=addrs["GetInstanceOfTSLicense"],
        target_rva=addrs["IsLicenseTypeLocalOnly"],
    )
    if lo:
        lines.extend(lo.lines)
        _log_append(log, "LocalOnlyPatch: found")
        try:
            off_line = next((line for line in lo.lines if line.startswith(f"LocalOnlyOffset.{arch}=")), "")
            if off_line:
                off_rva = int(off_line.split("=", 1)[1], 16)
                _log_disasm_context(
                    log, ctx,
                    func_start_rva=addrs["GetInstanceOfTSLicense"],
                    target_rva=off_rva,
                    label="LocalOnlyPatch",
                    decode_len=0x1200,
                )
        except Exception as e:
            _log_append(log, f"LocalOnlyPatch: disasm context failed: {e}")
    else:
        lines.append("ERROR: LocalOnlyPatch patten not found")
        _log_append(log, "LocalOnlyPatch: NOT found")

    # SLInit hook
    csl_init_rva = addrs["CSLQuery_Initialize"]
    csl_init_len = func_sizes.get("CSLQuery_Initialize", 0x11000)
    _log_append(log, f"SLInitHook: CSLQuery::Initialize RVA 0x{csl_init_rva:X}")
    _log_disasm_context(
        log, ctx,
        func_start_rva=csl_init_rva,
        target_rva=csl_init_rva,
        label="SLInitHook",
        decode_len=0x200,
        before=0,
        after=10,
    )
    lines.append(f"SLInitHook.{arch}=1")
    lines.append(f"SLInitOffset.{arch}={csl_init_rva:X}")
    lines.append(f"SLInitFunc.{arch}=New_CSLQuery_Initialize")

    lines.append("")
    lines.append(f"[{ver.to_ini_section()}-SLInit]")

    # Map policy wide strings -> var keys (same as x64)
    keys = {
        "TerminalServices-RemoteConnectionManager-AllowRemoteConnections": "bRemoteConnAllowed",
        "TerminalServices-RemoteConnectionManager-AllowMultipleSessions": "bFUSEnabled",
        "TerminalServices-RemoteConnectionManager-AllowAppServerMode": "bAppServerAllowed",
        "TerminalServices-RemoteConnectionManager-AllowMultimon": "bMultimonAllowed",
        "TerminalServices-RemoteConnectionManager-MaxUserSessions": "lMaxUserSessions",
        "TerminalServices-RemoteConnectionManager-ce0ad219-4670-4988-98fb-89b14c2f072b-MaxSessions": "ulMaxDebugSessions",
    }
    str_rvas: dict[str, int] = {}
    for s in keys:
        rva = _find_str(s.encode("utf-16le"))
        if rva is not None:
            str_rvas[s] = rva

    # Scan CSLQuery::Initialize to recover global var RVAs.
    # In x86, globals are accessed via absolute addresses:
    #   MOV [abs_addr], EAX   -> memory_base == NONE, memory_segment == DS
    #   MOV ECX, imm32        -> selects which policy string is being queried
    var_rvas: dict[str, int] = {"bServerSku": 0, "bInitialized": 0}
    for v in keys.values():
        var_rvas[v] = 0

    current = "bServerSku"
    scan_len = csl_init_len if csl_init_len > 0 else 0x11000
    start_va = mem.image_base + csl_init_rva
    code = mem.image[csl_init_rva:csl_init_rva + scan_len]
    dec = Decoder(bitness, code, ip=start_va)

    for insn in dec:
        # x86: MOV [abs_addr], EAX  (no base register, DS segment)
        # iced-x86: memory_base == NONE (0), memory_index == NONE, memory_segment == DS
        if (
            var_rvas.get(current, 0) == 0
            and insn.mnemonic == Mnemonic.MOV
            and insn.op0_kind == OpKind.MEMORY
            and insn.memory_base == Register.NONE
            and insn.memory_index == Register.NONE
            and insn.op1_kind == OpKind.REGISTER
            and insn.op1_register == Register.EAX
        ):
            abs_va = insn.memory_displacement
            if abs_va > mem.image_base:
                rva = abs_va - mem.image_base
                var_rvas[current] = rva
                _log_append(log, f"SLInitScan: {current} RVA 0x{rva:X} via {_fmt_insn(ctx, insn)}")
            continue

        # x86: MOV ECX, imm32  -> selects which policy string is being queried
        if (
            insn.mnemonic == Mnemonic.MOV
            and insn.op0_kind == OpKind.REGISTER
            and insn.op0_register == Register.ECX
            and insn.op1_kind == OpKind.IMMEDIATE32
        ):
            imm_va = int(insn.immediate32)
            imm_rva = imm_va - mem.image_base
            for s, key in keys.items():
                rva = str_rvas.get(s)
                if rva is not None and imm_rva == rva:
                    current = key
                    _log_append(log, f"SLInitScan: policy '{key}' selected via {_fmt_insn(ctx, insn)}")
                    break
            continue

        # x86: MOV [abs_addr], 1  -> bInitialized
        if (
            insn.mnemonic == Mnemonic.MOV
            and insn.op0_kind == OpKind.MEMORY
            and insn.memory_base == Register.NONE
            and insn.memory_index == Register.NONE
            and insn.op1_kind in (OpKind.IMMEDIATE8, OpKind.IMMEDIATE32)
        ):
            imm = insn.immediate8 if insn.op1_kind == OpKind.IMMEDIATE8 else insn.immediate32
            if imm == 1:
                abs_va = insn.memory_displacement
                if abs_va > mem.image_base:
                    rva = abs_va - mem.image_base
                    var_rvas["bInitialized"] = rva
                    _log_append(log, f"SLInitScan: bInitialized RVA 0x{rva:X} via {_fmt_insn(ctx, insn)}")
                break

    for k in ("bServerSku",) + tuple(keys.values()) + ("bInitialized",):
        v = var_rvas.get(k, 0)
        if v:
            lines.append(f"{k}.{arch}={v:X}")
        else:
            lines.append(f"ERROR: {k} not found")

    _write_log(log_path, log)
    return NoSymbolResult(text="\n".join(lines) + "\n")


def analyze(
    pe: pefile.PE,
    dll_path: Path,
    ver: FileVersion,
    *,
    log_path: str | Path | None = None,
) -> NoSymbolResult:
    log: list[str] = []
    _log_append(log, f"nosymbol analyze start: {dll_path}")
    _log_append(log, f"version: {ver.to_ini_section()}")
    mem = load_memory_image(pe)
    _log_append(log, f"image_base: 0x{mem.image_base:X}, is_64: {mem.is_64}")
    bitness = 64 if mem.is_64 else 32
    arch = "x64" if mem.is_64 else "x86"
    ctx = DisasmContext(bitness=bitness, image_base=mem.image_base, image=mem.image)

    if not mem.is_64:
        return _analyze_x86(pe, dll_path, ver, mem, ctx, log, log_path)

    rdata_sec = _find_section(pe, b".rdata") or pe.sections[0]
    sec_name = rdata_sec.Name.rstrip(b"\x00").decode(errors="ignore")
    _log_append(log, f"scan section: {sec_name} @ RVA 0x{int(rdata_sec.VirtualAddress):X}")

    # ASCII strings
    q = _pattern_match_in_section(mem.image, rdata_sec, b"CDefPolicy::Query")
    local_only = _pattern_match_in_section(mem.image, rdata_sec, b"CSLQuery::IsTerminalTypeLocalOnly")
    # Some builds only include the shortened suffix string in .rdata.
    single_enabled = _pattern_match_in_section(mem.image, rdata_sec, b"CSessionArbitrationHelper::IsSingleSessionPerUserEnabled")
    if single_enabled is None:
        single_enabled = _pattern_match_in_section(mem.image, rdata_sec, b"CSessionArbitrationHelper::IsSingleSessionPerUserEnabled".split(b"::")[-1])
    # Some builds include a trailing space in the string table.
    inst_license = _pattern_match_in_section(mem.image, rdata_sec, b"CEnforcementCore::GetInstanceOfTSLicense ")
    if inst_license is None:
        inst_license = _pattern_match_in_section(mem.image, rdata_sec, b"CEnforcementCore::GetInstanceOfTSLicense")
    # Prefer full name if present
    single_user = _pattern_match_in_section(mem.image, rdata_sec, b"CUtils::IsSingleSessionPerUser")
    if single_user is None:
        single_user = _pattern_match_in_section(mem.image, rdata_sec, b"IsSingleSessionPerUser")

    _log_append(log, f"rdata string RVAs: CDefPolicy::Query={q and hex(q)}")
    _log_append(log, f"rdata string RVAs: CSLQuery::IsTerminalTypeLocalOnly={local_only and hex(local_only)}")
    _log_append(log, f"rdata string RVAs: IsSingleSessionPerUserEnabled={single_enabled and hex(single_enabled)}")
    _log_append(log, f"rdata string RVAs: GetInstanceOfTSLicense={inst_license and hex(inst_license)}")
    _log_append(log, f"rdata string RVAs: IsSingleSessionPerUser={single_user and hex(single_user)}")

    # Wide strings used by SLInit scanning
    allow_remote = _pattern_match_in_section(
        mem.image, rdata_sec, "TerminalServices-RemoteConnectionManager-AllowRemoteConnections".encode("utf-16le")
    )

    if None in (q, local_only, single_enabled, inst_license, single_user, allow_remote):
        _log_append(log, "ERROR: required .rdata strings missing")
        _write_log(log_path, log)
        raise RuntimeError("Failed to locate required .rdata strings (nosymbol mode)")

    # Import/IAT RVAs
    memset_iat = (
        find_iat_rva(pe, "msvcrt.dll", "memset")
        or find_iat_rva(pe, "ucrtbase.dll", "memset")
        or find_iat_rva(pe, "api-ms-win-crt-string-l1-1-0.dll", "memset")
    )
    if memset_iat is None:
        _log_append(log, "ERROR: memset import not found")
        _write_log(log_path, log)
        raise RuntimeError("memset import not found")

    _log_append(log, f"IAT RVAs: memset=0x{memset_iat:X}")

    verify_iat = find_iat_rva(pe, "api-ms-win-core-kernel32-legacy-l1-1-1.dll", "VerifyVersionInfoW")
    if verify_iat is None:
        verify_iat = find_iat_rva(pe, "kernel32.dll", "VerifyVersionInfoW")
    _log_append(log, f"IAT RVAs: VerifyVersionInfoW={(hex(verify_iat) if verify_iat is not None else None)}")

    # Discover function RVAs by scanning exception directory for LEA xrefs.
    runtime_funcs = parse_exception_directory_x64(pe, mem.image)
    if not runtime_funcs:
        _log_append(log, "ERROR: no exception directory")
        _write_log(log_path, log)
        raise RuntimeError("No exception directory found (x64)")
    _log_append(log, f"runtime functions (exception dir): {len(runtime_funcs)}")

    addrs: dict[str, int] = {}
    csl_init_len: int | None = None
    allow_remote_xref: int | None = None

    # We prefer finding the CUtils::IsSingleSessionPerUser implementation, but some
    # builds don't reference the short string in a way we can recover via exception
    # directory scanning. Treat it as optional and fall back to the helper string.
    targets_required = {
        "CDefPolicy_Query": q,
        "GetInstanceOfTSLicense": inst_license,
        "IsSingleSessionPerUserEnabled": single_enabled,
        "IsLicenseTypeLocalOnly": local_only,
        "CSLQuery_Initialize": allow_remote,
    }
    targets_optional = {
        "IsSingleSessionPerUser": single_user,
    }
    targets = dict(targets_required)
    targets.update(targets_optional)

    for rf in runtime_funcs:
        func_len = int(rf.end_rva - rf.begin_rva)
        if func_len <= 0:
            continue
        for key, target in list(targets.items()):
            if key in addrs:
                continue
            xref = _xref_lea_rip(mem.image, mem.image_base, bitness, rf.begin_rva, func_len, target)
            if not xref:
                continue
            top = backtrace_x64(mem.image, rf)
            addrs[key] = int(top.begin_rva)
            _log_append(log, f"xref found: {key} -> function RVA 0x{addrs[key]:X}")
            if key == "CSLQuery_Initialize":
                csl_init_len = int(top.end_rva - top.begin_rva)
                allow_remote_xref = int(xref)
        if len(addrs) == len(targets):
            break

    missing = [k for k in targets_required if k not in addrs]
    if missing:
        _log_append(log, f"ERROR: missing function xrefs: {', '.join(missing)}")
        _write_log(log_path, log)
        raise RuntimeError(f"Failed to find function xrefs: {', '.join(missing)}")
    if csl_init_len is None or allow_remote_xref is None:
        _log_append(log, "ERROR: CSLQuery::Initialize not located")
        _write_log(log_path, log)
        raise RuntimeError("Failed to locate CSLQuery::Initialize")

    lines: list[str] = []
    lines.append(f"[{ver.to_ini_section()}]")

    # Patches
    # Prefer the IsSingleSessionPerUserEnabled implementation. The CUtils version
    # tends to have CMP instructions that check version info fields, leading to
    # false positives.
    # However, IsSingleSessionPerUserEnabled may not contain VerifyVersionInfoW call
    # in some builds. In that case, prefer IsSingleSessionPerUser which always has
    # the VerifyVersionInfoW call.
    su_start: int | None = None
    su_func_start: int | None = None
    su: PatchResult | None = None

    # Try IsSingleSessionPerUserEnabled first
    if addrs.get("IsSingleSessionPerUserEnabled") is not None:
        _log_append(log, f"SingleUser scan start RVA (IsSingleSessionPerUserEnabled): 0x{int(addrs['IsSingleSessionPerUserEnabled']):X}")
        su = single_user_patch(
            ctx,
            start_rva=int(addrs["IsSingleSessionPerUserEnabled"]),
            memset_target_rva=memset_iat,
            verifyversion_iat_rva=verify_iat,
            direct_call=False,
        )
        if su is not None:
            su_start = int(addrs["IsSingleSessionPerUserEnabled"])
            su_func_start = su_start

    # If IsSingleSessionPerUserEnabled didn't work, try IsSingleSessionPerUser
    if su is None and addrs.get("IsSingleSessionPerUser") is not None:
        _log_append(log, f"SingleUser scan start RVA (IsSingleSessionPerUser): 0x{int(addrs['IsSingleSessionPerUser']):X}")
        su = single_user_patch(
            ctx,
            start_rva=int(addrs["IsSingleSessionPerUser"]),
            memset_target_rva=memset_iat,
            verifyversion_iat_rva=verify_iat,
            direct_call=False,
        )
        if su is not None:
            su_start = int(addrs["IsSingleSessionPerUser"])
            su_func_start = su_start

    # If we found a string-xref-based function start but couldn't locate the
    # patch site, do a best-effort scan for the VerifyVersionInfoW call.
    # This keeps --nosymbol usable on builds where the string reference isn't
    # within the same function (or our backtrace lands in a wrapper).
    if su is None and verify_iat is not None:
        best: PatchResult | None = None
        best_func_start: int | None = None
        for rf in runtime_funcs:
            res = single_user_patch(
                ctx,
                start_rva=int(rf.begin_rva),
                memset_target_rva=memset_iat,
                verifyversion_iat_rva=verify_iat,
                direct_call=False,
            )
            if res is None:
                continue
            # Heuristic: prefer the VerifyVersionInfoW call-site patch form
            # when available (mov_eax_1_nop_N) over the generic CMP nop.
            code_line = next((line for line in res.lines if line.startswith(f"SingleUserCode.{arch}=")), "")
            if "mov_eax_1_nop_" in code_line:
                best = res
                best_func_start = int(rf.begin_rva)
                break
            if best is None:
                best = res
                best_func_start = int(rf.begin_rva)
        su = best
        if best_func_start is not None:
            su_func_start = best_func_start

    if su:
        lines.extend(su.lines)
        _log_append(log, "SingleUserPatch: found")
        off_line = next((line for line in su.lines if line.startswith(f"SingleUserOffset.{arch}=")), "")
        code_line = next((line for line in su.lines if line.startswith(f"SingleUserCode.{arch}=")), "")
        if off_line:
            _log_append(log, f"SingleUserPatch: {off_line}")
        if code_line:
            _log_append(log, f"SingleUserPatch: {code_line}")
        if off_line and su_func_start is not None:
            try:
                off_rva = int(off_line.split("=", 1)[1], 16)
                _log_disasm_context(
                    log, ctx,
                    func_start_rva=int(su_func_start),
                    target_rva=off_rva,
                    label="SingleUserPatch",
                    decode_len=0x800,
                    before=20,
                    after=15,
                )
            except Exception as e:
                _log_append(log, f"SingleUserPatch: disasm context parse failed: {e}")
    else:
        lines.append("ERROR: SingleUserPatch not found")
        _log_append(log, "SingleUserPatch: NOT found")

    dp = def_policy_patch(ctx, start_rva=addrs["CDefPolicy_Query"])
    if dp:
        lines.extend(dp.lines)
        _log_append(log, "DefPolicyPatch: found")
        try:
            off_line = next((line for line in dp.lines if line.startswith(f"DefPolicyOffset.{arch}=")), "")
            if off_line:
                off_rva = int(off_line.split("=", 1)[1], 16)
                _log_disasm_context(
                    log,
                    ctx,
                    func_start_rva=int(addrs["CDefPolicy_Query"]),
                    target_rva=off_rva,
                    label="DefPolicyPatch",
                    decode_len=0x800,
                )
        except Exception as e:
            _log_append(log, f"DefPolicyPatch: disasm context failed: {e}")
    else:
        lines.append("ERROR: DefPolicyPatch patten not found")
        _log_append(log, "DefPolicyPatch: NOT found")

    # Version gating like the C++ tool
    if ver.ms <= 0x00060001:
        _write_log(log_path, log)
        return NoSymbolResult(text="\n".join(lines) + "\n")

    if ver.ms == 0x00060002:
        # Win8 SLPolicy hook is a simple call after the allow-remote xref.
        start_va = mem.image_base + allow_remote_xref
        data = mem.image[allow_remote_xref:allow_remote_xref + 0x400]
        dec = Decoder(bitness, data, ip=start_va)
        for insn in dec:
            if insn.mnemonic == Mnemonic.CALL and insn.op0_kind in (OpKind.NEAR_BRANCH32, OpKind.NEAR_BRANCH64):
                off = int(insn.near_branch_target - mem.image_base)
                lines.append(f"SLPolicyInternal.{arch}=1")
                lines.append(f"SLPolicyOffset.{arch}={off:X}")
                lines.append(f"SLPolicyFunc.{arch}=New_Win8SL")
                _write_log(log_path, log)
                return NoSymbolResult(text="\n".join(lines) + "\n")

        lines.append("ERROR: SLGetWindowsInformationDWORDWrapper not found")
        _write_log(log_path, log)
        return NoSymbolResult(text="\n".join(lines) + "\n")

    lo = local_only_patch(
        ctx,
        start_rva=addrs["GetInstanceOfTSLicense"],
        target_rva=addrs["IsLicenseTypeLocalOnly"],
    )
    if lo:
        lines.extend(lo.lines)
        _log_append(log, "LocalOnlyPatch: found")
        try:
            off_line = next((line for line in lo.lines if line.startswith(f"LocalOnlyOffset.{arch}=")), "")
            if off_line:
                off_rva = int(off_line.split("=", 1)[1], 16)
                _log_disasm_context(
                    log,
                    ctx,
                    func_start_rva=int(addrs["GetInstanceOfTSLicense"]),
                    target_rva=off_rva,
                    label="LocalOnlyPatch",
                    decode_len=0x1200,
                )
        except Exception as e:
            _log_append(log, f"LocalOnlyPatch: disasm context failed: {e}")
    else:
        lines.append("ERROR: LocalOnlyPatch patten not found")
        _log_append(log, "LocalOnlyPatch: NOT found")

    # SLInit hook
    csl_init_rva = addrs["CSLQuery_Initialize"]
    _log_append(log, f"SLInitHook: CSLQuery::Initialize RVA 0x{int(csl_init_rva):X}")
    _log_disasm_context(
        log,
        ctx,
        func_start_rva=int(csl_init_rva),
        target_rva=int(csl_init_rva),
        label="SLInitHook",
        decode_len=0x200,
        before=0,
        after=10,
    )
    lines.append(f"SLInitHook.{arch}=1")
    lines.append(f"SLInitOffset.{arch}={csl_init_rva:X}")
    lines.append(f"SLInitFunc.{arch}=New_CSLQuery_Initialize")

    lines.append("")
    lines.append(f"[{ver.to_ini_section()}-SLInit]")

    # Map policy strings -> var keys
    keys = {
        "TerminalServices-RemoteConnectionManager-AllowRemoteConnections": "bRemoteConnAllowed",
        "TerminalServices-RemoteConnectionManager-AllowMultipleSessions": "bFUSEnabled",
        "TerminalServices-RemoteConnectionManager-AllowAppServerMode": "bAppServerAllowed",
        "TerminalServices-RemoteConnectionManager-AllowMultimon": "bMultimonAllowed",
        "TerminalServices-RemoteConnectionManager-MaxUserSessions": "lMaxUserSessions",
        "TerminalServices-RemoteConnectionManager-ce0ad219-4670-4988-98fb-89b14c2f072b-MaxSessions": "ulMaxDebugSessions",
    }
    str_rvas: dict[str, int] = {}
    for s in keys:
        rva = _pattern_match_in_section(mem.image, rdata_sec, s.encode("utf-16le"))
        if rva is not None:
            str_rvas[s] = int(rva)

    # Scan CSLQuery::Initialize to recover global var RVAs.
    var_rvas: dict[str, int] = {"bServerSku": 0, "bInitialized": 0}
    for v in keys.values():
        var_rvas[v] = 0

    current = "bServerSku"

    scan_len = csl_init_len if csl_init_len and csl_init_len > 0 else 0x11000
    start_va = mem.image_base + csl_init_rva
    code = mem.image[csl_init_rva:csl_init_rva + scan_len]
    dec = Decoder(bitness, code, ip=start_va)
    for insn in dec:
        # MOV [RIP+disp], EAX -> store to current var
        if (
            var_rvas.get(current, 0) == 0
            and insn.mnemonic == Mnemonic.MOV
            and insn.op0_kind == OpKind.MEMORY
            and insn.memory_base == Register.RIP
            and insn.op1_kind == OpKind.REGISTER
            and insn.op1_register == Register.EAX
        ):
            if insn.is_ip_rel_memory_operand:
                var_rvas[current] = int(insn.ip_rel_memory_address - mem.image_base)
                _log_append(
                    log,
                    f"SLInitScan: {current} RVA 0x{var_rvas[current]:X} via {_fmt_insn(ctx, insn)}",
                )
            continue

        # LEA RCX, [RIP+disp] selects which policy is being queried.
        if (
            insn.mnemonic == Mnemonic.LEA
            and insn.op0_kind == OpKind.REGISTER
            and insn.op0_register == Register.RCX
            and insn.op1_kind == OpKind.MEMORY
            and insn.memory_base == Register.RIP
        ):
            if not insn.is_ip_rel_memory_operand:
                continue
            target = int(insn.ip_rel_memory_address - mem.image_base)
            for s, key in keys.items():
                rva = str_rvas.get(s)
                if rva is not None and target == rva:
                    current = key
                    _log_append(
                        log,
                        f"SLInitScan: policy '{key}' selected via {_fmt_insn(ctx, insn)}",
                    )
                    break
            continue

        # MOV [RIP+disp], 1 marks bInitialized.
        if (
            insn.mnemonic == Mnemonic.MOV
            and insn.op0_kind == OpKind.MEMORY
            and insn.memory_base == Register.RIP
            and insn.op1_kind in (OpKind.IMMEDIATE8, OpKind.IMMEDIATE32)
            and (insn.immediate8 == 1 if insn.op1_kind == OpKind.IMMEDIATE8 else insn.immediate32 == 1)
        ):
            if insn.is_ip_rel_memory_operand:
                var_rvas["bInitialized"] = int(insn.ip_rel_memory_address - mem.image_base)
                _log_append(
                    log,
                    f"SLInitScan: bInitialized RVA 0x{var_rvas['bInitialized']:X} via {_fmt_insn(ctx, insn)}",
                )
            break

    for k in ("bServerSku",) + tuple(keys.values()) + ("bInitialized",):
        v = var_rvas.get(k, 0)
        if v:
            lines.append(f"{k}.{arch}={v:X}")
        else:
            lines.append(f"ERROR: {k} not found")

    _write_log(log_path, log)
    return NoSymbolResult(text="\n".join(lines) + "\n")
