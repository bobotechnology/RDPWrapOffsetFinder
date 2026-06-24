from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from datetime import datetime

import pefile
from iced_x86 import Decoder, Mnemonic, OpKind, Register

from disasm import DisasmContext
from exception_table import backtrace_x64, parse_exception_directory_x64
from imports import find_iat_rva
from patches import PatchResult, def_policy_patch, local_only_patch, single_user_patch
from pe_image import load_memory_image
from winver import FileVersion

# PE section characteristics flags (IMAGE_SECTION_HEADER.Characteristics).
# See: winnt.h / ECMA-335 II.25.3.3.1 / PE-COFF specification §6.3.
# Used as fallback when no section is explicitly named ".text"/".rdata".
IMAGE_SCN_MEM_EXECUTE = 0x20000000  # Section can be executed as code.


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


# Module-level progress callback set by analyze() — allows the GUI to
# receive real-time log messages without threading through every internal
# function signature.  Safe because only one analysis runs at a time.
_progress_callback: Callable[[str], None] | None = None


def _log_append(log: list[str], msg: str) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted = f"[{ts}] {msg}"
    log.append(formatted)
    if _progress_callback is not None:
        try:
            _progress_callback(formatted)
        except Exception:
            pass


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
        # Fallback: pick the first section flagged executable (handles DLLs
        # where the code section is named differently, e.g. packed binaries).
        for sec in pe.sections:
            if sec.Characteristics & IMAGE_SCN_MEM_EXECUTE:
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


def _xref_imm32_x86(image: bytes, image_base: int, func_rva: int, func_len: int, target_rva: int, *, allow_mem: bool = False) -> int | None:
    target_va = image_base + target_rva
    start_va = image_base + func_rva
    code = image[func_rva:func_rva + func_len]
    dec = Decoder(32, code, ip=start_va)
    for insn in dec:
        if insn.mnemonic == Mnemonic.PUSH and insn.op0_kind == OpKind.IMMEDIATE32:
            if int(insn.immediate32) == target_va:
                return int(insn.next_ip - image_base)
        if insn.mnemonic == Mnemonic.MOV and insn.op1_kind == OpKind.IMMEDIATE32:
            # MOV reg, imm32 — load string address into register
            if insn.op0_kind == OpKind.REGISTER:
                if int(insn.immediate32) == target_va:
                    return int(insn.next_ip - image_base)
            # MOV [mem], imm32 — store string address in local variable
            # (e.g., mov dword [ebp-10h], offset string)
            # Only checked in fallback pass to avoid false positives in
            # large functions where the immediate might match by coincidence.
            elif allow_mem and insn.op0_kind == OpKind.MEMORY:
                if int(insn.immediate32) == target_va:
                    return int(insn.next_ip - image_base)
    return None


def _find_func_start_x86(image: bytes, image_base: int, xref_rva: int, text_funcs: list[tuple[int, int]]) -> tuple[int, int] | None:
    for begin, end in text_funcs:
        if begin <= xref_rva < end:
            return (begin, end)
    return None


def _resolve_jmp_stub_x86(image: bytes, image_base: int, func_rva: int, text_funcs: list[tuple[int, int]], max_depth: int = 3) -> int:
    for _ in range(max_depth):
        func_info = _find_func_start_x86(image, image_base, func_rva, text_funcs)
        if func_info is None:
            break
        begin, end = func_info
        func_len = end - begin
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
        target_func = _find_func_start_x86(image, image_base, jmp_target, text_funcs)
        if target_func is None:
            break
        func_rva = target_func[0]
    return func_rva


def _locate_strings(pe: pefile.PE, image: bytes) -> dict[str, int | None]:
    """Locate the C++ class/method name strings in the PE's read-only sections.

    Scans .rdata first (the common case), then falls back to all sections for
    DLLs where strings live elsewhere. Returns a dict mapping logical name to
    RVA (or None if not found).
    """
    rdata = _find_section(pe, b".rdata")

    def _find(pat: bytes) -> int | None:
        if rdata is not None:
            rva = _pattern_match_in_section(image, rdata, pat)
            if rva is not None:
                return rva
        for sec in pe.sections:
            rva = _pattern_match_in_section(image, sec, pat)
            if rva is not None:
                return rva
        return None

    def _find_exact(pat: bytes) -> int | None:
        """Find a null-terminated string. Does not match substrings of
        longer strings (unlike _find which falls back to prefix search)."""
        needle = pat + b"\x00"
        sections = ([rdata] if rdata is not None else []) + \
                   [s for s in pe.sections if s is not rdata]
        for sec in sections:
            start = int(sec.VirtualAddress)
            size = int(getattr(sec, "Misc_VirtualSize", 0) or 0) or int(sec.SizeOfRawData)
            hay = image[start:start + size]
            idx = hay.find(needle)
            if idx >= 0:
                return start + idx
        return None

    return {
        "CDefPolicy::Query": _find(b"CDefPolicy::Query"),
        "CSLQuery::IsTerminalTypeLocalOnly": _find(b"CSLQuery::IsTerminalTypeLocalOnly"),
        "IsSingleSessionPerUserEnabled": _find(b"CSessionArbitrationHelper::IsSingleSessionPerUserEnabled")
            or _find(b"IsSingleSessionPerUserEnabled"),
        # Search order for GetInstanceOfTSLicense:
        # 1. Error message prefix (only referenced in the function that calls
        #    IsLicenseTypeLocalOnly — avoids ambiguity with other functions
        #    that reference the short identifier)
        # 2. Standalone CEnforcementCore::GetInstanceOfTSLicense\0 (x64)
        # 3. Standalone GetInstanceOfTSLicense\0 (x86 fallback)
        # 4. Legacy prefix searches (last resort)
        "GetInstanceOfTSLicense": _find(b"CEnforcementCore::GetInstanceOfTSLicense FAILED")
            or _find(b"CEnforcementCore::GetInstanceOfTSLicense ")
            or _find(b"CEnforcementCore::GetInstanceOfTSLicense")
            or _find_exact(b"CEnforcementCore::GetInstanceOfTSLicense")
            or _find_exact(b"GetInstanceOfTSLicense")
            or _find(b"GetInstanceOfTSLicense"),
        "IsSingleSessionPerUser": _find(b"CUtils::IsSingleSessionPerUser")
            or _find(b"IsSingleSessionPerUser"),
        "AllowRemoteConnections": _find("TerminalServices-RemoteConnectionManager-AllowRemoteConnections".encode("utf-16le")),
    }


def _locate_iats(pe: pefile.PE, log: list[str]) -> tuple[int, int | None]:
    """Find memset and VerifyVersionInfoW IAT slot RVAs."""
    memset_iat = (
        find_iat_rva(pe, "msvcrt.dll", "memset")
        or find_iat_rva(pe, "ucrtbase.dll", "memset")
        or find_iat_rva(pe, "api-ms-win-crt-string-l1-1-0.dll", "memset")
    )
    if memset_iat is None:
        _log_append(log, "ERROR: memset import not found")
        raise RuntimeError("memset import not found")
    _log_append(log, f"IAT RVAs: memset=0x{memset_iat:X}")

    verify_iat = find_iat_rva(pe, "api-ms-win-core-kernel32-legacy-l1-1-1.dll", "VerifyVersionInfoW")
    if verify_iat is None:
        verify_iat = find_iat_rva(pe, "kernel32.dll", "VerifyVersionInfoW")
    _log_append(log, f"IAT RVAs: VerifyVersionInfoW={(hex(verify_iat) if verify_iat is not None else None)}")
    return memset_iat, verify_iat


def _apply_single_user_patch(
    strat, ctx, log, addrs, pe, mem, memset_iat, verify_iat,
) -> tuple[PatchResult | None, int | None]:
    """Try SingleUserPatch via targeted function, then fallback exhaustive scan.

    Returns (result, func_start_rva).
    """
    arch = strat.arch
    su: PatchResult | None = None
    su_func_start: int | None = None

    # Attempt 1: IsSingleSessionPerUserEnabled
    start = addrs.get("IsSingleSessionPerUserEnabled") or addrs.get("IsSingleSessionPerUser")
    if start is not None:
        _log_append(log, f"SingleUser scan start RVA: 0x{int(start):X}")
        su = single_user_patch(
            ctx, start_rva=int(start),
            memset_target_rva=memset_iat,
            verifyversion_iat_rva=verify_iat,
            direct_call=False,
        )
        if su is not None:
            su_func_start = int(start)

    # Attempt 2: IsSingleSessionPerUser
    if su is None and addrs.get("IsSingleSessionPerUser") is not None:
        _log_append(log, f"SingleUser scan start RVA (IsSingleSessionPerUser): 0x{int(addrs['IsSingleSessionPerUser']):X}")
        su = single_user_patch(
            ctx, start_rva=int(addrs["IsSingleSessionPerUser"]),
            memset_target_rva=memset_iat,
            verifyversion_iat_rva=verify_iat,
            direct_call=False,
        )
        if su is not None:
            su_func_start = int(addrs["IsSingleSessionPerUser"])

    # Attempt 3: exhaustive scan (architecture-specific preferred pattern)
    if su is None and verify_iat is not None:
        su, su_func_start = strat.find_single_user_fallback(
            ctx, pe, mem.image, memset_iat, verify_iat, arch,
        )

    return su, su_func_start


def _emit_patch_result(
    log: list[str], ctx, result: PatchResult | None, arch: str, label: str,
    func_start: int | None, lines: list[str], decode_len: int = 0x800,
    before: int = 3, after: int = 3,
) -> None:
    """Append patch result lines to output and log disasm context on success.

    ``label`` is used for log messages (e.g. "SingleUserPatch: found").
    The INI line prefix is derived by stripping "Patch" (e.g. "SingleUserOffset.x64=").
    """
    line_prefix = label[:-5] if label.endswith("Patch") else label
    if result:
        lines.extend(result.lines)
        _log_append(log, f"{label}: found")
        off_line = next((line for line in result.lines if line.startswith(f"{line_prefix}Offset.{arch}=")), "")
        code_line = next((line for line in result.lines if line.startswith(f"{line_prefix}Code.{arch}=")), "")
        if off_line:
            _log_append(log, f"{label}: {off_line}")
        if code_line:
            _log_append(log, f"{label}: {code_line}")
        if off_line and func_start is not None:
            try:
                off_rva = int(off_line.split("=", 1)[1], 16)
                _log_disasm_context(log, ctx, func_start_rva=func_start, target_rva=off_rva,
                                    label=label, decode_len=decode_len, before=before, after=after)
            except Exception as e:
                _log_append(log, f"{label}: disasm context parse failed: {e}")
    else:
        lines.append(f"ERROR: {label} not found")
        _log_append(log, f"{label}: NOT found")


# SLInit policy-string → global-variable-name mapping (shared by both archs).
_SLINIT_KEYS = {
    "TerminalServices-RemoteConnectionManager-AllowRemoteConnections": "bRemoteConnAllowed",
    "TerminalServices-RemoteConnectionManager-AllowMultipleSessions": "bFUSEnabled",
    "TerminalServices-RemoteConnectionManager-AllowAppServerMode": "bAppServerAllowed",
    "TerminalServices-RemoteConnectionManager-AllowMultimon": "bMultimonAllowed",
    "TerminalServices-RemoteConnectionManager-MaxUserSessions": "lMaxUserSessions",
    "TerminalServices-RemoteConnectionManager-ce0ad219-4670-4988-98fb-89b14c2f072b-MaxSessions": "ulMaxDebugSessions",
}


def analyze(
    pe: pefile.PE,
    dll_path: Path,
    ver: FileVersion,
    *,
    log_path: str | Path | None = None,
    progress_callback: Callable[[str], None] | None = None,
) -> NoSymbolResult:
    """Analyze termsrv.dll without PDB symbols and emit rdpwrap.ini sections.

    Architecture-specific differences (x86 vs x64) are handled by an
    ``ArchStrategy`` object selected via :func:`nosymbol_arch.get_strategy`.
    The main flow is a single linear path shared by both architectures.
    """
    global _progress_callback
    _progress_callback = progress_callback
    try:
        return _analyze_impl(pe, dll_path, ver, log_path=log_path)
    finally:
        _progress_callback = None


def _analyze_impl(
    pe: pefile.PE,
    dll_path: Path,
    ver: FileVersion,
    *,
    log_path: str | Path | None = None,
) -> NoSymbolResult:
    """Internal implementation — separated so try/finally can clear the callback."""
    from nosymbol_arch import get_strategy

    log: list[str] = []
    _log_append(log, f"nosymbol analyze start: {dll_path}")
    _log_append(log, f"version: {ver.to_ini_section()}")
    mem = load_memory_image(pe)
    _log_append(log, f"image_base: 0x{mem.image_base:X}, is_64: {mem.is_64}")

    strat = get_strategy(mem.is_64)
    bitness = strat.bitness
    arch = strat.arch
    ctx = DisasmContext(bitness=bitness, image_base=mem.image_base, image=mem.image)

    # --- 1. Locate C++ class/method name strings --------------------------
    strings = _locate_strings(pe, mem.image)
    for name, rva in strings.items():
        _log_append(log, f"string RVAs: {name}={rva and hex(rva)}")

    missing_strs = [n for n, v in strings.items() if v is None]
    if missing_strs:
        _log_append(log, f"ERROR: required strings missing: {', '.join(missing_strs)}")
        _write_log(log_path, log)
        raise RuntimeError(f"Failed to locate required strings (nosymbol): {', '.join(missing_strs)}")

    q = strings["CDefPolicy::Query"]
    local_only = strings["CSLQuery::IsTerminalTypeLocalOnly"]
    single_enabled = strings["IsSingleSessionPerUserEnabled"]
    inst_license = strings["GetInstanceOfTSLicense"]
    single_user = strings["IsSingleSessionPerUser"]
    allow_remote = strings["AllowRemoteConnections"]

    # --- 2. Locate IAT slots (memset, VerifyVersionInfoW) ------------------
    memset_iat, verify_iat = _locate_iats(pe, log)

    # --- 3. Scan functions for string cross-references --------------------
    targets_required = {
        "GetInstanceOfTSLicense": inst_license,
        "IsSingleSessionPerUserEnabled": single_enabled,
        "IsLicenseTypeLocalOnly": local_only,
        "CSLQuery_Initialize": allow_remote,
    }
    if arch == "x64":
        targets_required["CDefPolicy_Query"] = q
    targets_optional = {"IsSingleSessionPerUser": single_user}
    targets = dict(targets_required)
    targets.update(targets_optional)

    addrs, func_sizes, xref_map = strat.scan_function_xrefs(
        mem.image, mem.image_base, pe, targets, log,
    )

    missing = [k for k in targets_required if k not in addrs]
    if missing:
        _log_append(log, f"ERROR: missing function xrefs: {', '.join(missing)}")
        _write_log(log_path, log)
        raise RuntimeError(f"Failed to find function xrefs: {', '.join(missing)}")

    allow_remote_xref = xref_map.get("CSLQuery_Initialize")
    if allow_remote_xref is None:
        _log_append(log, "ERROR: CSLQuery::Initialize not located")
        _write_log(log_path, log)
        raise RuntimeError("Failed to locate CSLQuery::Initialize")

    # x86 locates CDefPolicy_Query separately (CMP-pattern pre-scan).
    if "CDefPolicy_Query" not in addrs:
        funcs = strat.iter_functions(pe, mem.image, mem.image_base)
        dp_query_rva = strat.find_def_policy_query(ctx, funcs, q, mem.image, mem.image_base)
        if dp_query_rva is not None:
            addrs["CDefPolicy_Query"] = dp_query_rva
            _log_append(log, f"CDefPolicy_Query: found at RVA 0x{dp_query_rva:X}")
        else:
            _log_append(log, "ERROR: CDefPolicy_Query not found")
            _write_log(log_path, log)
            raise RuntimeError("Failed to find CDefPolicy_Query")

    # --- 4. Build INI main section ----------------------------------------
    lines: list[str] = [f"[{ver.to_ini_section()}]"]

    # SingleUserPatch
    su, su_func_start = _apply_single_user_patch(
        strat, ctx, log, addrs, pe, mem, memset_iat, verify_iat,
    )
    _emit_patch_result(log, ctx, su, arch, "SingleUserPatch", su_func_start, lines,
                       decode_len=0x800, before=20, after=15)

    # DefPolicyPatch
    dp_func_rva = addrs["CDefPolicy_Query"]
    if arch == "x86":
        from nosymbol import _resolve_jmp_stub_x86
        funcs = strat.iter_functions(pe, mem.image, mem.image_base)
        dp_func_rva = _resolve_jmp_stub_x86(mem.image, mem.image_base, dp_func_rva, funcs)
    _log_append(log, f"DefPolicyPatch: resolved func RVA 0x{int(dp_func_rva):X}")
    dp = def_policy_patch(ctx, start_rva=int(dp_func_rva))
    _emit_patch_result(log, ctx, dp, arch, "DefPolicyPatch", int(dp_func_rva), lines,
                       decode_len=0x800)

    # Vista / Win7: no SLInit, return early.
    if ver.ms <= 0x00060001:
        _write_log(log_path, log)
        return NoSymbolResult(text="\n".join(lines) + "\n")

    # Win8: SL hook via SLGetWindowsInformationDWORDWrapper.
    if ver.ms == 0x00060002:
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
    _emit_patch_result(log, ctx, lo, arch, "LocalOnlyPatch",
                       int(addrs["GetInstanceOfTSLicense"]), lines, decode_len=0x1200)

    # --- 5. SLInit hook + global variable scan ----------------------------
    csl_init_rva = addrs["CSLQuery_Initialize"]
    csl_init_len = func_sizes.get("CSLQuery_Initialize", 0x11000)
    _log_append(log, f"SLInitHook: CSLQuery::Initialize RVA 0x{int(csl_init_rva):X}")
    _log_disasm_context(log, ctx, func_start_rva=int(csl_init_rva), target_rva=int(csl_init_rva),
                        label="SLInitHook", decode_len=0x200, before=0, after=10)
    lines.append(f"SLInitHook.{arch}=1")
    lines.append(f"SLInitOffset.{arch}={csl_init_rva:X}")
    lines.append(f"SLInitFunc.{arch}=New_CSLQuery_Initialize")

    lines.append("")
    lines.append(f"[{ver.to_ini_section()}-SLInit]")

    # Locate policy-string RVAs (wide strings) for SLInit scan.
    str_rvas: dict[str, int] = {}
    for s in _SLINIT_KEYS:
        rva = _pattern_match_in_section(mem.image, _find_section(pe, b".rdata") or pe.sections[0], s.encode("utf-16le"))
        if rva is not None:
            str_rvas[s] = int(rva)

    var_rvas = strat.scan_slinit_globals(
        mem.image, mem.image_base, int(csl_init_rva), csl_init_len,
        str_rvas, _SLINIT_KEYS, log, ctx,
    )

    for k in ("bServerSku",) + tuple(_SLINIT_KEYS.values()) + ("bInitialized",):
        v = var_rvas.get(k, 0)
        if v:
            lines.append(f"{k}.{arch}={v:X}")
        else:
            lines.append(f"ERROR: {k} not found")

    _write_log(log_path, log)
    return NoSymbolResult(text="\n".join(lines) + "\n")
