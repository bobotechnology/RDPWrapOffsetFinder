"""Architecture strategy layer for nosymbol analysis.

The x86 and x64 analysis paths in ``nosymbol.py`` share ~70% of their code
(string location, IAT lookup, patch application, INI section building) but
differ in a handful of well-defined places:

- How functions are enumerated (prologue scan vs .pdata exception directory)
- How string cross-references are found (PUSH/MOV imm32 vs LEA [RIP+disp])
- Whether JMP thunk resolution is needed (x86 only)
- How CDefPolicy::Query is located (x86 has a CMP-pattern pre-scan)
- How SLInit global variables are read (absolute addressing vs RIP-relative)

This module encapsulates those differences behind an ``ArchStrategy`` so the
main ``analyze()`` function can be a single linear path instead of two
near-duplicate 400-line branches.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, Protocol

import pefile
from iced_x86 import Decoder, Mnemonic, OpKind, Register

from disasm import DisasmContext
from exception_table import RuntimeFunction, backtrace_x64, parse_exception_directory_x64
from patches import PatchResult, def_policy_patch, single_user_patch
from nosymbol import _log_append


# ---------------------------------------------------------------------------
# Strategy protocol
# ---------------------------------------------------------------------------

class ArchStrategy(Protocol):
    """Architecture-specific operations needed by the nosymbol analyzer.

    Implementations: ``X86Strategy``, ``X64Strategy``.
    """

    bitness: int
    arch: str  # "x86" | "x64"

    def iter_functions(self, pe: pefile.PE, image: bytes, image_base: int) -> list[tuple[int, int]]:
        """Return (begin_rva, end_rva) for every function in the code section."""
        ...

    def scan_function_xrefs(
        self,
        image: bytes,
        image_base: int,
        pe: pefile.PE,
        targets: dict[str, int],
        log: list[str],
    ) -> tuple[dict[str, int], dict[str, int], dict[str, int | None]]:
        """Scan all functions for references to the given target RVAs.

        Returns ``(addrs, func_sizes, xrefs)`` where:
        - ``addrs[key]`` = the real function entry RVA (after thunk/backtrace resolution)
        - ``func_sizes[key]`` = the real function length
        - ``xrefs[key]`` = the xref instruction's next-RVA (or None)

        Only keys that were found appear in the returned dicts.
        """
        ...

    def find_single_user_fallback(
        self,
        ctx: DisasmContext,
        pe: pefile.PE,
        image: bytes,
        memset_iat: int,
        verify_iat: int | None,
        arch: str,
    ) -> tuple[PatchResult | None, int | None]:
        """Exhaustive scan for SingleUserPatch when the targeted-function
        approach failed. Returns (result, func_start_rva)."""
        ...

    def find_def_policy_query(self, ctx: DisasmContext, funcs: list[tuple[int, int]],
                              q_string_rva: int, image: bytes, image_base: int) -> int | None:
        """Locate CDefPolicy::Query. x86 tries a CMP-pattern scan first; x64
        uses string xref directly."""
        ...

    def scan_slinit_globals(self, image: bytes, image_base: int, csl_init_rva: int,
                            csl_init_len: int, str_rvas: dict[str, int],
                            keys: dict[str, str], log: list[str], ctx: DisasmContext) -> dict[str, int]:
        """Scan CSLQuery::Initialize for the 8 global variable RVAs."""
        ...


# ---------------------------------------------------------------------------
# Shared helpers (used by both strategies)
# ---------------------------------------------------------------------------

def _fmt_insn(ctx: DisasmContext, insn) -> str:
    rva = int(insn.ip - ctx.image_base)
    b = ctx.image[rva:rva + insn.len]
    bhex = " ".join(f"{x:02X}" for x in b)
    return f"{rva:08X}  {bhex:<24}  {insn}"


# ---------------------------------------------------------------------------
# x86 strategy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class X86Strategy:
    bitness: int = 32
    arch: str = "x86"

    def iter_functions(self, pe, image, image_base):
        from nosymbol import _scan_text_functions_x86
        return _scan_text_functions_x86(pe, image, image_base)

    def scan_function_xrefs(self, image, image_base, pe, targets, log):
        """x86: scan text functions for PUSH/MOV imm32 references.

        Two-pass approach:
        1. Strict pass: PUSH imm32 + MOV reg, imm32 only (precise, no false
           positives).
        2. Fallback pass: additionally check MOV [mem], imm32 (needed for
           some x86 DLLs where string addresses are stored in local vars
           instead of registers). Skips functions already assigned in pass 1
           to avoid false positives in large functions.
        """
        from nosymbol import _scan_text_functions_x86, _xref_imm32_x86

        text_funcs = _scan_text_functions_x86(pe, image, image_base)
        _log_append(log, f"x86 text functions found: {len(text_funcs)}")

        addrs: dict[str, int] = {}
        func_sizes: dict[str, int] = {}
        xrefs: dict[str, int | None] = {}

        # Pass 1: strict patterns (PUSH imm32, MOV reg, imm32)
        for begin_rva, end_rva in text_funcs:
            func_len = end_rva - begin_rva
            if func_len <= 0:
                continue
            for key, target_rva in list(targets.items()):
                if key in addrs:
                    continue
                xref = _xref_imm32_x86(image, image_base, begin_rva, func_len, target_rva)
                if xref is None:
                    continue
                addrs[key] = begin_rva
                func_sizes[key] = func_len
                xrefs[key] = xref
                _log_append(log, f"xref found: {key} -> function RVA 0x{begin_rva:X} (size 0x{func_len:X})")
            if len(addrs) == len(targets):
                break

        # Pass 2: fallback to MOV [mem], imm32 for missing targets
        missing = {k: v for k, v in targets.items() if k not in addrs}
        if missing:
            _log_append(log, f"x86 fallback scan (MOV [mem], imm32) for {len(missing)} missing xrefs")
            assigned_funcs = set(addrs.values())
            for begin_rva, end_rva in text_funcs:
                if begin_rva in assigned_funcs:
                    continue
                func_len = end_rva - begin_rva
                if func_len <= 0:
                    continue
                for key, target_rva in list(missing.items()):
                    if key in addrs:
                        continue
                    xref = _xref_imm32_x86(image, image_base, begin_rva, func_len, target_rva, allow_mem=True)
                    if xref is None:
                        continue
                    addrs[key] = begin_rva
                    func_sizes[key] = func_len
                    xrefs[key] = xref
                    assigned_funcs.add(begin_rva)
                    _log_append(log, f"xref found: {key} -> function RVA 0x{begin_rva:X} (size 0x{func_len:X}) (via MOV [mem])")
                if len(addrs) == len(targets):
                    break

        return addrs, func_sizes, xrefs

    def find_single_user_fallback(self, ctx, pe, image, memset_iat, verify_iat, arch):
        """x86: scan all text functions for SingleUserPatch, preferring
        the 'pop_eax_add_esp_12_nop_' code variant."""
        from nosymbol import _scan_text_functions_x86

        text_funcs = _scan_text_functions_x86(pe, image, ctx.image_base)
        best: PatchResult | None = None
        best_func_start: int | None = None
        for begin_rva, end_rva in text_funcs:
            res = single_user_patch(
                ctx, start_rva=begin_rva,
                memset_target_rva=memset_iat,
                verifyversion_iat_rva=verify_iat,
                direct_call=False,
            )
            if res is None:
                continue
            code_line = next((line for line in res.lines if line.startswith(f"SingleUserCode.{arch}=")), "")
            if "pop_eax_add_esp_12_nop_" in code_line:
                return res, begin_rva
            if best is None:
                best = res
                best_func_start = begin_rva
        return best, best_func_start

    def find_def_policy_query(self, ctx, funcs, q_string_rva, image, image_base):
        """x86: try CMP-pattern scan first, fall back to string xref."""
        from nosymbol import _xref_imm32_x86

        candidates: list[int] = []
        for begin_rva, end_rva in funcs:
            func_len = end_rva - begin_rva
            if func_len <= 0 or func_len > 0x800:
                continue
            start_va = image_base + begin_rva
            code = image[begin_rva:begin_rva + func_len]
            dec = Decoder(32, code, ip=start_va)
            for insn in dec:
                if insn.mnemonic != Mnemonic.CMP:
                    continue
                if (insn.op1_kind == OpKind.MEMORY
                        and insn.memory_base == Register.ECX
                        and insn.memory_displacement in (0x320, 0x63C)
                        and insn.op0_kind == OpKind.REGISTER):
                    candidates.append(begin_rva)
                    break
                if (insn.op0_kind == OpKind.MEMORY
                        and insn.memory_base == Register.ECX
                        and insn.memory_displacement in (0x320, 0x63C)
                        and insn.op1_kind == OpKind.REGISTER):
                    candidates.append(begin_rva)
                    break

        for rva in candidates:
            if def_policy_patch(ctx, start_rva=rva) is not None:
                return rva
        if candidates:
            return candidates[0]

        for begin_rva, end_rva in funcs:
            func_len = end_rva - begin_rva
            if func_len <= 0:
                continue
            xref = _xref_imm32_x86(image, image_base, begin_rva, func_len, q_string_rva)
            if xref is not None:
                from nosymbol import _resolve_jmp_stub_x86
                return _resolve_jmp_stub_x86(image, image_base, begin_rva, funcs)
        return None

    def scan_slinit_globals(self, image, image_base, csl_init_rva, csl_init_len,
                            str_rvas, keys, log, ctx):
        """x86 SLInit scan: policy-string-driven approach.

        Tracks which policy string (MOV ECX, imm32) was last seen, then
        assigns the next MOV [abs], REG32 to that variable. This is
        version-independent and matches the x64 strategy. The fixed-offset
        cluster approach was removed because the struct layout varies
        across Windows versions (e.g. 17134 has 0x20-byte block, 17763
        has a gap making it 0x24 bytes).
        """
        var_rvas: dict[str, int] = {"bServerSku": 0, "bInitialized": 0}
        for v in keys.values():
            var_rvas[v] = 0

        scan_len = csl_init_len if csl_init_len and csl_init_len > 0 else 0x11000
        if scan_len < 0x1000:
            scan_len = 0x40000
        current = "bServerSku"
        start_va = image_base + csl_init_rva
        code = image[csl_init_rva:csl_init_rva + scan_len]
        dec = Decoder(32, code, ip=start_va)

        for insn in dec:
            # bServerSku / policy globals: MOV [abs], REG32
            if (var_rvas.get(current, 0) == 0
                    and insn.mnemonic == Mnemonic.MOV
                    and insn.op0_kind == OpKind.MEMORY
                    and insn.memory_base == Register.NONE
                    and insn.memory_index == Register.NONE
                    and insn.op1_kind == OpKind.REGISTER):
                abs_va = insn.memory_displacement
                if abs_va > image_base:
                    rva = abs_va - image_base
                    var_rvas[current] = rva
                    _log_append(log, f"SLInitScan: {current} RVA 0x{rva:X} via {_fmt_insn(ctx, insn)}")
                continue

            # Policy string selection: MOV any_reg, imm32 or PUSH imm32
            # (absolute address of wide string). Older versions (10586) use
            # MOV EDX, imm32; newer versions use MOV ECX, imm32.
            is_mov_reg_imm32 = (insn.mnemonic == Mnemonic.MOV
                                and insn.op0_kind == OpKind.REGISTER
                                and insn.op1_kind == OpKind.IMMEDIATE32)
            is_push_imm32 = (insn.mnemonic == Mnemonic.PUSH
                             and insn.op0_kind == OpKind.IMMEDIATE32)
            if is_mov_reg_imm32 or is_push_imm32:
                imm_va = int(insn.immediate32)
                imm_rva = imm_va - image_base
                for s, key in keys.items():
                    rva = str_rvas.get(s)
                    if rva is not None and imm_rva == rva:
                        current = key
                        _log_append(log, f"SLInitScan: policy '{key}' selected via {_fmt_insn(ctx, insn)}")
                        break
                continue

            # bInitialized: MOV [abs], 1
            if (insn.mnemonic == Mnemonic.MOV
                    and insn.op0_kind == OpKind.MEMORY
                    and insn.memory_base == Register.NONE
                    and insn.memory_index == Register.NONE
                    and insn.op1_kind in (OpKind.IMMEDIATE8, OpKind.IMMEDIATE32)):
                imm = insn.immediate8 if insn.op1_kind == OpKind.IMMEDIATE8 else insn.immediate32
                if imm == 1:
                    abs_va = insn.memory_displacement
                    if abs_va > image_base:
                        rva = abs_va - image_base
                        var_rvas["bInitialized"] = rva
                        _log_append(log, f"SLInitScan: bInitialized RVA 0x{rva:X} via {_fmt_insn(ctx, insn)}")
                    break

        return var_rvas


# ---------------------------------------------------------------------------
# x64 strategy
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class X64Strategy:
    bitness: int = 64
    arch: str = "x64"

    def iter_functions(self, pe, image, image_base):
        runtime_funcs = parse_exception_directory_x64(pe, image)
        return [(int(rf.begin_rva), int(rf.end_rva)) for rf in runtime_funcs]

    def scan_function_xrefs(self, image, image_base, pe, targets, log):
        """x64: scan exception-directory functions for LEA [RIP+disp] references,
        backtracing unwind chains to find the real function entry."""
        from nosymbol import _xref_lea_rip

        runtime_funcs = parse_exception_directory_x64(pe, image)
        _log_append(log, f"runtime functions (exception dir): {len(runtime_funcs)}")

        addrs: dict[str, int] = {}
        func_sizes: dict[str, int] = {}
        xrefs: dict[str, int | None] = {}

        for rf in runtime_funcs:
            func_len = int(rf.end_rva - rf.begin_rva)
            if func_len <= 0:
                continue
            for key, target in list(targets.items()):
                if key in addrs:
                    continue
                xref = _xref_lea_rip(image, image_base, 64, rf.begin_rva, func_len, target)
                if not xref:
                    continue
                top = backtrace_x64(image, rf)
                addrs[key] = int(top.begin_rva)
                func_sizes[key] = int(top.end_rva - top.begin_rva)
                xrefs[key] = int(xref)
                _log_append(log, f"xref found: {key} -> function RVA 0x{addrs[key]:X}")
            if len(addrs) == len(targets):
                break

        return addrs, func_sizes, xrefs

    def find_single_user_fallback(self, ctx, pe, image, memset_iat, verify_iat, arch):
        """x64: scan all runtime functions for SingleUserPatch, preferring
        the 'mov_eax_1_nop_' code variant."""
        runtime_funcs = parse_exception_directory_x64(pe, image)
        best: PatchResult | None = None
        best_func_start: int | None = None
        for rf in runtime_funcs:
            res = single_user_patch(
                ctx, start_rva=int(rf.begin_rva),
                memset_target_rva=memset_iat,
                verifyversion_iat_rva=verify_iat,
                direct_call=False,
            )
            if res is None:
                continue
            code_line = next((line for line in res.lines if line.startswith(f"SingleUserCode.{arch}=")), "")
            if "mov_eax_1_nop_" in code_line:
                return res, int(rf.begin_rva)
            if best is None:
                best = res
                best_func_start = int(rf.begin_rva)
        return best, best_func_start

    def find_def_policy_query(self, ctx, funcs, q_string_rva, image, image_base):
        """x64: use string xref directly (no CMP pre-scan)."""
        from nosymbol import _xref_lea_rip
        for begin_rva, end_rva in funcs:
            func_len = end_rva - begin_rva
            if func_len <= 0:
                continue
            xref = _xref_lea_rip(image, image_base, 64, begin_rva, func_len, q_string_rva)
            if xref is not None:
                return begin_rva
        return None

    def scan_slinit_globals(self, image, image_base, csl_init_rva, csl_init_len,
                            str_rvas, keys, log, ctx):
        """x64 SLInit scan: policy-string-driven approach.

        Two fixes for old DLLs with tiny exception dir entries (e.g. 10240):
        1. Expand scan_len beyond the exception dir entry when it's < 4KB,
           but cap at the next exception dir entry to avoid adjacent functions.
        2. bInitialized via register: only if MOV reg,1 was within 0x30 bytes
           of the MOV [RIP+disp],reg — prevents false positives from stale
           register values while still catching the 10240 pattern (ECX=1 at
           +0xC before write).
        """
        var_rvas: dict[str, int] = {"bServerSku": 0, "bInitialized": 0}
        for v in keys.values():
            var_rvas[v] = 0

        current = "bServerSku"
        scan_len = csl_init_len if csl_init_len and csl_init_len > 0 else 0x11000
        # Some DLLs (e.g. 10240 x64) have tiny exception dir entries that
        # only cover the prologue (142B for a 225KB function). For those,
        # use a generous scan window. Proximity-based reg tracking for
        # bInitialized prevents false positives from adjacent functions.
        if scan_len < 0x1000:
            scan_len = 0x40000

        start_va = image_base + csl_init_rva
        code = image[csl_init_rva:csl_init_rva + scan_len]
        dec = Decoder(64, code, ip=start_va)

        # Track {(register, rva): value} for bInitialized via register.
        # Only used when the MOV reg, 1 is within 0x30 bytes of the store.
        reg_imm: dict[tuple[int, int], int] = {}

        for insn in dec:
            # Track MOV reg, imm (for bInitialized via register)
            if (insn.mnemonic == Mnemonic.MOV
                    and insn.op0_kind == OpKind.REGISTER
                    and insn.op1_kind in (OpKind.IMMEDIATE8, OpKind.IMMEDIATE32)):
                imm = insn.immediate8 if insn.op1_kind == OpKind.IMMEDIATE8 else insn.immediate32
                rva = int(insn.ip - image_base)
                reg_imm[(insn.op0_register, rva)] = imm

            # bServerSku / policy globals: MOV [RIP+disp], REG32 (any register)
            if (var_rvas.get(current, 0) == 0
                    and insn.mnemonic == Mnemonic.MOV
                    and insn.op0_kind == OpKind.MEMORY
                    and insn.memory_base == Register.RIP
                    and insn.op1_kind == OpKind.REGISTER):
                if insn.is_ip_rel_memory_operand:
                    var_rvas[current] = int(insn.ip_rel_memory_address - image_base)
                    _log_append(log, f"SLInitScan: {current} RVA 0x{var_rvas[current]:X} via {_fmt_insn(ctx, insn)}")
                    # Only clear this register's tracking so near-proximity
                    # MOV reg,1 for bInitialized (e.g. ECX=1 at +0xC) is preserved.
                    reg_imm.pop((insn.op1_register, int(insn.ip - image_base)), None)
                continue
            # Policy string selection: LEA RCX, [RIP+disp]
            if (insn.mnemonic == Mnemonic.LEA
                    and insn.op0_kind == OpKind.REGISTER
                    and insn.op0_register == Register.RCX
                    and insn.op1_kind == OpKind.MEMORY
                    and insn.memory_base == Register.RIP):
                if not insn.is_ip_rel_memory_operand:
                    continue
                target = int(insn.ip_rel_memory_address - image_base)
                for s, key in keys.items():
                    rva = str_rvas.get(s)
                    if rva is not None and target == rva:
                        current = key
                        _log_append(log, f"SLInitScan: policy '{key}' selected via {_fmt_insn(ctx, insn)}")
                        break
                continue

            # bInitialized: MOV [RIP+disp], 1 (immediate) or MOV [RIP+disp], REG
            # where REG was set to 1 nearby (within 0x30 bytes — handles 10240's
            # MOV ECX,1; MOV [X],R14D; MOV [bInit],ECX pattern).
            if (insn.mnemonic == Mnemonic.MOV
                    and insn.op0_kind == OpKind.MEMORY
                    and insn.memory_base == Register.RIP
                    and insn.is_ip_rel_memory_operand):
                is_imm_1 = (insn.op1_kind in (OpKind.IMMEDIATE8, OpKind.IMMEDIATE32)
                            and (insn.immediate8 if insn.op1_kind == OpKind.IMMEDIATE8 else insn.immediate32) == 1)

                is_reg_1 = False
                if insn.op1_kind == OpKind.REGISTER:
                    store_rva = int(insn.ip - image_base)
                    for (reg, mov_rva), val in reg_imm.items():
                        if reg == insn.op1_register and val == 1 and store_rva - mov_rva <= 0x30:
                            is_reg_1 = True
                            break

                if is_imm_1 or is_reg_1:
                    var_rvas["bInitialized"] = int(insn.ip_rel_memory_address - image_base)
                    _log_append(log, f"SLInitScan: bInitialized RVA 0x{var_rvas['bInitialized']:X} via {_fmt_insn(ctx, insn)}")
                    break

        return var_rvas


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def get_strategy(is_64: bool) -> ArchStrategy:
    """Return the appropriate strategy for the given architecture."""
    return X64Strategy() if is_64 else X86Strategy()
