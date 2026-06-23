"""Tests for patches.py: local_only_patch, def_policy_patch, single_user_patch.

These tests build synthetic instruction sequences with iced-x86's Encoder and
verify the patch detectors recognize the expected patterns and return the
correct offset/code strings. Negative cases verify that malformed sequences
are rejected (return None).

Convention: image_base = 0 so VA == RVA throughout, which keeps Encoder's
RIP-relative target equal to the RVA.
"""
from __future__ import annotations

from typing import Iterable

import pytest
from iced_x86 import Code, Instruction, MemoryOperand, Register

from disasm import DisasmContext
from patches import def_policy_patch, local_only_patch, single_user_patch

from _asmharness import (
    TEST_IMAGE_BASE,
    asm,
    call_rel64,
    cmp_rm64_r64,
    cmp_r64_rm64,
    je_rel64,
    jne_rel64,
    jns_rel64,
    js_rel64,
    mov_r64_rm64,
    nop,
    place_code,
    make_image,
    rip_mem,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ctx(bitness: int, image: bytes) -> DisasmContext:
    return DisasmContext(bitness=bitness, image_base=TEST_IMAGE_BASE, image=image)


def _build_image(bitness: int, func_rva: int, instructions: Iterable[Instruction],
                 image_size: int = 0x4000) -> DisasmContext:
    code = asm(bitness, instructions, rip=TEST_IMAGE_BASE + func_rva)
    img = make_image(image_size)
    place_code(img, func_rva, code)
    return _ctx(bitness, bytes(img))


def _test_rm64_r64(reg1: int, reg2: int) -> Instruction:
    """TEST reg1, reg2 (64-bit)."""
    return Instruction.create_reg_reg(Code.TEST_RM64_R64, reg1, reg2)


# ===========================================================================
# local_only_patch
# ===========================================================================
#
# Expected pattern (JNS variant):
#   call  IsLicenseTypeLocalOnly   ; rel32 call
#   [optional MOVs]
#   test  reg, reg
#   jns   <cmp>                    ; jump-to-cmp
#   <fallthrough region>           ; jns.ip + jns.len
#   cmp   ...
#   je    <jns fallthrough>        ; must target jns fallthrough
#
# The detector returns:
#   LocalOnlyCode = "nopjmp"  if JE is rel32 (len > 2)
#   LocalOnlyCode = "jmpshort" if JE is rel8 (len == 2)

class TestLocalOnlyPatch:
    FUNC = 0x1000
    TARGET = 0x2000  # IsLicenseTypeLocalOnly

    def test_jns_nopjmp_positive(self):
        """Full JNS pattern with rel32 JE → returns nopjmp.

        Layout (rel32 forced so all sizes are deterministic):
          0x1000: call (5B)  -> 0x1005
          0x1005: test (3B)  -> 0x1008
          0x1008: jns (6B)   -> 0x100E, target=0x1014, fallthrough=0x100E
          0x100E: nop*6      -> 0x1014   (fallthrough region)
          0x1014: cmp (7B)   -> 0x101B
          0x101B: je  (6B)   -> 0x1021, target=0x100E (= jns fallthrough)
        """
        ctx = _build_image(64, self.FUNC, [
            call_rel64(self.TARGET),
            _test_rm64_r64(Register.RAX, Register.RAX),
            jns_rel64(0x1014),
            nop(), nop(), nop(), nop(), nop(), nop(),
            cmp_r64_rm64(Register.RAX, rip_mem(0x63C)),
            je_rel64(0x100E),
        ])
        r = local_only_patch(ctx, start_rva=self.FUNC, target_rva=self.TARGET)
        assert r is not None
        assert "LocalOnlyPatch.x64=1" in r.lines
        # JE is rel32 (6 bytes) → nopjmp.
        assert "LocalOnlyCode.x64=nopjmp" in r.lines
        # Offset = JE instruction's RVA.
        assert "LocalOnlyOffset.x64=101B" in r.lines

    def test_js_variant_positive(self):
        """JS variant: CMP at JS fallthrough, JE targets JS.target."""
        #   0x1000: call (5B) -> 0x1005
        #   0x1005: test (3B) -> 0x1008
        #   0x1008: js   (6B) -> 0x100E, target=0x1015, fallthrough=0x100E
        #   0x100E: cmp  (7B) -> 0x1015    <- at JS fallthrough
        #   0x1015: je   (6B) -> 0x101B, target=0x1015? No — must target JS.target.
        # JS: ip = br.ip + br.len (fallthrough = 0x100E = CMP), target_fallthrough = br.target (0x1015).
        # So CMP at 0x100E, JE at 0x1015, JE.target must == JS.target == 0x1015.
        # But JE.target == JE.ip means JE jumps to itself which is odd; the
        # detector only checks JE.near_branch_target == target_fallthrough.
        # Layout below sets JS.target = 0x101B so JE can target 0x101B cleanly.
        #   0x1000: call (5B)
        #   0x1005: test (3B)
        #   0x1008: js   (6B) target=0x101B fallthrough=0x100E
        #   0x100E: cmp  (7B) -> 0x1015
        #   0x1015: je   (6B) target=0x101B (= JS.target)
        ctx = _build_image(64, self.FUNC, [
            call_rel64(self.TARGET),
            _test_rm64_r64(Register.RAX, Register.RAX),
            js_rel64(0x101B),
            cmp_r64_rm64(Register.RAX, rip_mem(0x63C)),
            je_rel64(0x101B),
        ])
        r = local_only_patch(ctx, start_rva=self.FUNC, target_rva=self.TARGET)
        assert r is not None
        assert "LocalOnlyPatch.x64=1" in r.lines

    def test_no_call_to_target_returns_none(self):
        """When the CALL doesn't target the requested function, no match."""
        ctx = _build_image(64, self.FUNC, [
            call_rel64(0x9999),  # wrong target
            _test_rm64_r64(Register.RAX, Register.RAX),
            jns_rel64(0x1014),
            nop(), nop(), nop(), nop(), nop(), nop(),
            cmp_r64_rm64(Register.RAX, rip_mem(0x63C)),
            je_rel64(0x100E),
        ])
        r = local_only_patch(ctx, start_rva=self.FUNC, target_rva=self.TARGET)
        assert r is None

    def test_missing_test_returns_none(self):
        """CALL directly followed by a non-TEST instruction (not MOV) fails."""
        ctx = _build_image(64, self.FUNC, [
            call_rel64(self.TARGET),
            jns_rel64(0x1014),  # no TEST in between
            nop(),
            cmp_r64_rm64(Register.RAX, rip_mem(0x63C)),
            je_rel64(0x100E),
        ])
        r = local_only_patch(ctx, start_rva=self.FUNC, target_rva=self.TARGET)
        assert r is None

    def test_wrong_branch_returns_none(self):
        """Jcc that isn't JNS/JS after TEST → no match."""
        ctx = _build_image(64, self.FUNC, [
            call_rel64(self.TARGET),
            _test_rm64_r64(Register.RAX, Register.RAX),
            je_rel64(0x1014),  # JE instead of JNS/JS
            nop(),
            cmp_r64_rm64(Register.RAX, rip_mem(0x63C)),
            je_rel64(0x100E),
        ])
        r = local_only_patch(ctx, start_rva=self.FUNC, target_rva=self.TARGET)
        assert r is None

    def test_je_target_mismatch_returns_none(self):
        """JE doesn't jump back to JNS fallthrough → no match."""
        ctx = _build_image(64, self.FUNC, [
            call_rel64(self.TARGET),
            _test_rm64_r64(Register.RAX, Register.RAX),
            jns_rel64(0x1014),
            nop(), nop(), nop(), nop(), nop(), nop(),
            cmp_r64_rm64(Register.RAX, rip_mem(0x63C)),
            je_rel64(0x1021),  # wrong target (should be 0x100E)
        ])
        r = local_only_patch(ctx, start_rva=self.FUNC, target_rva=self.TARGET)
        assert r is None


# ===========================================================================
# def_policy_patch
# ===========================================================================
#
# Two main shapes recognized:
# (A) Direct CMP [reg+0x63C], reg2  (or swapped CMP reg2, [reg+0x320])
#     followed by JE/JNE/POP.
# (B) x64 alias chain: MOV reg, [base+0x63C] → alias copies →
#     MOV reg2, [alias_base+0x638] → CMP reg, reg2 → JE/JNE.

class TestDefPolicyPatch:
    FUNC = 0x1000

    def test_direct_cmp_63c_with_je(self):
        """CMP [RCX+0x63C], RAX followed by JE → matched, offset = CMP ip."""
        mem = MemoryOperand(base=Register.RCX, displ=0x63C)
        ctx = _build_image(64, self.FUNC, [
            cmp_rm64_r64(mem, Register.RAX),
            je_rel64(self.FUNC + 0x20),
        ])
        r = def_policy_patch(ctx, start_rva=self.FUNC)
        assert r is not None
        assert "DefPolicyPatch.x64=1" in r.lines
        # 64-bit regs → "rax"/"rcx" lowercase. No _jmp suffix (JE not JNE).
        assert "DefPolicyCode.x64=CDefPolicy_Query_rax_rcx" in r.lines
        assert f"DefPolicyOffset.x64={self.FUNC:X}" in r.lines

    def test_direct_cmp_63c_with_jne_adds_jmp_suffix(self):
        """JNE after CMP → code suffix '_jmp'."""
        mem = MemoryOperand(base=Register.RCX, displ=0x63C)
        ctx = _build_image(64, self.FUNC, [
            cmp_rm64_r64(mem, Register.RAX),
            jne_rel64(self.FUNC + 0x20),
        ])
        r = def_policy_patch(ctx, start_rva=self.FUNC)
        assert r is not None
        assert "DefPolicyCode.x64=CDefPolicy_Query_rax_rcx_jmp" in r.lines

    def test_direct_cmp_320_swapped_operands(self):
        """CMP RAX, [RCX+0x320] (operands swapped) → matched."""
        mem = MemoryOperand(base=Register.RCX, displ=0x320)
        ctx = _build_image(64, self.FUNC, [
            cmp_r64_rm64(Register.RAX, mem),
            je_rel64(self.FUNC + 0x20),
        ])
        r = def_policy_patch(ctx, start_rva=self.FUNC)
        assert r is not None
        # reg1 = RAX (op0), reg2 = RCX (memory_base).
        assert "DefPolicyCode.x64=CDefPolicy_Query_rax_rcx" in r.lines

    def test_no_followup_jcc_returns_none(self):
        """CMP [RCX+0x63C], RAX not followed by JE/JNE/POP → no match."""
        mem = MemoryOperand(base=Register.RCX, displ=0x63C)
        ctx = _build_image(64, self.FUNC, [
            cmp_rm64_r64(mem, Register.RAX),
            nop(),  # wrong follow-up
        ])
        r = def_policy_patch(ctx, start_rva=self.FUNC)
        assert r is None

    def test_wrong_displacement_returns_none(self):
        """CMP [RCX+0x999], RAX (wrong disp) → no match."""
        mem = MemoryOperand(base=Register.RCX, displ=0x999)
        ctx = _build_image(64, self.FUNC, [
            cmp_rm64_r64(mem, Register.RAX),
            je_rel64(self.FUNC + 0x20),
        ])
        r = def_policy_patch(ctx, start_rva=self.FUNC)
        assert r is None

    def test_jne_with_preceding_mov_638_uses_mov_offset(self):
        """When CMP is JNE and preceded by MOV reg,[base+0x638] (same dest reg
        as CMP's operand), the offset points at the MOV, not the CMP."""
        mem638 = MemoryOperand(base=Register.RCX, displ=0x638)
        mem63c = MemoryOperand(base=Register.RCX, displ=0x63C)
        ctx = _build_image(64, self.FUNC, [
            mov_r64_rm64(Register.RAX, mem638),
            cmp_rm64_r64(mem63c, Register.RAX),
            jne_rel64(self.FUNC + 0x40),
        ])
        r = def_policy_patch(ctx, start_rva=self.FUNC)
        assert r is not None
        assert "DefPolicyCode.x64=CDefPolicy_Query_rax_rcx_jmp" in r.lines
        # Offset = MOV's RVA (first instruction = FUNC).
        assert f"DefPolicyOffset.x64={self.FUNC:X}" in r.lines


# ===========================================================================
# single_user_patch
# ===========================================================================
#
# Two detection paths:
# (1) Find a CALL to memset IAT slot, then scan forward for either:
#     - CALL to VerifyVersionInfoW IAT slot → "mov_eax_1[_nop_N]" / "pop_eax_add_esp_12[_nop_N]"
#     - CMP [RBP/RSP], imm/reg → "nop_N"
# (2) If no memset-led match, scan for any CALL to VerifyVersionInfoW.

class TestSingleUserPatch:
    FUNC = 0x1000
    MEMSET_IAT = 0x3000
    VERIFY_IAT = 0x3008

    def _iat_call_x64(self, iat_rva: int) -> Instruction:
        """x64 CALL [RIP+disp] pointing at the IAT slot at iat_rva."""
        return Instruction.create_mem(Code.CALL_RM64, rip_mem(iat_rva))

    def _iat_call_x86(self, iat_rva: int) -> Instruction:
        """x86 CALL [disp32] pointing at the IAT slot at iat_rva."""
        return Instruction.create_mem(Code.CALL_RM32, MemoryOperand(displ=iat_rva))

    def test_memset_then_verifyversion_x64(self):
        """CALL [memset] → CALL [VerifyVersionInfoW] → mov_eax_1_nop_N."""
        ctx = _build_image(64, self.FUNC, [
            self._iat_call_x64(self.MEMSET_IAT),
            self._iat_call_x64(self.VERIFY_IAT),
        ])
        r = single_user_patch(
            ctx, start_rva=self.FUNC,
            memset_target_rva=self.MEMSET_IAT,
            verifyversion_iat_rva=self.VERIFY_IAT,
            direct_call=False,
        )
        assert r is not None
        assert "SingleUserPatch.x64=1" in r.lines
        # VerifyVersionInfoW CALL is 6 bytes (FF 15 + disp32); n = max(0, 6-5) = 1.
        assert "SingleUserCode.x64=mov_eax_1_nop_1" in r.lines

    def test_memset_then_cmp_rbp_reg_x64(self):
        """CALL [memset] → CMP [RBP+disp], reg → nop_N.

        Uses a register operand (not immediate) because iced-x86 represents
        sign-extended imm8 operands with a distinct OpKind that the detector
        doesn't list. The REGISTER path is the common real-world case anyway.
        single_user_patch requires CMP to be followed by a validating pattern
        (see _is_valid_single_user_cmp): either JE/JNE + MOV, or MOV [mem], reg.
        We append ``MOV [RBP+0x18], RAX`` to satisfy the second shape.
        """
        from _asmharness import mov_rm64_r64
        ctx = _build_image(64, self.FUNC, [
            self._iat_call_x64(self.MEMSET_IAT),
            cmp_rm64_r64(MemoryOperand(base=Register.RBP, displ=0x10), Register.RAX),
            mov_rm64_r64(MemoryOperand(base=Register.RBP, displ=0x18), Register.RAX),
            nop(),  # _is_valid_single_user_cmp requires 2 instructions after CMP
        ])
        r = single_user_patch(
            ctx, start_rva=self.FUNC,
            memset_target_rva=self.MEMSET_IAT,
            verifyversion_iat_rva=None,
            direct_call=False,
        )
        assert r is not None
        assert "SingleUserPatch.x64=1" in r.lines
        assert any(line.startswith("SingleUserCode.x64=nop_") for line in r.lines)

    def test_verifyversion_only_x64(self):
        """No memset CALL, but VerifyVersionInfoW CALL present → fallback path."""
        ctx = _build_image(64, self.FUNC, [
            nop(),
            self._iat_call_x64(self.VERIFY_IAT),
        ])
        r = single_user_patch(
            ctx, start_rva=self.FUNC,
            memset_target_rva=self.MEMSET_IAT,
            verifyversion_iat_rva=self.VERIFY_IAT,
            direct_call=False,
        )
        assert r is not None
        assert "SingleUserPatch.x64=1" in r.lines

    def test_no_relevant_calls_returns_none(self):
        """Neither memset nor VerifyVersionInfoW CALL → no match."""
        ctx = _build_image(64, self.FUNC, [
            nop(),
            Instruction.create_reg_reg(Code.XOR_R64_RM64, Register.RAX, Register.RAX),
            nop(),
        ])
        r = single_user_patch(
            ctx, start_rva=self.FUNC,
            memset_target_rva=self.MEMSET_IAT,
            verifyversion_iat_rva=self.VERIFY_IAT,
            direct_call=False,
        )
        assert r is None

    def test_x86_pop_eax_add_esp_12_path(self):
        """x86: CALL [VerifyVersionInfoW] → pop_eax_add_esp_12[_nop_N]."""
        memset_iat32 = 0x3000
        verify_iat32 = 0x3008
        ctx = _build_image(32, self.FUNC, [
            self._iat_call_x86(memset_iat32),
            self._iat_call_x86(verify_iat32),
        ])
        r = single_user_patch(
            ctx, start_rva=self.FUNC,
            memset_target_rva=memset_iat32,
            verifyversion_iat_rva=verify_iat32,
            direct_call=False,
        )
        assert r is not None
        assert "SingleUserPatch.x86=1" in r.lines
        # x86 CALL [disp32] is 6 bytes; n = max(0, 6-4) = 2.
        assert "SingleUserCode.x86=pop_eax_add_esp_12_nop_2" in r.lines
