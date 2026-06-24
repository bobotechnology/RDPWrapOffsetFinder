"""Tests for nosymbol.py's architecture-specific xref helpers.

These are the low-level functions that scan a function body for an instruction
referencing a target RVA — the core of the "no symbols" reverse-engineering
approach. x64 uses LEA/MOV with RIP-relative addressing; x86 uses PUSH/MOV with
absolute immediate32.
"""
from __future__ import annotations

import pytest
from iced_x86 import Code, Instruction, MemoryOperand, Register

from _asmharness import (
    TEST_IMAGE_BASE,
    asm,
    call_rel64,
    lea_r64_m,
    lea_r32_m,
    make_image,
    mov_r32_imm32,
    mov_r64_imm64,
    mov_rm32_imm32,
    place_code,
    rip_mem,
)
from iced_x86 import Decoder, Mnemonic, OpKind
import sys
sys.path.insert(0, ".")

from nosymbol import _xref_imm32_x86, _xref_lea_rip


# ---------------------------------------------------------------------------
# _xref_lea_rip (x64)
# ---------------------------------------------------------------------------

class TestXrefLeaRip:
    FUNC = 0x1000
    TARGET = 0x5000  # target RVA the LEA points at

    def _build_and_scan(self, instructions, func_len_override=None):
        code = asm(64, instructions, rip=TEST_IMAGE_BASE + self.FUNC)
        img = make_image(0x8000)
        place_code(img, self.FUNC, code)
        func_len = func_len_override or len(code)
        return _xref_lea_rip(
            image=bytes(img),
            image_base=TEST_IMAGE_BASE,
            bitness=64,
            func_rva=self.FUNC,
            func_len=func_len,
            target_rva=self.TARGET,
        )

    def test_lea_matching_target_returns_xref(self):
        """LEA RCX, [RIP+disp] pointing at target → returns the instruction's
        next_ip (i.e. the RVA just past the LEA)."""
        xref = self._build_and_scan([
            lea_r64_m(Register.RCX, rip_mem(self.TARGET)),
        ])
        assert xref is not None
        # LEA is 7 bytes; next_ip = FUNC + 7.
        assert xref == self.FUNC + 7

    def test_lea_wrong_target_returns_none(self):
        xref = self._build_and_scan([
            lea_r64_m(Register.RCX, rip_mem(0x9999)),  # wrong target
        ])
        assert xref is None

    def test_mov_reg_imm_matching_target_returns_xref(self):
        """MOV reg, imm64 with imm == target VA → also recognized."""
        # image_base=0 so target VA == target RVA.
        xref = self._build_and_scan([
            mov_r64_imm64(Register.RAX, TEST_IMAGE_BASE + self.TARGET),
        ])
        assert xref is not None
        # MOV r64, imm64 is 10 bytes (REX.W + B8+rd + imm64).
        assert xref == self.FUNC + 10

    def test_lea_not_first_instruction(self):
        """LEA can appear after other instructions; scan is linear."""
        xref = self._build_and_scan([
            Instruction.create(Code.NOPD),
            Instruction.create(Code.NOPD),
            lea_r64_m(Register.RCX, rip_mem(self.TARGET)),
        ])
        assert xref is not None
        # 2 NOPs (1B each) + LEA (7B) → next_ip = FUNC + 9.
        assert xref == self.FUNC + 9

    def test_empty_function_returns_none(self):
        xref = self._build_and_scan([])
        assert xref is None


# ---------------------------------------------------------------------------
# _xref_imm32_x86 (x86)
# ---------------------------------------------------------------------------

class TestXrefImm32X86:
    FUNC = 0x1000
    TARGET = 0x5000

    def _build_and_scan(self, instructions, *, allow_mem=False):
        code = asm(32, instructions, rip=TEST_IMAGE_BASE + self.FUNC)
        img = make_image(0x8000)
        place_code(img, self.FUNC, code)
        return _xref_imm32_x86(
            image=bytes(img),
            image_base=TEST_IMAGE_BASE,
            func_rva=self.FUNC,
            func_len=len(code),
            target_rva=self.TARGET,
            allow_mem=allow_mem,
        )

    def test_push_imm32_matching_target_returns_xref(self):
        """PUSH imm32 with value == target VA → recognized."""
        from _asmharness import push_imm32_x86
        xref = self._build_and_scan([
            push_imm32_x86(TEST_IMAGE_BASE + self.TARGET),
        ])
        assert xref is not None
        # PUSH imm32 is 5 bytes; next_ip = FUNC + 5.
        assert xref == self.FUNC + 5

    def test_mov_reg_imm32_matching_target_returns_xref(self):
        xref = self._build_and_scan([
            mov_r32_imm32(Register.EAX, TEST_IMAGE_BASE + self.TARGET),
        ])
        assert xref is not None
        # MOV r32, imm32 is 5 bytes (B8+rd + imm32).
        assert xref == self.FUNC + 5

    def test_wrong_target_returns_none(self):
        from _asmharness import push_imm32_x86
        xref = self._build_and_scan([
            push_imm32_x86(0x9999),  # wrong target
        ])
        assert xref is None

    def test_no_matching_instruction_returns_none(self):
        xref = self._build_and_scan([
            Instruction.create(Code.NOPD),
            Instruction.create(Code.NOPD),
        ])
        assert xref is None

    # --- MOV [mem], imm32 pattern (allow_mem=True fallback) ---------------

    def test_mov_mem_imm32_with_allow_mem_returns_xref(self):
        """MOV dword [ebp-10h], imm32 with allow_mem=True → recognized.

        This is the pattern used by x86 termsrv.dll 10.0.19041.6456 where
        string addresses are stored in local variables rather than pushed
        or loaded into registers directly.
        """
        mem = MemoryOperand(base=Register.EBP, displ=-0x10)
        xref = self._build_and_scan([
            mov_rm32_imm32(mem, TEST_IMAGE_BASE + self.TARGET),
        ], allow_mem=True)
        assert xref is not None
        # MOV r/m32, imm32 with [ebp-10h] = C7 45 F0 + imm32 = 7 bytes.
        assert xref == self.FUNC + 7

    def test_mov_mem_imm32_without_allow_mem_returns_none(self):
        """Same instruction with allow_mem=False (default) → not matched.

        This ensures backward compatibility: strict pass does not match
        MOV [mem], imm32, preventing false positives in large functions.
        """
        mem = MemoryOperand(base=Register.EBP, displ=-0x10)
        xref = self._build_and_scan([
            mov_rm32_imm32(mem, TEST_IMAGE_BASE + self.TARGET),
        ], allow_mem=False)
        assert xref is None

    def test_mov_mem_imm32_wrong_target_returns_none(self):
        """MOV [mem], imm32 with wrong immediate → not matched even with
        allow_mem=True."""
        mem = MemoryOperand(base=Register.EBP, displ=-0x10)
        xref = self._build_and_scan([
            mov_rm32_imm32(mem, 0x9999),
        ], allow_mem=True)
        assert xref is None

    def test_mov_mem_imm32_after_nop_returns_correct_xref(self):
        """MOV [mem], imm32 after other instructions → correct next_ip."""
        mem = MemoryOperand(base=Register.EBP, displ=-0x10)
        xref = self._build_and_scan([
            Instruction.create(Code.NOPD),
            Instruction.create(Code.NOPD),
            mov_rm32_imm32(mem, TEST_IMAGE_BASE + self.TARGET),
        ], allow_mem=True)
        assert xref is not None
        # 2 NOPs (1B each) + MOV (7B) → next_ip = FUNC + 9.
        assert xref == self.FUNC + 9
