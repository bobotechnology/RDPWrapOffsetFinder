"""Shared helpers for building synthetic PE images and instruction sequences
in tests, so we can exercise the disassembly-driven code paths without
requiring a real termsrv.dll fixture.

Design notes
------------
- We use iced-x86's ``Encoder`` (not ``BlockEncoder``) and encode each
  instruction individually. ``BlockEncoder`` silently shortens branches to
  rel8 when the target is in range, which shifts all subsequent addresses and
  breaks tests that hard-code expected RVAs. ``Encoder`` respects the exact
  ``Code`` enum we pass (e.g. ``JNS_REL32_64`` stays 6 bytes), giving us
  deterministic layouts.
- When a ``MemoryOperand`` uses ``Register.RIP`` as base, the ``displ`` is
  treated as the *target absolute address* and the encoder computes the
  correct RIP-relative displacement. Setting the image base to 0 makes
  ``ip_rel_memory_address`` equal the RVA directly, which keeps assertions
  readable.
"""
from __future__ import annotations

from typing import Iterable

from iced_x86 import Code, Encoder, Instruction, MemoryOperand, Register

# Sentinel image base used by every test. Keeping it at 0 means VA == RVA,
# which makes Encoder's RIP-relative target == RVA directly.
TEST_IMAGE_BASE = 0
TEST_BITNESS_64 = 64
TEST_BITNESS_32 = 32


def asm(bitness: int, instructions: Iterable[Instruction], rip: int) -> bytes:
    """Encode instructions starting at ``rip`` and return concatenated bytes.

    Each instruction is encoded independently via ``Encoder`` so the exact
    ``Code`` enum is honored (no rel8 shortening). ``rip`` is advanced by the
    encoded length of each instruction so RIP-relative operands resolve to the
    intended absolute target.
    """
    enc = Encoder(bitness)
    ip = rip
    chunks: list[bytes] = []
    for instr in instructions:
        enc.encode(instr, ip)
        chunk = enc.take_buffer()
        chunks.append(chunk)
        ip += len(chunk)
    return b"".join(chunks)


def rip_mem(target_rva: int, base: int = Register.RIP) -> MemoryOperand:
    """RIP-relative memory operand pointing at ``target_rva`` (absolute = RVA
    because the test image base is 0)."""
    return MemoryOperand(base=base, displ=target_rva)


# --- Common instruction factories (64-bit variants) ------------------------

def call_rel64(target_va: int) -> Instruction:
    return Instruction.create_branch(Code.CALL_REL32_64, target_va)


def call_rm64(mem: MemoryOperand) -> Instruction:
    return Instruction.create_mem(Code.CALL_RM64, mem)


def jmp_rel64(target_va: int) -> Instruction:
    return Instruction.create_branch(Code.JMP_REL32_64, target_va)


def jns_rel64(target_va: int) -> Instruction:
    return Instruction.create_branch(Code.JNS_REL32_64, target_va)


def js_rel64(target_va: int) -> Instruction:
    return Instruction.create_branch(Code.JS_REL32_64, target_va)


def je_rel64(target_va: int) -> Instruction:
    return Instruction.create_branch(Code.JE_REL32_64, target_va)


def jne_rel64(target_va: int) -> Instruction:
    return Instruction.create_branch(Code.JNE_REL32_64, target_va)


def test_rm64_r64(reg1: int, reg2: int) -> Instruction:
    return Instruction.create_reg_reg(Code.TEST_RM64_R64, reg1, reg2)


def test_rm32_r32(reg1: int, reg2: int) -> Instruction:
    return Instruction.create_reg_reg(Code.TEST_RM32_R32, reg1, reg2)


def cmp_rm64_r64(mem: MemoryOperand, reg: int) -> Instruction:
    return Instruction.create_mem_reg(Code.CMP_RM64_R64, mem, reg)


def cmp_rm32_r32(mem: MemoryOperand, reg: int) -> Instruction:
    return Instruction.create_mem_reg(Code.CMP_RM32_R32, mem, reg)


def cmp_r64_rm64(reg: int, mem: MemoryOperand) -> Instruction:
    return Instruction.create_reg_mem(Code.CMP_R64_RM64, reg, mem)


def cmp_r32_rm32(reg: int, mem: MemoryOperand) -> Instruction:
    return Instruction.create_reg_mem(Code.CMP_R32_RM32, reg, mem)


def mov_r64_rm64(reg: int, mem: MemoryOperand) -> Instruction:
    return Instruction.create_reg_mem(Code.MOV_R64_RM64, reg, mem)


def mov_r32_rm32(reg: int, mem: MemoryOperand) -> Instruction:
    return Instruction.create_reg_mem(Code.MOV_R32_RM32, reg, mem)


def mov_rm64_r64(mem: MemoryOperand, reg: int) -> Instruction:
    return Instruction.create_mem_reg(Code.MOV_RM64_R64, mem, reg)


def mov_rm32_r32(mem: MemoryOperand, reg: int) -> Instruction:
    return Instruction.create_mem_reg(Code.MOV_RM32_R32, mem, reg)


def mov_r64_r64(dst: int, src: int) -> Instruction:
    return Instruction.create_reg_reg(Code.MOV_RM64_R64, dst, src)


def lea_r64_m(reg: int, mem: MemoryOperand) -> Instruction:
    return Instruction.create_reg_mem(Code.LEA_R64_M, reg, mem)


def lea_r32_m(reg: int, mem: MemoryOperand) -> Instruction:
    return Instruction.create_reg_mem(Code.LEA_R32_M, reg, mem)


def push_imm32_x86(value: int) -> Instruction:
    # PUSH imm32 — use PUSHD_IMM32 for 32-bit mode, PUSHQ_IMM32 for 64-bit.
    # The caller picks the right one via the bitness parameter; here we default
    # to the 32-bit form since this helper is used in x86 tests.
    return Instruction.create_i32(Code.PUSHD_IMM32, value)


def mov_r32_imm32(reg: int, value: int) -> Instruction:
    return Instruction.create_reg_i32(Code.MOV_R32_IMM32, reg, value)


def mov_r64_imm64(reg: int, value: int) -> Instruction:
    return Instruction.create_reg_i64(Code.MOV_R64_IMM64, reg, value)


def nop() -> Instruction:
    """Single-byte NOP (0x90)."""
    return Instruction.create(Code.NOPD)


def raw_byte(b: int) -> Instruction:
    """Emit a single literal byte (via declare_byte)."""
    return Instruction.create_declare_byte_1(b & 0xFF)


def place_code(image: bytearray, rva: int, code: bytes) -> None:
    """Write ``code`` bytes into ``image`` at ``rva``, growing the image if
    necessary (zero-filled)."""
    end = rva + len(code)
    if end > len(image):
        image.extend(b"\x00" * (end - len(image)))
    image[rva:rva + len(code)] = code


def make_image(size: int = 0x10000) -> bytearray:
    """Allocate a zeroed image buffer."""
    return bytearray(size)
