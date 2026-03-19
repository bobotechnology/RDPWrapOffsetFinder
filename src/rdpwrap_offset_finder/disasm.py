from __future__ import annotations

from dataclasses import dataclass

from iced_x86 import Decoder, OpKind, Register


_REG_VALUE_TO_NAME: dict[int, str] | None = None


def _reg_value_to_name() -> dict[int, str]:
    global _REG_VALUE_TO_NAME
    if _REG_VALUE_TO_NAME is None:
        # iced_x86.Register is a module exporting int constants (RAX, EAX, ...).
        m: dict[int, str] = {}
        for k, v in Register.__dict__.items():
            if not k or not k[0].isupper():
                continue
            if isinstance(v, int):
                m[v] = k
        _REG_VALUE_TO_NAME = m
    return _REG_VALUE_TO_NAME


@dataclass(frozen=True)
class DisasmContext:
    bitness: int  # 32 or 64
    image_base: int  # VA
    image: bytes  # memory-mapped image (SizeOfImage bytes)

    def va_to_rva(self, va: int) -> int:
        return va - self.image_base

    def rva_to_va(self, rva: int) -> int:
        return self.image_base + rva


def decode_linear(ctx: DisasmContext, start_va: int, max_len: int) -> list:
    """Decode up to max_len bytes starting at start_va."""

    rva = ctx.va_to_rva(start_va)
    if rva < 0:
        return []
    data = ctx.image[rva:rva + max_len]
    dec = Decoder(ctx.bitness, data, ip=start_va)
    return list(dec)


def mem_effective_va(insn) -> int | None:
    """Return effective VA for RIP/EIP-relative memory operands when possible."""
    if insn.op0_kind == OpKind.MEMORY and insn.memory_base in (Register.RIP, Register.EIP):
        return int(insn.ip_rel_memory_address)
    if insn.op1_kind == OpKind.MEMORY and insn.memory_base in (Register.RIP, Register.EIP):
        return int(insn.ip_rel_memory_address)
    return None


def mem_effective_rva(ctx: DisasmContext, insn) -> int | None:
    """Return effective RVA for RIP/EIP-relative memory operands when possible."""
    va = mem_effective_va(insn)
    if va is None:
        return None
    return ctx.va_to_rva(va)


def reg_name(reg_val: int) -> str:
    """Convert register value to name (e.g. 162 -> 'RCX')."""
    return _reg_value_to_name().get(reg_val, f"<reg{reg_val}>")
