from __future__ import annotations

from dataclasses import dataclass

from iced_x86 import Mnemonic, OpKind, Register

from .disasm import DisasmContext, decode_linear, reg_name


@dataclass(frozen=True)
class PatchResult:
    lines: list[str]

    def to_text(self) -> str:
        return "\n".join(self.lines) + ("\n" if self.lines else "")


def _is_rel_call_to(insn, target_va: int) -> bool:
    return (
        insn.mnemonic == Mnemonic.CALL
        and insn.op0_kind in (OpKind.NEAR_BRANCH32, OpKind.NEAR_BRANCH64)
        and insn.near_branch_target == target_va
    )


def local_only_patch(ctx: DisasmContext, start_rva: int, target_rva: int) -> PatchResult | None:
    start_va = ctx.rva_to_va(start_rva)
    target_va = ctx.rva_to_va(target_rva)
    insns = decode_linear(ctx, start_va, 256)

    for i, insn in enumerate(insns):
        if not _is_rel_call_to(insn, target_va):
            continue

        j = i + 1
        while j < len(insns) and insns[j].mnemonic == Mnemonic.MOV:
            j += 1
        if j >= len(insns) or insns[j].mnemonic != Mnemonic.TEST:
            return None
        j += 1
        if j >= len(insns):
            return None

        br = insns[j]
        if not br.is_jcc_short_or_near or br.op0_kind not in (OpKind.NEAR_BRANCH32, OpKind.NEAR_BRANCH64):
            return None

        if br.mnemonic == Mnemonic.JNS:
            ip = br.near_branch_target
            target_fallthrough = br.ip + br.len
        elif br.mnemonic == Mnemonic.JS:
            ip = br.ip + br.len
            target_fallthrough = br.near_branch_target
        else:
            return None

        by_ip = {x.ip: x for x in insns}
        cmp_insn = by_ip.get(ip)
        if not cmp_insn or cmp_insn.mnemonic != Mnemonic.CMP:
            return None
        next_ip = cmp_insn.next_ip
        jcc2 = by_ip.get(next_ip)
        if not jcc2 or jcc2.mnemonic not in (Mnemonic.JE,):
            return None
        if jcc2.near_branch_target != target_fallthrough:
            return None

        jmp = "nopjmp" if jcc2.len > 2 else "jmpshort"
        off_rva = int(jcc2.ip - ctx.image_base)
        arch = "x64" if ctx.bitness == 64 else "x86"
        return PatchResult(
            lines=[
                f"LocalOnlyPatch.{arch}=1",
                f"LocalOnlyOffset.{arch}={off_rva:X}",
                f"LocalOnlyCode.{arch}={jmp}",
            ]
        )
    return None


def def_policy_patch(ctx: DisasmContext, start_rva: int) -> PatchResult | None:
    start_va = ctx.rva_to_va(start_rva)
    insns = decode_linear(ctx, start_va, 128)
    mov_base = Register.NONE
    mov_target = Register.NONE
    last_len = 0

    for idx, insn in enumerate(insns):
        if insn.mnemonic == Mnemonic.CMP and insn.op_count >= 2:
            reg1 = reg2 = None

            if insn.op0_kind == OpKind.MEMORY and insn.memory_displacement == 0x63C and insn.op1_kind == OpKind.REGISTER:
                reg1 = reg_name(insn.op1_register)
                reg2 = reg_name(insn.memory_base)
            elif insn.op1_kind == OpKind.MEMORY and insn.memory_displacement == 0x320 and insn.op0_kind == OpKind.REGISTER:
                reg1 = reg_name(insn.op0_register)
                reg2 = reg_name(insn.memory_base)

            if reg1 and reg2:
                if idx + 1 >= len(insns):
                    return None
                nxt = insns[idx + 1]
                suffix = ""
                ip_for_offset = insn.ip
                if nxt.mnemonic == Mnemonic.JNE:
                    ip_for_offset = insn.ip - last_len
                    suffix = "_jmp"
                elif nxt.mnemonic not in (Mnemonic.JE, Mnemonic.POP):
                    return None

                arch = "x64" if ctx.bitness == 64 else "x86"
                off_rva = int(ip_for_offset - ctx.image_base)
                return PatchResult(
                    lines=[
                        f"DefPolicyPatch.{arch}=1",
                        f"DefPolicyOffset.{arch}={off_rva:X}",
                        f"DefPolicyCode.{arch}=CDefPolicy_Query_{reg1.lower()}_{reg2.lower()}{suffix}",
                    ]
                )

        if ctx.bitness == 64 and mov_base == Register.NONE and insn.mnemonic == Mnemonic.MOV and \
           insn.op0_kind == OpKind.REGISTER and insn.op1_kind == OpKind.MEMORY and insn.memory_displacement == 0x63C:
            mov_base = insn.memory_base
            mov_target = insn.op0_register
        elif ctx.bitness == 64 and mov_base != Register.NONE and insn.mnemonic == Mnemonic.MOV and \
             insn.op0_kind == OpKind.REGISTER and insn.op1_kind == OpKind.MEMORY and \
             insn.memory_base == mov_base and insn.memory_displacement == 0x638:
            mov_target2 = insn.op0_register
            for k in range(idx + 1, len(insns)):
                cmpi = insns[k]
                if cmpi.mnemonic == Mnemonic.CMP and cmpi.op0_kind == OpKind.REGISTER and cmpi.op1_kind == OpKind.REGISTER:
                    if (cmpi.op0_register == mov_target and cmpi.op1_register == mov_target2) or \
                       (cmpi.op0_register == mov_target2 and cmpi.op1_register == mov_target):
                        if k + 1 >= len(insns):
                            return None
                        nxt = insns[k + 1]
                        suffix = ""
                        ip_for_offset = insn.ip
                        if nxt.mnemonic == Mnemonic.JNE:
                            ip_for_offset = insn.ip - last_len
                            suffix = "_jmp"
                        elif nxt.mnemonic not in (Mnemonic.JE, Mnemonic.POP):
                            return None

                        reg1 = reg_name(mov_target2)
                        reg2 = reg_name(mov_base)
                        off_rva = int(ip_for_offset - ctx.image_base)
                        return PatchResult(
                            lines=[
                                "DefPolicyPatch.x64=1",
                                f"DefPolicyOffset.x64={off_rva:X}",
                                f"DefPolicyCode.x64=CDefPolicy_Query_{reg1.lower()}_{reg2.lower()}{suffix}",
                            ]
                        )

        last_len = insn.len
    return None


def single_user_patch(
    ctx: DisasmContext,
    start_rva: int,
    memset_target_rva: int,
    verifyversion_iat_rva: int | None,
    *,
    direct_call: bool,
) -> PatchResult | None:
    start_va = ctx.rva_to_va(start_rva)
    insns = decode_linear(ctx, start_va, 2048)
    if not insns:
        return None

    memset_target_va = ctx.rva_to_va(memset_target_rva)
    verify_slot_va = ctx.rva_to_va(verifyversion_iat_rva) if verifyversion_iat_rva else None

    def _call_hits_iat_slot(call_insn, slot_va: int) -> bool:
        if call_insn.mnemonic != Mnemonic.CALL:
            return False

        if call_insn.op0_kind == OpKind.MEMORY:
            if ctx.bitness == 64 and call_insn.memory_base == Register.RIP:
                return call_insn.is_ip_rel_memory_operand and call_insn.ip_rel_memory_address == slot_va
            if ctx.bitness == 32 and call_insn.memory_segment == Register.DS and call_insn.memory_base == Register.NONE:
                return call_insn.memory_displacement == slot_va
            return False

        if call_insn.op0_kind in (OpKind.NEAR_BRANCH32, OpKind.NEAR_BRANCH64):
            stub_va = call_insn.near_branch_target
            stub_insns = decode_linear(ctx, stub_va, 16)
            if not stub_insns:
                return False
            jmp = stub_insns[0]
            if jmp.mnemonic != Mnemonic.JMP or jmp.op0_kind != OpKind.MEMORY:
                return False
            if ctx.bitness == 64:
                if jmp.memory_base != Register.RIP:
                    return False
                return jmp.is_ip_rel_memory_operand and jmp.ip_rel_memory_address == slot_va
            if jmp.memory_segment != Register.DS or jmp.memory_base != Register.NONE:
                return False
            return jmp.memory_displacement == slot_va

        return False

    def _is_valid_single_user_cmp(cmp_idx: int) -> bool:
        if cmp_idx + 2 >= len(insns):
            return False
        next1 = insns[cmp_idx + 1]
        next2 = insns[cmp_idx + 2]
        if next1.mnemonic in (Mnemonic.JNE, Mnemonic.JE):
            if next2.mnemonic == Mnemonic.MOV and next2.op0_kind == OpKind.MEMORY:
                if next2.memory_base in (Register.RDI, Register.RBP, Register.RSP) or next2.op1_kind == OpKind.REGISTER:
                    return True
        if next1.mnemonic == Mnemonic.MOV and next1.op0_kind == OpKind.MEMORY and next1.op1_kind == OpKind.REGISTER:
            return True
        return False

    def _scan_forward_from(idx: int) -> PatchResult | None:
        for j in range(idx + 1, len(insns)):
            x = insns[j]
            if ctx.bitness == 64:
                if verify_slot_va is not None and _call_hits_iat_slot(x, verify_slot_va):
                    n = max(0, x.len - 5)
                    code_type = "mov_eax_1" if n == 0 else f"mov_eax_1_nop_{n}"
                    off_rva = int(x.ip - ctx.image_base)
                    return PatchResult(
                        lines=[
                            "SingleUserPatch.x64=1",
                            f"SingleUserOffset.x64={off_rva:X}",
                            f"SingleUserCode.x64={code_type}",
                        ]
                    )
                if x.mnemonic == Mnemonic.CMP and x.len <= 8 and x.op0_kind == OpKind.MEMORY and \
                   x.memory_base in (Register.RBP, Register.RSP):
                    if x.op1_kind == OpKind.IMMEDIATE8 and x.immediate8 == 1 or \
                       x.op1_kind == OpKind.IMMEDIATE32 and x.immediate32 == 1 or \
                       x.op1_kind == OpKind.REGISTER:
                        if not _is_valid_single_user_cmp(j):
                            continue
                        off_rva = int(x.ip - ctx.image_base)
                        return PatchResult(
                            lines=[
                                "SingleUserPatch.x64=1",
                                f"SingleUserOffset.x64={off_rva:X}",
                                f"SingleUserCode.x64=nop_{x.len}",
                            ]
                        )
            else:
                if verify_slot_va is not None and _call_hits_iat_slot(x, verify_slot_va):
                    n = max(0, x.len - 4)
                    code_type = "pop_eax_add_esp_12" if n == 0 else f"pop_eax_add_esp_12_nop_{n}"
                    off_rva = int(x.ip - ctx.image_base)
                    return PatchResult(
                        lines=[
                            "SingleUserPatch.x86=1",
                            f"SingleUserOffset.x86={off_rva:X}",
                            f"SingleUserCode.x86={code_type}",
                        ]
                    )
                if x.mnemonic == Mnemonic.CMP and x.len <= 8 and x.op0_kind == OpKind.MEMORY and \
                   x.memory_base == Register.EBP and x.op1_kind in (OpKind.IMMEDIATE8, OpKind.IMMEDIATE32):
                    imm = x.immediate8 if x.op1_kind == OpKind.IMMEDIATE8 else x.immediate32
                    if imm == 1:
                        off_rva = int(x.ip - ctx.image_base)
                        return PatchResult(
                            lines=[
                                "SingleUserPatch.x86=1",
                                f"SingleUserOffset.x86={off_rva:X}",
                                f"SingleUserCode.x86=nop_{x.len}",
                            ]
                        )
        return None

    for idx, insn in enumerate(insns):
        matched_memset = False
        if direct_call:
            matched_memset = _is_rel_call_to(insn, memset_target_va)
        else:
            matched_memset = _call_hits_iat_slot(insn, memset_target_va)

        if not matched_memset:
            continue
        res = _scan_forward_from(idx)
        if res:
            return res
        break

    if verify_slot_va is not None:
        for x in insns:
            if _call_hits_iat_slot(x, verify_slot_va):
                if ctx.bitness == 64:
                    n = max(0, x.len - 5)
                    code_type = "mov_eax_1" if n == 0 else f"mov_eax_1_nop_{n}"
                    off_rva = int(x.ip - ctx.image_base)
                    return PatchResult(
                        lines=[
                            "SingleUserPatch.x64=1",
                            f"SingleUserOffset.x64={off_rva:X}",
                            f"SingleUserCode.x64={code_type}",
                        ]
                    )
                n = max(0, x.len - 4)
                code_type = "pop_eax_add_esp_12" if n == 0 else f"pop_eax_add_esp_12_nop_{n}"
                off_rva = int(x.ip - ctx.image_base)
                return PatchResult(
                    lines=[
                        "SingleUserPatch.x86=1",
                        f"SingleUserOffset.x86={off_rva:X}",
                        f"SingleUserCode.x86={code_type}",
                    ]
                )

    return None
