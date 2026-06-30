from __future__ import annotations

from dataclasses import dataclass

import pefile


@dataclass(frozen=True)
class RuntimeFunction:
    begin_rva: int
    end_rva: int
    unwind_rva: int


@dataclass(frozen=True)
class UnwindInfo:
    version: int
    flags: int
    count_of_codes: int


UNW_FLAG_CHAININFO = 0x4
RUNTIME_FUNCTION_INDIRECT = 0x1


def _u32(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off + 4], "little", signed=False)


def parse_exception_directory_x64(pe: pefile.PE, image: bytes) -> list[RuntimeFunction]:
    dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]]
    rva = int(dd.VirtualAddress)
    size = int(dd.Size)
    if rva == 0 or size == 0:
        return []

    data = image[rva:rva + size]
    out: list[RuntimeFunction] = []
    for off in range(0, len(data) - 11, 12):
        begin_rva = _u32(data, off)
        end_rva = _u32(data, off + 4)
        unwind_rva = _u32(data, off + 8)
        if begin_rva == 0 and end_rva == 0 and unwind_rva == 0:
            continue
        out.append(RuntimeFunction(begin_rva=begin_rva, end_rva=end_rva, unwind_rva=unwind_rva))
    return out


def _read_runtime_function(image: bytes, rva: int) -> RuntimeFunction:
    begin_rva = _u32(image, rva)
    end_rva = _u32(image, rva + 4)
    unwind_rva = _u32(image, rva + 8)
    return RuntimeFunction(begin_rva=begin_rva, end_rva=end_rva, unwind_rva=unwind_rva)


def _parse_unwind_info(image: bytes, rva: int) -> UnwindInfo:
    b0 = image[rva]
    version = b0 & 0x7
    flags = (b0 >> 3) & 0x1F
    count = image[rva + 2]
    return UnwindInfo(version=version, flags=flags, count_of_codes=count)


def backtrace_x64(image: bytes, func: RuntimeFunction) -> RuntimeFunction:
    if func.unwind_rva & RUNTIME_FUNCTION_INDIRECT:
        func = _read_runtime_function(image, func.unwind_rva & ~0x3)

    unwind = _parse_unwind_info(image, func.unwind_rva)
    while unwind.flags & UNW_FLAG_CHAININFO:
        code_slots = (unwind.count_of_codes + 1) & ~1
        chained_off = func.unwind_rva + 4 + (2 * code_slots)
        func = _read_runtime_function(image, chained_off)
        if func.unwind_rva & RUNTIME_FUNCTION_INDIRECT:
            func = _read_runtime_function(image, func.unwind_rva & ~0x3)
        unwind = _parse_unwind_info(image, func.unwind_rva)
    return func


# Minimum size for a function to be considered "real" (not a thunk/stub).
_REAL_FUNC_MIN_SIZE = 0x200

# When the terminal is a thunk, scan this far forward for the real prologue.
_PROLOGUE_SCAN_RANGE = 0x20000   # 128 KB


def _looks_like_prologue(image: bytes, rva: int) -> bool:
    """Check if the instruction at *rva* looks like an x64 function prologue.

    Common prologue starters (first 1-2 bytes):
        PUSH RBP          (55)
        PUSH RBX          (53)
        PUSH RSI          (56)
        PUSH RDI          (57)
        PUSH R12..R15     (41 54 .. 41 57)
        MOV [RSP+...],reg (48 89 .. / 4C 89 ..)
        SUB RSP,imm32     (48 81 EC / 48 83 EC)
    """
    if rva >= len(image) - 1:
        return False
    b0 = image[rva]
    # PUSH rbx/rbp/rsi/rdi
    if b0 in (0x55, 0x53, 0x56, 0x57):
        return True
    # REX.W (48): MOV [RSP+...], reg / SUB RSP / MOV RBP,RSP
    if b0 == 0x48 and rva + 1 < len(image):
        b1 = image[rva + 1]
        if b1 in (0x89, 0x81, 0x83, 0xE5):
            return True
    # REX.W + R (4C): MOV [RSP+...], r12..r15
    if b0 == 0x4C and rva + 1 < len(image):
        if image[rva + 1] == 0x89:
            return True
    # REX.R + PUSH r12..r15  (41 54 .. 41 57)
    if b0 == 0x41 and rva + 1 < len(image):
        if 0x54 <= image[rva + 1] <= 0x57:
            return True
    return False


def find_function_bounds(
    image: bytes,
    all_funcs: list[RuntimeFunction],
    initial: RuntimeFunction,
) -> tuple[int, int, int]:
    """Find the true bounds of a function, handling thunks.

    Returns ``(prologue_begin, data_begin, data_end)`` where:

    * ``prologue_begin`` is the RVA of the real function prologue (used for
      SLInitOffset and other patching).
    * ``data_begin`` is the earliest RVA belonging to this function
      (excluding known thunks).  Used as the scan-start so that all code
      segments, including those placed before the prologue by PGO‑driven
      splitting, are covered.
    * ``data_end`` is the latest RVA belonging to this function.

    For normal functions the three values are equal to the terminal's
    begin/end.  Only for large split functions (e.g. CSLQuery::Initialize on
    Win8.1) where the terminal is a tiny thunk does the extra prologue‑scan
    logic activate.
    """
    terminal = backtrace_x64(image, initial)

    terminal_size = terminal.end_rva - terminal.begin_rva

    # Collect the family (entries that chain to the same terminal) so we
    # can compute data_begin / data_end regardless of the prologue logic.
    data_begin = terminal.begin_rva
    data_end = terminal.end_rva
    family: list[RuntimeFunction] = [terminal]
    for rf in all_funcs:
        if rf.begin_rva > terminal.begin_rva + 0x100000:
            continue
        if rf.end_rva < terminal.begin_rva - 0x100000:
            continue
        try:
            top = backtrace_x64(image, rf)
            if top.begin_rva == terminal.begin_rva:
                data_begin = min(data_begin, rf.begin_rva)
                data_end = max(data_end, rf.end_rva)
                family.append(rf)
        except Exception:
            pass

    # --- Determine prologue_begin ---
    # Normal case: terminal is a real function (large enough or looks like a
    # prologue).  Use terminal.begin_rva directly.
    if terminal_size >= _REAL_FUNC_MIN_SIZE:
        # Exclude tiny thunks from data_begin (skip family members that are
        # very small and don't look like a prologue).
        for rf in sorted(family, key=lambda x: x.begin_rva):
            if rf.end_rva - rf.begin_rva < 0x40 and not _looks_like_prologue(image, rf.begin_rva):
                if rf.begin_rva == data_begin:
                    data_begin = rf.end_rva
                continue
            data_begin = rf.begin_rva
            break
        return terminal.begin_rva, data_begin, data_end

    # Small terminal — check if it looks like a prologue.
    if _looks_like_prologue(image, terminal.begin_rva):
        # Small but valid prologue (e.g. split function where the prologue
        # entry only covers a few instructions).  Use terminal.begin_rva
        # as prologue_begin, but data_begin should still encompass all
        # family members (code may exist before the prologue in PGO-split
        # functions like CSLQuery::Initialize on Win8.1).
        for rf in sorted(family, key=lambda x: x.begin_rva):
            if rf.end_rva - rf.begin_rva < 0x40 and not _looks_like_prologue(image, rf.begin_rva):
                if rf.begin_rva == data_begin:
                    data_begin = rf.end_rva
                continue
            data_begin = rf.begin_rva
            break
        return terminal.begin_rva, data_begin, data_end

    # Terminal is a tiny thunk (doesn't look like a prologue).
    # Find the real prologue among family members, preferring the one
    # closest to the terminal.
    best_begin: int | None = None
    best_dist = 0xFFFFFFFF
    for rf in family:
        if _looks_like_prologue(image, rf.begin_rva):
            dist = abs(rf.begin_rva - terminal.begin_rva)
            if dist < best_dist:
                best_dist = dist
                best_begin = rf.begin_rva

    if best_begin is not None:
        prologue_begin = best_begin
    else:
        # Last resort: scan all entries near the terminal.
        scan_end = min(terminal.begin_rva + _PROLOGUE_SCAN_RANGE, len(image))
        prologue_begin = terminal.begin_rva  # fallback
        for rf in all_funcs:
            if rf.begin_rva < terminal.begin_rva:
                continue
            if rf.begin_rva >= scan_end:
                break
            if _looks_like_prologue(image, rf.begin_rva):
                prologue_begin = rf.begin_rva
                data_end = max(data_end, rf.end_rva)
                break

    # Exclude tiny thunks from data_begin.
    for rf in sorted(family, key=lambda x: x.begin_rva):
        if rf.end_rva - rf.begin_rva < 0x40 and not _looks_like_prologue(image, rf.begin_rva):
            if rf.begin_rva == data_begin:
                data_begin = rf.end_rva
            continue
        data_begin = rf.begin_rva
        break

    return prologue_begin, data_begin, data_end
