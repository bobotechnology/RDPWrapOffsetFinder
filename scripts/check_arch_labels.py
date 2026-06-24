#!/usr/bin/env python3
"""校验 termsrv 测试 DLL 文件名中的 _x86/_x64 标签是否与实际 PE 架构一致。"""
import sys
import os
from pathlib import Path

import pefile

MACHINE_NAMES = {
    0x014C: "x86 (I386)",
    0x8664: "x64 (AMD64)",
    0x0200: "IA64",
    0x01C4: "ARM",
    0xAA64: "ARM64",
}


def check_dll(filepath: Path) -> dict | None:
    """返回 None 表示正确，返回 dict 表示不匹配。"""
    try:
        pe = pefile.PE(str(filepath))
    except Exception as e:
        return {"error": str(e)}

    machine = pe.FILE_HEADER.Machine
    magic = pe.OPTIONAL_HEADER.Magic

    filename = filepath.name.lower()

    # 实际架构
    if machine == 0x014C:
        actual = "x86"
    elif machine == 0x8664:
        actual = "x64"
    else:
        actual = f"0x{machine:04X}"

    real_arch = MACHINE_NAMES.get(machine, f"0x{machine:04X}")

    # 文件名标注
    if "_x64" in filename:
        label = "x64"
    elif "_x86" in filename:
        label = "x86"
    else:
        return None  # 没有架构标签，跳过

    if label == actual:
        return None  # 匹配

    return {
        "file": filepath.name,
        "label": label,
        "actual": actual,
        "machine": f"0x{machine:04X}",
        "magic": f"0x{magic:04X}",
        "real": real_arch,
    }


def main():
    test_dir = sys.argv[1] if len(sys.argv) > 1 else None
    if not test_dir:
        # 尝试常见路径
        candidates = [
            Path.home() / "Downloads" / "termsrv_tests",
            Path(__file__).parent.parent / "tests" / "fixtures",
        ]
        for c in candidates:
            if c.is_dir():
                test_dir = str(c)
                break
        if not test_dir:
            print("Usage: python check_arch_labels.py <path_to_test_dlls>")
            sys.exit(1)

    root = Path(test_dir)
    if not root.is_dir():
        print(f"ERROR: not a directory: {root}")
        sys.exit(1)

    dlls = sorted(root.glob("*.dll"))
    if not dlls:
        print(f"ERROR: no .dll files found in {root}")
        sys.exit(1)

    print(f"Scanning {len(dlls)} DLLs in {root}")
    print("-" * 70)

    total = 0
    ok = 0
    mismatches = []

    for dll in dlls:
        total += 1
        result = check_dll(dll)
        if result is None:
            ok += 1
        else:
            mismatches.append(result)

    print(f"{'Filename':<45} {'Label':>5} {'Actual':>5}  Machine/Magic")
    print("-" * 70)

    for m in mismatches:
        err = m.get("error", "")
        if err:
            print(f"  {m['file']:<43} ERROR: {err}")
        else:
            print(
                f"  {m['file']:<43}"
                f"  {m['label']:>3} -> {m['actual']:>3}"
                f"    {m['machine']} / {m['magic']}"
            )

    print("-" * 70)
    if not mismatches:
        print(f"ALL {total} DLLs: architecture labels match PE headers. ✓")
    else:
        print(
            f"{ok}/{total} correct, {len(mismatches)} MISMATCHES. "
            f"Please rename the files above."
        )

    # 汇总: 列出所有 x86 / x64 分布
    print()
    x86_list = []
    x64_list = []
    unknown = []
    for dll in dlls:
        try:
            pe = pefile.PE(str(dll))
            m = pe.FILE_HEADER.Machine
            if m == 0x014C:
                x86_list.append(dll.name)
            elif m == 0x8664:
                x64_list.append(dll.name)
            else:
                unknown.append((dll.name, f"0x{m:04X}"))
        except Exception:
            unknown.append((dll.name, "READ_ERROR"))

    print(f"PE x86:  {len(x86_list)} files")
    print(f"PE x64:  {len(x64_list)} files")
    if unknown:
        print(f"Unknown: {len(unknown)} files")
        for name, m in unknown:
            print(f"  {name}: {m}")

    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
