#!/usr/bin/env python3
"""Batch compare symbol-based vs nosymbol-based analysis for all DLLs.

Usage:
    python scripts/compare_all.py [--dir PATH] [--output PATH] [--verbose]
"""

import argparse
import configparser
import io
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from termsrv import analyze_termsrv


# ── INI Parsing ──────────────────────────────────────────────────────────────

def parse_ini_output(text: str) -> dict[str, dict[str, str]]:
    """Parse the INI-format output into {section_name: {key: value}}."""
    cfg = configparser.ConfigParser()
    cfg.optionxform = str  # preserve case
    cfg.read_string(text)
    result: dict[str, dict[str, str]] = {}
    for section in cfg.sections():
        result[section] = dict(cfg.items(section))
    return result


def compare_sections(sym: dict[str, dict[str, str]],
                     nosym: dict[str, dict[str, str]]) -> list[dict]:
    """Compare two parsed INI results, return list of discrepancies.

    Each discrepancy is a dict with keys:
        section, key, sym_value, nosym_value, kind
    where kind is one of: 'mismatch', 'sym_only', 'nosym_only'
    """
    diffs = []
    all_sections = set(sym.keys()) | set(nosym.keys())

    for section in sorted(all_sections):
        sym_keys = set(sym.get(section, {}).keys())
        nosym_keys = set(nosym.get(section, {}).keys())

        # Keys in both: compare values
        for key in sorted(sym_keys & nosym_keys):
            sv = sym[section][key]
            nv = nosym[section][key]
            # Normalise empty strings and None
            if (sv or '').strip() != (nv or '').strip():
                diffs.append({
                    'section': section,
                    'key': key,
                    'sym_value': sv.strip() if sv else '',
                    'nosym_value': nv.strip() if nv else '',
                    'kind': 'mismatch',
                })

        # Keys only in sym
        for key in sorted(sym_keys - nosym_keys):
            diffs.append({
                'section': section,
                'key': key,
                'sym_value': sym[section][key],
                'nosym_value': '(missing)',
                'kind': 'sym_only',
            })

        # Keys only in nosym
        for key in sorted(nosym_keys - sym_keys):
            diffs.append({
                'section': section,
                'key': key,
                'sym_value': '(missing)',
                'nosym_value': nosym[section][key],
                'kind': 'nosym_only',
            })

    return diffs


# ── Analysis ─────────────────────────────────────────────────────────────────

@dataclass
class CompareResult:
    path: str
    version: str = ''
    arch: str = ''
    success: bool = False
    error: str = ''
    sym_time: float = 0.0
    nosym_time: float = 0.0
    diffs: list[dict] = field(default_factory=list)
    sym_raw: str = ''
    nosym_raw: str = ''


def _extract_version_arch(raw: str) -> tuple[str, str]:
    """Extract version string and arch from the first section header."""
    m = re.search(r'^\[([0-9.]+)\]', raw, re.MULTILINE)
    version = m.group(1) if m else ''
    arch = ''
    if '.x64=' in raw:
        arch = 'x64'
    elif '.x86=' in raw:
        arch = 'x86'
    return version, arch


def _is_no_pdb(dll_path: str) -> bool:
    """DLL under a 'nosym' (or similar) directory has no PDB reference."""
    lower = dll_path.lower().replace('\\', '/')
    return '/nosym/' in lower or '/no pdb/' in lower


def analyze_one(dll_path: str) -> CompareResult:
    """Run both symbol and nosymbol analysis on one DLL."""
    r = CompareResult(path=dll_path)
    no_pdb = _is_no_pdb(dll_path)

    # Symbol mode — skip if we know there's no PDB
    if no_pdb:
        r.sym_raw = ''
        r.sym_time = 0.0
    else:
        t0 = time.perf_counter()
        try:
            r.sym_raw = analyze_termsrv(dll_path, use_symbols=True)
            r.success = True
        except Exception as e:
            r.error = f"symbol: {e}"
            r.sym_time = time.perf_counter() - t0
            return r
        r.sym_time = time.perf_counter() - t0

    # Nosymbol mode
    t0 = time.perf_counter()
    try:
        r.nosym_raw = analyze_termsrv(dll_path, use_symbols=False)
    except Exception as e:
        r.error = f"nosymbol: {e}"
        # set version even on nosym failure so the entry shows up
        r.version, r.arch = _extract_version_arch('')
        r.nosym_time = time.perf_counter() - t0
        return r
    r.nosym_time = time.perf_counter() - t0

    r.version, r.arch = _extract_version_arch(r.sym_raw or r.nosym_raw)

    # Parse and compare — for no-PDB DLLs there is nothing to compare
    if no_pdb:
        r.success = True
        return r

    try:
        sym_parsed = parse_ini_output(r.sym_raw)
        nosym_parsed = parse_ini_output(r.nosym_raw)
        r.diffs = compare_sections(sym_parsed, nosym_parsed)
    except Exception as e:
        r.error = f"parse/compare: {e}"

    return r


# ── Reporting ────────────────────────────────────────────────────────────────

def print_summary(results: list[CompareResult]):
    """Print a compact summary table."""
    total = len(results)
    ok = sum(1 for r in results if r.success and not r.diffs and not _is_no_pdb(r.path))
    no_pdb = sum(1 for r in results if r.success and _is_no_pdb(r.path))
    diff = sum(1 for r in results if r.success and r.diffs)
    fail = total - ok - diff - no_pdb

    print(f"\n{'='*90}")
    print(f"Total: {total}  |  OK: {ok}  |  DIFF: {diff}  |  NOPDB: {no_pdb}  |  FAIL: {fail}")
    print(f"{'='*90}")

    if fail:
        print("\n── FAILURES ──")
        for r in results:
            if not r.success:
                name = os.path.basename(r.path)
                print(f"  {name}: {r.error}")


def print_diffs(results: list[CompareResult], verbose: bool = False):
    """Print detailed diffs for each DLL with discrepancies."""
    if not any(r.diffs for r in results if not _is_no_pdb(r.path)):
        print("\n✅ All symbol/nosymbol results match!")
        return

    for r in results:
        if not r.diffs or _is_no_pdb(r.path):
            continue
        name = os.path.basename(r.path)
        main_diffs = [d for d in r.diffs if '-SLInit' not in d['section']]
        slinit_diffs = [d for d in r.diffs if '-SLInit' in d['section']]

        print(f"\n── {name}  ({r.version}, {r.arch})  ──")

        if main_diffs:
            print(f"  Main section ({len(main_diffs)} diffs):")
            for d in main_diffs:
                print(f"    [{d['kind']}] {d['key']}:  sym={d['sym_value']}  nosym={d['nosym_value']}")

        if slinit_diffs:
            slinit_section = slinit_diffs[0]['section']
            print(f"  [{slinit_section}] ({len(slinit_diffs)} diffs):")
            for d in slinit_diffs:
                print(f"    [{d['kind']}] {d['key']}:  sym={d['sym_value']}  nosym={d['nosym_value']}")


def print_slinit_summary(results: list[CompareResult]):
    """Print a focused summary of SLInit global variable consistency."""
    print(f"\n{'='*90}")
    print("SLInit Global Variables: nosymbol found / symbol total")
    print(f"{'='*90}")
    print(f"{'DLL':<50} {'Found':>6}  {'Result':>12}")
    print(f"{'-'*50} {'-'*6}  {'-'*12}")

    for r in results:
        if not r.success:
            continue
        name = os.path.basename(r.path)
        if _is_no_pdb(r.path):
            nosym_parsed = parse_ini_output(r.nosym_raw)
            nosym_slinit = next((v for k, v in nosym_parsed.items() if k.endswith('-SLInit')), {})
            nc = len(nosym_slinit)
            print(f"{name:<50} {nc:>3}/-   {'NOPDB':>12}")
            continue
        sym_parsed = parse_ini_output(r.sym_raw)
        nosym_parsed = parse_ini_output(r.nosym_raw)

        # Find SLInit sections
        sym_slinit = next((v for k, v in sym_parsed.items() if k.endswith('-SLInit')), {})
        nosym_slinit = next((v for k, v in nosym_parsed.items() if k.endswith('-SLInit')), {})

        sym_count = len(sym_slinit)
        nosym_count = len(nosym_slinit)

        # Check match
        match = True
        for k in sym_slinit:
            if k not in nosym_slinit or sym_slinit[k].strip() != nosym_slinit[k].strip():
                match = False
                break

        if sym_count == 0:
            status = "N/A"
        elif match:
            status = f"{nosym_count}/{sym_count} ✅"
        else:
            status = f"{nosym_count}/{sym_count} ❌"

        print(f"{name:<50} {nosym_count:>3}/{sym_count:<3}  {status:>12}")


def export_csv(results: list[CompareResult], output_path: str):
    """Export full comparison to CSV."""
    import csv
    with open(output_path, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)
        writer.writerow(['DLL', 'Version', 'Arch', 'Section', 'Key',
                         'Symbol', 'Nosymbol', 'Kind', 'Status'])
        for r in results:
            name = os.path.basename(r.path)
            no_pdb = _is_no_pdb(r.path)
            if not r.success:
                writer.writerow([name, '', '', '', '', '', '', '', f'ERROR: {r.error}'])
                continue
            if no_pdb:
                writer.writerow([name, r.version, r.arch, '', '', '', '', '', 'NOPDB'])
            elif not r.diffs:
                writer.writerow([name, r.version, r.arch, '', '', '', '', '', 'OK'])
            for d in r.diffs:
                writer.writerow([name, r.version, r.arch,
                                 d['section'], d['key'],
                                 d['sym_value'], d['nosym_value'],
                                 d['kind'], 'DIFF'])


# ── Main ─────────────────────────────────────────────────────────────────────

def find_dlls(directory: str) -> list[str]:
    """Find all DLL files in directory, recursively."""
    dlls = []
    for root, dirs, files in os.walk(directory):
        for f in files:
            if f.lower().endswith('.dll'):
                dlls.append(os.path.join(root, f))
    return sorted(dlls)


def main():
    parser = argparse.ArgumentParser(description='Compare symbol vs nosymbol for all DLLs')
    parser.add_argument('--dir', default=None,
                        help='Directory containing test DLLs')
    parser.add_argument('--output', default=None,
                        help='Export detailed CSV to this path')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Show symbol and nosymbol raw output for diffs')
    parser.add_argument('--filter', default=None,
                        help='Only test DLLs whose filename contains this string')
    args = parser.parse_args()

    # Auto-detect test directory
    if args.dir:
        test_dir = args.dir
    else:
        candidates = [
            'C:/Users/bobot.DESKTOP-H2S0A0K/Documents/BaiduNetdiskWorkspace/termsrv_tests',
            os.path.expanduser('~/Downloads/termsrv_tests'),
            'C:/Users/bobot.DESKTOP-H2S0A0K/Downloads/termsrv_tests',
        ]
        test_dir = next((c for c in candidates if os.path.isdir(c)), None)
        if not test_dir:
            print("ERROR: Cannot find test directory. Use --dir to specify.")
            sys.exit(1)

    dlls = find_dlls(test_dir)
    if args.filter:
        dlls = [d for d in dlls if args.filter.lower() in os.path.basename(d).lower()]

    print(f"Testing {len(dlls)} DLLs from {test_dir}")
    print(f"Running both symbol (PDB) and nosymbol (heuristic) modes...\n")

    results: list[CompareResult] = []
    for i, dll in enumerate(dlls, 1):
        name = os.path.basename(dll)
        print(f"[{i:>3}/{len(dlls)}] {name} ... ", end='', flush=True)
        r = analyze_one(dll)
        results.append(r)

        if not r.success:
            print(f"FAIL ({r.error})")
        elif not r.diffs:
            sym_t = r.sym_time
            ns_t = r.nosym_time
            print(f"OK  (sym:{sym_t:.1f}s  nosym:{ns_t:.1f}s)")
        else:
            n_main = len([d for d in r.diffs if '-SLInit' not in d['section']])
            n_slinit = len([d for d in r.diffs if '-SLInit' in d['section']])
            parts = []
            if n_main:
                parts.append(f"main:{n_main}")
            if n_slinit:
                parts.append(f"SLInit:{n_slinit}")
            print(f"DIFF ({', '.join(parts)})")

    # Print reports
    print_summary(results)
    print_diffs(results, verbose=args.verbose)
    print_slinit_summary(results)

    # Export CSV if requested
    if args.output:
        export_csv(results, args.output)
        print(f"\nDetailed CSV exported to: {args.output}")

    # Return exit code
    has_diffs = any(r.diffs for r in results)
    has_fails = any(not r.success for r in results)
    sys.exit(1 if (has_diffs or has_fails) else 0)


if __name__ == '__main__':
    main()
