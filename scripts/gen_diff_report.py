#!/usr/bin/env python3
"""Generate an HTML diff report from compare_report.csv.

Reads the CSV produced by compare_all.py and produces a standalone HTML
file with an accurate, data-driven table of all discrepancies.

Usage:
    python scripts/gen_diff_report.py [--input CSV] [--output HTML]
"""

import argparse
import csv
import os
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def classify_diff(sym_val: str, nosym_val: str) -> str:
    """Classify a single diff row based on which side has data."""
    s = (sym_val or '').strip()
    n = (nosym_val or '').strip()
    if not s and n:
        return 'sym_empty'
    if s and not n:
        return 'nosym_empty'
    if not s and not n:
        return 'both_empty'
    return 'value_mismatch'


def category_label(cat: str) -> str:
    return {
        'sym_empty': 'symbol 空 / nosym 有值',
        'nosym_empty': 'nosym 空 / symbol 有值',
        'both_empty': '双方都空',
        'value_mismatch': '值不同',
    }.get(cat, cat)


def category_color(cat: str) -> str:
    return {
        'sym_empty': '#FCEBEB',
        'nosym_empty': '#E6F1FB',
        'both_empty': '#F1EFE8',
        'value_mismatch': '#FAEEDA',
    }.get(cat, '#FFFFFF')


def load_csv(path: str) -> list[dict]:
    rows = []
    with open(path, 'r', encoding='utf-8-sig', newline='') as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append(r)
    return rows


def build_dll_entries(rows: list[dict]) -> list[dict]:
    """Group diff rows by DLL, return list of entries with metadata."""
    dll_data: dict[str, dict] = {}

    for r in rows:
        if r['Status'] != 'DIFF':
            continue
        dll = r['DLL']
        if dll not in dll_data:
            dll_data[dll] = {
                'dll': dll,
                'version': r['Version'],
                'arch': r['Arch'],
                'main_diffs': [],
                'slinit_diffs': [],
            }
        entry = dll_data[dll]
        cat = classify_diff(r['Symbol'], r['Nosymbol'])
        diff_item = {
            'section': r['Section'],
            'key': r['Key'],
            'symbol': r['Symbol'],
            'nosymbol': r['Nosymbol'],
            'cat': cat,
        }
        if '-SLInit' in r['Section']:
            entry['slinit_diffs'].append(diff_item)
        else:
            entry['main_diffs'].append(diff_item)

    # Sort by version string (natural-ish)
    entries = sorted(dll_data.values(),
                     key=lambda e: (e['version'], e['arch']))
    return entries


def count_ok(rows: list[dict]) -> int:
    """Count unique DLLs with Status=OK (one row per OK DLL)."""
    return sum(1 for r in rows if r['Status'] == 'OK')


def count_diff(rows: list[dict]) -> int:
    """Count unique DLLs with at least one DIFF row."""
    diff_dlls = {r['DLL'] for r in rows if r['Status'] == 'DIFF'}
    return len(diff_dlls)


def count_total(rows: list[dict]) -> int:
    """Count unique DLLs (OK + DIFF)."""
    all_dlls = {r['DLL'] for r in rows}
    return len(all_dlls)


def generate_html(entries: list[dict], total: int, ok: int, diff: int) -> str:
    """Generate standalone HTML report."""

    parts = []
    parts.append('<!DOCTYPE html>')
    parts.append('<html lang="zh-CN">')
    parts.append('<head>')
    parts.append('<meta charset="UTF-8">')
    parts.append('<meta name="viewport" content="width=device-width, initial-scale=1.0">')
    parts.append('<title>Symbol vs Nosymbol Diff Report</title>')
    parts.append('<style>')
    parts.append('''
      * { margin: 0; padding: 0; box-sizing: border-box; }
      body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        font-size: 14px;
        line-height: 1.6;
        color: #1a1a1a;
        background: #fafafa;
        padding: 24px;
      }
      h1 { font-size: 20px; font-weight: 600; margin-bottom: 8px; }
      h2 { font-size: 16px; font-weight: 600; margin: 24px 0 8px; }
      .summary {
        display: flex;
        gap: 16px;
        margin-bottom: 24px;
        flex-wrap: wrap;
      }
      .stat {
        background: #fff;
        border-radius: 8px;
        padding: 12px 20px;
        border: 1px solid #e0e0e0;
        min-width: 120px;
      }
      .stat .label { font-size: 12px; color: #666; }
      .stat .value { font-size: 24px; font-weight: 600; margin-top: 4px; }
      .stat.ok .value { color: #0F6E56; }
      .stat.diff .value { color: #D85A30; }
      .stat.total .value { color: #333; }
      .legend {
        display: flex;
        gap: 12px;
        margin-bottom: 16px;
        flex-wrap: wrap;
        font-size: 12px;
      }
      .legend-item {
        display: flex;
        align-items: center;
        gap: 6px;
        padding: 3px 10px;
        border-radius: 4px;
      }
      table {
        width: 100%;
        border-collapse: collapse;
        background: #fff;
        border-radius: 8px;
        overflow: hidden;
        border: 1px solid #e0e0e0;
        margin-bottom: 24px;
      }
      th {
        background: #f5f5f5;
        padding: 8px 10px;
        text-align: left;
        font-weight: 600;
        font-size: 13px;
        border-bottom: 1px solid #e0e0e0;
        position: sticky;
        top: 0;
      }
      td {
        padding: 6px 10px;
        border-bottom: 1px solid #f0f0f0;
        font-size: 13px;
        vertical-align: top;
      }
      tr:last-child td { border-bottom: none; }
      tr.dll-header td {
        background: #e8e8e8;
        font-weight: 600;
        font-size: 14px;
        padding: 8px 10px;
      }
      .cat-badge {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 500;
      }
      .mono { font-family: "SF Mono", Consolas, "Liberation Mono", monospace; font-size: 12px; }
      .empty { color: #ccc; font-style: italic; }
      .section-tag {
        display: inline-block;
        padding: 1px 6px;
        border-radius: 3px;
        font-size: 10px;
        font-weight: 600;
        margin-right: 4px;
      }
      .section-tag.main { background: #d4e4f7; color: #185FA5; }
      .section-tag.slinit { background: #e1f5ee; color: #0F6E56; }
    ''')
    parts.append('</style>')
    parts.append('</head>')
    parts.append('<body>')

    # Title & summary
    pct = round(ok / total * 100) if total else 0
    parts.append(f'<h1>Symbol vs Nosymbol Diff Report</h1>')
    parts.append(f'<p style="color:#666;font-size:13px;margin-bottom:16px;">'
                 f'{total} DLL tested | {ok} OK ({pct}%) | {diff} DIFF</p>')

    parts.append('<div class="summary">')
    parts.append(f'<div class="stat total"><div class="label">Total</div><div class="value">{total}</div></div>')
    parts.append(f'<div class="stat ok"><div class="label">OK</div><div class="value">{ok}</div></div>')
    parts.append(f'<div class="stat diff"><div class="label">DIFF</div><div class="value">{diff}</div></div>')
    parts.append('</div>')

    # Legend
    parts.append('<div class="legend">')
    for cat, label in [
        ('sym_empty', 'symbol 空 / nosym 有值'),
        ('nosym_empty', 'nosym 空 / symbol 有值'),
        ('value_mismatch', '值不同'),
        ('both_empty', '双方都空'),
    ]:
        bg = category_color(cat)
        parts.append(f'<div class="legend-item" style="background:{bg};">'
                     f'<span>{label}</span></div>')
    parts.append('</div>')

    # Table
    parts.append('<table>')
    parts.append('<thead><tr>')
    parts.append('<th style="width:12%">DLL</th>')
    parts.append('<th style="width:8%">Arch</th>')
    parts.append('<th style="width:8%">Section</th>')
    parts.append('<th style="width:18%">Key</th>')
    parts.append('<th style="width:20%">Symbol</th>')
    parts.append('<th style="width:20%">Nosymbol</th>')
    parts.append('<th style="width:14%">Category</th>')
    parts.append('</tr></thead>')
    parts.append('<tbody>')

    for entry in entries:
        dll_name = entry['dll'].replace('.dll', '')
        all_diffs = entry['main_diffs'] + entry['slinit_diffs']
        n_main = len(entry['main_diffs'])
        n_slinit = len(entry['slinit_diffs'])
        parts.append(
            f'<tr class="dll-header">'
            f'<td colspan="7">{dll_name} '
            f'<span style="font-weight:400;color:#666;font-size:12px;">'
            f'({entry["version"]}, {entry["arch"]}) '
            f'&mdash; main:{n_main}, SLInit:{n_slinit}</span></td></tr>'
        )

        for d in all_diffs:
            cat = d['cat']
            bg = category_color(cat)
            badge = (f'<span class="cat-badge" style="background:{bg};">'
                     f'{category_label(cat)}</span>')

            sec_tag_class = 'slinit' if '-SLInit' in d['section'] else 'main'
            sec_label = 'SLInit' if '-SLInit' in d['section'] else 'Main'

            sym_display = d['symbol'] if d['symbol'] else '<span class="empty">(empty)</span>'
            nosym_display = d['nosymbol'] if d['nosymbol'] else '<span class="empty">(empty)</span>'

            parts.append(
                f'<tr style="background:{bg}25;">'
                f'<td></td>'
                f'<td></td>'
                f'<td><span class="section-tag {sec_tag_class}">{sec_label}</span></td>'
                f'<td class="mono">{d["key"]}</td>'
                f'<td class="mono">{sym_display}</td>'
                f'<td class="mono">{nosym_display}</td>'
                f'<td>{badge}</td>'
                f'</tr>'
            )

    parts.append('</tbody></table>')
    parts.append('</body></html>')

    return '\n'.join(parts)


def main():
    parser = argparse.ArgumentParser(description='Generate HTML diff report from CSV')
    parser.add_argument('--input', '-i',
                        default=str(PROJECT_ROOT / 'scripts' / 'compare_report.csv'),
                        help='Input CSV path')
    parser.add_argument('--output', '-o',
                        default=str(PROJECT_ROOT / 'scripts' / 'diff_report.html'),
                        help='Output HTML path')
    args = parser.parse_args()

    rows = load_csv(args.input)
    entries = build_dll_entries(rows)
    total = count_total(rows)
    ok = count_ok(rows)
    diff = count_diff(rows)

    html = generate_html(entries, total, ok, diff)
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f"Report generated: {args.output}")
    print(f"  Total: {total} | OK: {ok} | DIFF: {diff}")
    print(f"  Diff DLLs: {len(entries)}")


if __name__ == '__main__':
    main()
