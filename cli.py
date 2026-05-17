from __future__ import annotations

import argparse
import sys

from termsrv import analyze_termsrv


def _create_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rdpwrap-offset-finder",
        description="Find offsets for RDPWrap (termsrv.dll) and generate ini sections",
        add_help=True,
    )

    parser.add_argument(
        "termsrv",
        nargs="?",
        default=None,
        help="Path to termsrv.dll (default: %%SystemRoot%%\\System32\\termsrv.dll)",
    )
    parser.add_argument(
        "--nosymbol",
        action="store_true",
        help="Use heuristic pattern search instead of PDB symbols",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _create_argument_parser()
    args = parser.parse_args(argv)

    try:
        result = analyze_termsrv(args.termsrv, use_symbols=not args.nosymbol)
    except Exception as error:
        print(f"ERROR: {error}")
        return 2

    sys.stdout.write(result)
    if result and not result.endswith("\n"):
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
