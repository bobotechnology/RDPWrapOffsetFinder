"""Command-line interface for RDPWrap Offset Finder.

This module provides the command-line interface for finding offsets in termsrv.dll
to generate RDPWrap configuration sections.
"""

from __future__ import annotations

import argparse
import sys

try:
    from .termsrv import analyze_termsrv
except ImportError:
    from rdpwrap_offset_finder.termsrv import analyze_termsrv


def _create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser for the CLI.
    
    Returns:
        Configured ArgumentParser instance with all supported options.
    """
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
    """Main entry point for the RDPWrap Offset Finder CLI.
    
    Args:
        argv: Optional list of command-line arguments. If None, uses sys.argv.
        
    Returns:
        Exit code: 0 for success, 2 for error.
    """
    parser = _create_argument_parser()
    args = parser.parse_args(argv)

    try:
        # Run analysis with or without symbols based on user preference
        result = analyze_termsrv(args.termsrv, use_symbols=not args.nosymbol)
    except Exception as error:
        print(f"ERROR: {error}")
        return 2

    # Output the results to stdout
    sys.stdout.write(result)
    if result and not result.endswith("\n"):
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
