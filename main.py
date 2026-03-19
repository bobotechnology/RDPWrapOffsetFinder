"""Entry point for RDPWrap Offset Finder.

This module serves as the main entry point for the command-line application.
"""

import sys
from rdpwrap_offset_finder.cli import main

if __name__ == "__main__":
    # Execute the main CLI function and exit with its return code
    sys.exit(main())
