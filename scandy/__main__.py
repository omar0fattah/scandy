"""
Lets the package be run directly: `python3 -m scandy <command> ...`
"""

import sys

from scandy.cli import main

if __name__ == "__main__":
    sys.exit(main())
