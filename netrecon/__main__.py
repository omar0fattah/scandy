"""
Lets the package be run directly: `python3 -m netrecon <command> ...`
"""

import sys

from netrecon.cli import main

if __name__ == "__main__":
    sys.exit(main())
