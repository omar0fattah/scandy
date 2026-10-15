"""
Minimal ANSI color helpers for terminal output.

Kept deliberately separate from the data classes (Host, ScanResult,
etc.) - those should stay plain data with no opinion about how
they're displayed. Color is a CLI/presentation concern, so it lives
here and gets applied when building the printed report, not inside
__str__ methods that other code might rely on for plain text (logging,
tests, JSON prep, etc).

Respects the NO_COLOR convention (https://no-color.org) and disables
itself when output isn't going to a real terminal (e.g. piped to a
file), so saved reports and `> output.txt` redirects stay clean.
"""

import os
import sys

RESET = "\033[0m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BOLD = "\033[1m"


def _enabled() -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    return sys.stdout.isatty()


def colorize(text: str, *codes: str) -> str:
    """Wrap text in the given ANSI codes, or return it unchanged if
    color is disabled (non-tty output or NO_COLOR set)."""
    if not _enabled() or not codes:
        return text
    return "".join(codes) + text + RESET


def red(text: str) -> str:
    return colorize(text, RED)


def green(text: str) -> str:
    return colorize(text, GREEN)


def yellow(text: str) -> str:
    return colorize(text, YELLOW)


def cyan(text: str) -> str:
    return colorize(text, CYAN)


def bold(text: str) -> str:
    return colorize(text, BOLD)
