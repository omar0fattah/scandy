"""
Real tests for colors.py - no mocking of the color logic itself,
just controlled manipulation of the two things it actually checks
(NO_COLOR env var, stdout.isatty()) to prove both code paths work.
"""

import os
import unittest
from unittest.mock import patch

from scandy import colors


class TestColors(unittest.TestCase):
    def test_colorize_adds_codes_when_tty_and_no_color_unset(self):
        with patch.object(colors.sys.stdout, "isatty", return_value=True), \
             patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NO_COLOR", None)
            result = colors.red("hello")
            self.assertIn(colors.RED, result)
            self.assertIn(colors.RESET, result)
            self.assertIn("hello", result)

    def test_colorize_skips_codes_when_not_a_tty(self):
        with patch.object(colors.sys.stdout, "isatty", return_value=False):
            result = colors.red("hello")
            self.assertEqual(result, "hello")

    def test_colorize_skips_codes_when_no_color_set(self):
        with patch.object(colors.sys.stdout, "isatty", return_value=True), \
             patch.dict(os.environ, {"NO_COLOR": "1"}):
            result = colors.green("world")
            self.assertEqual(result, "world")

    def test_plain_text_content_always_preserved(self):
        # Whether or not color codes are added, the original text must
        # always be recoverable/visible - color should never eat content.
        with patch.object(colors.sys.stdout, "isatty", return_value=True):
            os.environ.pop("NO_COLOR", None)
            colored = colors.bold("important")
            self.assertIn("important", colored)
        with patch.object(colors.sys.stdout, "isatty", return_value=False):
            plain = colors.bold("important")
            self.assertEqual(plain, "important")


if __name__ == "__main__":
    unittest.main()
