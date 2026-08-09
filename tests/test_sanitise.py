"""Sanitise helper — terminal-injection defence (H1).

A crafted capture can embed ESC sequences (\\x1b[2J, \\x1b[?25l) in decoded
hostnames/credentials/payloads. `core.sanitise.sanitise` strips C0 control
bytes (except TAB/LF/CR) and DEL before such data reaches a TTY.
"""
import unittest

from core.sanitise import sanitise


class TestSanitise(unittest.TestCase):
    def test_empty_and_plain(self):
        self.assertEqual(sanitise(""), "")
        self.assertEqual(sanitise("abc"), "abc")

    def test_keeps_formatting_whitespace(self):
        self.assertEqual(sanitise("keep\ttab\nnl\rcr"), "keep\ttab\nnl\rcr")

    def test_strips_esc_sequence(self):
        self.assertEqual(sanitise("evil\x1b[2Jclear"), "evil[2Jclear")
        self.assertNotIn("\x1b", sanitise("a\x1b[1;31mb"))

    def test_strips_cursor_hide(self):
        self.assertEqual(sanitise("hide\x1b[?25lcursor"), "hide[?25lcursor")

    def test_strips_all_c0_controls(self):
        self.assertEqual(sanitise("\x00\x01\x08\x0b\x0c\x0e\x1f\x7f bell\x07"), " bell")


if __name__ == "__main__":
    unittest.main()
