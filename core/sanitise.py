"""Terminal-safety helper: strip control characters from decoded payloads.

Forensic data (hostnames, credentials, HTTP headers, chat text) is decoded
from raw bytes with latin-1, which maps *every* byte 1:1 to a character —
including ESC (\\x1b) and other C0 controls. A crafted capture can embed
terminal escape sequences (e.g. \\x1b[2J clears the screen, \\x1b[?25l
hides the cursor) that would be executed by the analyst's TTY on print.
Sanitising before printing closes this terminal-injection vector.

The strip set removes all C0 controls except TAB/LF/CR (kept for readable
output), plus DEL (0x7f):
    [\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]
"""
from __future__ import annotations

import re

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitise(text: str) -> str:
    """Remove terminal-control characters from a decoded string.

    Returns the input unchanged if it contains no control characters.
    """
    if not text:
        return text
    return _CONTROL_RE.sub("", text)
