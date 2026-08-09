"""
status.py — terminal activity renderer for long-running AI commands.

Writes a single-line progress indicator to STDERR so it bypasses the
stdout redirect used by the shell's boxed answer rendering
(``redirect_stdout`` in cli/shell.py). The line is updated in place with
a carriage return: spinner + elapsed timer + stage + detail.

Auto-disabled when stderr is not a TTY (pipes, regression tests, scripts)
so automated runs produce clean, deterministic output.
"""
from __future__ import annotations

import os
import sys
import threading
import time
from typing import Callable, Optional

from main import (RESET, BOLD, DIM, CYAN, BRIGHT_CYAN, BRIGHT_GREEN, YELLOW,
                  UNICODE_GLYPHS)

if UNICODE_GLYPHS:
    _SPINNER_FRAMES = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")
else:
    _SPINNER_FRAMES = ("|", "/", "-", "\\")
_TICK_SECONDS = 0.1


class ActivityStatus:
    """A single-line, in-place status indicator on stderr.

    Usage::

        st = ActivityStatus()
        st.set("tool-loop", "get_smtp_credentials 2/8")
        ...
        st.clear()          # or st.finish("done in 4.2s")

    Thread-safe: ``set``/``clear`` can be called from any thread (e.g.
    LLMClient event callbacks, background self-critique) while the ticker
    thread redraws. Never writes when not a TTY.
    """

    def __init__(self, enabled: Optional[bool] = None):
        if enabled is None:
            enabled = bool(sys.stderr.isatty())
        self._enabled = enabled
        self._stage: str = ""
        self._detail: str = ""
        self._t0 = time.monotonic()
        self._lock = threading.Lock()
        self._ticker: Optional[threading.Thread] = None
        self._stop = False
        if enabled:
            self._ticker = threading.Thread(
                target=self._run_ticker, name="status-ticker", daemon=True)
            self._ticker.start()

    # ------------------------------------------------------------------ #
    # Public API                                                         #
    # ------------------------------------------------------------------ #
    def set(self, stage: str, detail: str = "") -> None:
        """Update the stage label and optional detail of the status line."""
        if not self._enabled:
            return
        with self._lock:
            self._stage = stage
            self._detail = detail
        self._redraw()

    def clear(self) -> None:
        """Erase the status line and stop the ticker."""
        self._stop_ticker()
        if not self._enabled:
            return
        with self._lock:
            self._stage = ""
            self._detail = ""
        try:
            sys.stderr.write("\r\x1b[2K")
            sys.stderr.flush()
        except Exception:
            pass

    def finish(self, summary: str = "") -> None:
        """Stop the spinner and leave a short summary line (in place of
        the spinner). Always called before a command prints its result."""
        self._stop_ticker()
        if not self._enabled:
            return
        with self._lock:
            stage = self._stage
            detail = self._detail
        elapsed = time.monotonic() - self._t0
        text = ""
        if stage:
            text += f"{BOLD}{stage}{RESET}"
            if detail:
                text += f" {DIM}·{RESET} {detail}"
        if summary:
            text += (f" {DIM}·{RESET} {BRIGHT_GREEN}{summary}{RESET}")
        if not text:
            text = f"{BRIGHT_GREEN}done{RESET}"
        try:
            line = f"{text}  {DIM}{elapsed:.1f}s{RESET}"
            sys.stderr.write("\r\x1b[2K" + line + "\n")
            sys.stderr.flush()
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # Internal                                                           #
    # ------------------------------------------------------------------ #
    def _run_ticker(self) -> None:
        while not self._stop:
            self._redraw()
            time.sleep(_TICK_SECONDS)

    def _stop_ticker(self) -> None:
        self._stop = True
        t = self._ticker
        if t is not None:
            t.join(timeout=0.3)
        self._ticker = None

    def _redraw(self) -> None:
        if not self._enabled:
            return
        with self._lock:
            stage = self._stage
            detail = self._detail
        if not stage:
            return
        elapsed = time.monotonic() - self._t0
        frame = _SPINNER_FRAMES[int(time.monotonic() * 10) % len(_SPINNER_FRAMES)]
        parts = [f"{BRIGHT_CYAN}{frame}{RESET} {BOLD}{stage}{RESET}"]
        if detail:
            parts.append(f"{DIM}·{RESET} {detail}")
        parts.append(f"{DIM}{elapsed:6.1f}s{RESET}")
        try:
            line = " ".join(parts)
            # Erase the previous line fully, then write the new one.
            sys.stderr.write("\r\x1b[2K" + line)
            sys.stderr.flush()
        except Exception:
            pass


# A module-level default instance, so the many call sites don't need to
# thread one through. Commands that want a custom lifecycle create their
# own instance instead of using this.
_default = ActivityStatus()


def status(stage: str, detail: str = "") -> None:
    """Update the shared default status line."""
    _default.set(stage, detail)


def status_clear() -> None:
    """Clear the shared default status line."""
    _default.clear()


def status_finish(summary: str = "") -> None:
    """Finish the shared default status line with an optional summary."""
    _default.finish(summary)
