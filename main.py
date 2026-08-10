"""
EasyShark main entry point.

Usage:
    python3 main.py <pcap_path> [--no-ai]
    python3 main.py <pcap_path> --session <key|latest>
    python3 main.py --session <key|latest>
    python3 main.py --sessions
    python3 main.py --session <key> --forget
"""
from __future__ import annotations

import argparse
import logging
import os
import re
import sys
import textwrap
from pathlib import Path


def _colors_enabled() -> bool:
    """M10 — colour gating. Colours are disabled when NO_COLOR is set
    (any value, per no-color.org) or when stdout is not a TTY (piped /
    scripted output must not be polluted with ANSI escapes)."""
    if os.environ.get("NO_COLOR") is not None:
        return False
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


def _ensure_utf8_stdio() -> None:
    """M11 — enforce UTF-8 on stdout/stderr so box/table Unicode never
    crashes on a non-UTF-8 locale. Uses errors='replace' so any byte that
    still cannot be encoded degrades to '?' instead of raising."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def _unicode_glyphs() -> bool:
    """L16 — verdict/spinner glyph fallback. Unicode marks (✓/✗/⠋…) are
    rendered only on an interactive TTY; piped/scripted output (and any
    run with EASYSHARK_ASCII=1) uses ASCII-safe alternatives so
    missing-font terminals never show boxes."""
    if os.environ.get("EASYSHARK_ASCII") is not None:
        return False
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


UNICODE_GLYPHS = _unicode_glyphs()


# ANSI colour constants (TUI redesign). Gated once at import time so every
# `from main import RESET, ...` importer inherits the NO_COLOR/isatty policy.
if _colors_enabled():
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    CYAN    = "\033[36m"
    BRIGHT_CYAN  = "\033[96m"
    GREEN   = "\033[32m"
    BRIGHT_GREEN = "\033[92m"
    YELLOW  = "\033[33m"
    WHITE   = "\033[97m"
    BORDER  = "\033[36m"  # cyan for box borders
else:
    RESET   = ""
    BOLD    = ""
    DIM     = ""
    CYAN    = ""
    BRIGHT_CYAN  = ""
    GREEN   = ""
    BRIGHT_GREEN = ""
    YELLOW  = ""
    WHITE   = ""
    BORDER  = ""


def _shark_art() -> str:
    """Return the ASCII shark art as a string, BRIGHT_CYAN coloured."""
    c = BRIGHT_CYAN
    r = RESET
    return (
        c + "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠲⣶⣶⣤⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀" + r + "\n"
        + c + "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠛⢻⣿⣷⣦⣀⠀⠀⠀⠀⠀⠀⠀" + r + "\n"
        + c + "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿⣿⣧⡄⠀⠀⠀⠀⠀" + r + "\n"
        + c + "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⣿⣿⣿⡆⠀⠀⠀⠀" + r + "\n"
        + c + "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⡄⠀⠀⠀" + r + "\n"
        + c + "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⣿⣿⣿⣦⡀⠀" + r + "\n"
        + c + "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣿⣿⣿⡿⠿⢿⣿⣷⡀" + r + "\n"
        + c + "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣶⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⡿⠿⠛⠉⠀⠀⠀⣻⣿⡇" + r + "\n"
        + c + "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⡇" + r + "\n"
        + c + "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣾⣿⣿⣿⠇" + r + "\n"
        + c + "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣶⣶⣶⣿⣿⣿⣿⣿⠏⠀" + r + "\n"
        + c + "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣦⣤⣤⣤⣤⣶⣶⣶⣶⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀" + r + "\n"
        + c + "⠀⠀⠀⢀⣀⣀⣀⣀⣀⣤⣤⣴⣶⣶⣶⣶⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠛⠋⠀⠀⠀" + r + "\n"
        + c + "⠲⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠛⠁⠀⠀⠀⠀⠀⠀" + r + "\n"
        + c + "⠀⠀⠉⠛⠿⣿⣿⣿⣿⣿⣏⣨⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀" + r + "\n"
        + c + "⠀⠀⠀⠀⠀⠈⠋⢉⣉⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠛⠛⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀" + r + "\n"
        + c + "⠀⠀⠀⠀⠀⠀⠀⠘⠛⠿⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀" + r + "\n"
        + c + "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠙⠛⠿⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀" + r + "\n"
        + c + "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⠟⠻⣿⣿⣿⣿⣿⣿⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀" + r + "\n"
        + c + "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⣿⠋⠀⠀⠀⠙⠿⣿⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀" + r + "\n"
        + c + "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠉⠛⠿⢿⣿⣷⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀" + r + "\n"
        + c + "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀" + r + "\n"
        + c + "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⠏⠀⠀⠀⠀"
    )


_ANSI_RE = re.compile(r"\033\[[0-9;]*m")
_ANSI_TOKEN_RE = re.compile(r"(\033\[[0-9;]*m)")


def _visible_len(text: str) -> int:
    """Return the visible length of text, excluding ANSI escape codes."""
    return len(_ANSI_RE.sub("", text))


def _display_width(text: str) -> int:
    """Return the terminal display width of text, excluding ANSI escapes.

    East Asian wide/fullwidth (W/F) characters count as 2 columns.
    Ambiguous-width chars (box-drawing, `█`) are counted as 1 so the
    fixed-width box borders stay aligned on the common 1x terminals;
    the wordmark itself is kept short enough to fit the box even on
    2x-rendering terminals (L14).
    """
    import unicodedata

    width = 0
    for ch in _ANSI_RE.sub("", text):
        if unicodedata.east_asian_width(ch) in ("W", "F"):
            width += 2
        else:
            width += 1
    return width


def _ljust_visible(text: str, width: int) -> str:
    """Left-justify text to display width, accounting for ANSI escapes."""
    visible = _display_width(text)
    pad = max(0, width - visible)
    return text + " " * pad


def _wrap_visible(text: str, width: int):
    """Word-wrap text to `width` visible columns, preserving ANSI colour
    codes (L13). Continuation lines reopen the colour code active at the
    wrapped word, so a boxed body never renders uncoloured text.

    Falls back to textwrap (word-boundary wrap) for ANSI-free input so
    existing boxed bodies are byte-for-byte unchanged.
    """
    if "\033" not in text:
        return textwrap.wrap(text, width=width)
    tokens = _ANSI_TOKEN_RE.split(text)
    lines = []
    cur = ""
    cur_visible = 0
    last_colour = ""
    for tok in tokens:
        if not tok:
            continue
        if _ANSI_TOKEN_RE.fullmatch(tok):
            cur += tok
            last_colour = tok
            continue
        for word in tok.split(" "):
            word_visible = _visible_len(word)
            if word_visible > width:
                if cur_visible > 0:
                    lines.append(cur)
                    cur = ""
                    cur_visible = 0
                lines.append(word)
                continue
            if cur_visible > 0 and cur_visible + word_visible > width:
                lines.append(cur)
                cur = last_colour
                cur_visible = 0
            cur += word + (" " if cur_visible > 0 else "")
            cur_visible += word_visible + (1 if cur_visible > 0 else 0)
    if cur_visible > 0:
        lines.append(cur)
    return lines


def _box(title: str, body_lines, width: int = 62) -> str:
    """Draw a thin bordered box around content."""
    c = CYAN
    r = RESET
    title_visible = _visible_len(title)
    top = c + "┌─ " + BOLD + title + r + c + " " + "─" * (width - title_visible - 3) + "┐" + r
    mid = []
    for line in body_lines:
        vlen = _visible_len(line)
        if vlen > width - 2:
            for wl in _wrap_visible(line, width=width - 2):
                mid.append(c + "│ " + r + WHITE + _ljust_visible(wl, width - 2) + r + c + " │" + r)
        else:
            mid.append(c + "│ " + r + WHITE + _ljust_visible(line, width - 2) + r + c + " │" + r)
    bot = c + "└" + "─" * width + "┘" + r
    return "\n".join([top] + mid + [bot])


def _render_banner(shell) -> str:
    """Build the full TUI banner string.

    Called after shell init so session, packet count, and flow count
    are all available.
    """
    W = 62
    border = BORDER
    c = RESET
    s = getattr(shell, "session", None)
    session_key = getattr(s, "key", "ESK-NEW-SESS") if s is not None else "ESK-NEW-SESS"
    pcap = getattr(shell, "pcap_file", "?")
    pkts = getattr(shell, "packets_raw", None)
    pkt_count = len(pkts) if pkts is not None else 0
    flow_count = len(getattr(shell.flow_engine, "flows", {})) if hasattr(shell, "flow_engine") else 0

    def _banner_line(content: str) -> str:
        return border + "║" + _ljust_visible(content, W) + "║" + c

    lines = []
    # Top border
    lines.append(border + "╔" + "═" * W + "╗" + c)
    lines.append(_banner_line(""))

    # Wordmark (compact so it fits the 62-col box even on terminals that
    # render U+2588 as 2 columns — 56 cols at 2x rendering)
    wordmark = BOLD + BRIGHT_CYAN + "███ ███ ███ █ █ ███ █ █ ███ ███ █ █" + c
    lines.append(_banner_line("  " + wordmark))
    lines.append(_banner_line(""))

    # Shark art
    art_lines = _shark_art().split("\n")
    for art_line in art_lines:
        lines.append(_banner_line("  " + art_line))

    # Divider
    lines.append(border + "╠" + "═" * W + "╣" + c)

    # Info section
    version = BOLD + BRIGHT_GREEN + "v1.00" + c
    devs = DIM + "Sagnik Ray | Suraj Mishra" + c
    wave = CYAN + DIM + "~~~ ~~~~ ~~~ ~~~~ ~~~ ~~~~~ ~~~ ~~~~ ~~~~ ~~~~~" + c
    session_val = BRIGHT_GREEN + session_key + c

    lines.append(_banner_line("  EasyShark " + version + " – Interactive PCAP Shell"))
    lines.append(_banner_line("  Developed By: " + devs))
    lines.append(_banner_line("  " + wave))
    lines.append(_banner_line(""))
    lines.append(_banner_line("    Session ID: " + session_val))
    lines.append(_banner_line("    PCAP: " + pcap))
    lines.append(_banner_line("    Packets: " + WHITE + str(pkt_count) + c + " | Flows: " + WHITE + str(flow_count) + c))

    # Bottom border
    lines.append(border + "╚" + "═" * W + "╝" + c)

    return "\n".join(lines)


def _print_sessions(mgr) -> None:
    sessions = mgr.list_sessions()
    if not sessions:
        print("No saved sessions. Run `python3 main.py <pcap>` to create one.")
        return
    print("Saved sessions (most recent first):")
    print(f"  {'KEY':<14} {'LAST ACTIVE':<22}  PCAP")
    print("  " + "-" * 100)
    for s in sessions:
        print(f"  {s.key:<14} {s.last_active:<22}  {s.pcap_path}")
        print("\nResume with: python3 main.py --session <key>")


def _prepare_state_dir() -> Path:
    """Select a writable state directory before importing stateful modules."""
    preferred = Path(os.environ.get(
        "EASYSHARK_STATE_DIR", str(Path.home() / ".easyshark")))
    try:
        preferred.mkdir(parents=True, exist_ok=True)
        probe = preferred / ".write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        state_dir = preferred
    except OSError:
        state_dir = Path.cwd() / ".easyshark"
        state_dir.mkdir(parents=True, exist_ok=True)
        print(f"Warning: using writable local state directory {state_dir}",
              file=sys.stderr)
    os.environ["EASYSHARK_STATE_DIR"] = str(state_dir)
    os.environ.setdefault("EASYSHARK_SESSIONS_DIR", str(state_dir / "sessions"))
    os.environ.setdefault("EASYSHARK_QUEUE_DB", str(state_dir / "jobs.db"))
    os.environ.setdefault("EASYSHARK_AUDIT_PATH", str(state_dir / "audit.jsonl"))
    os.environ.setdefault("EASYSHARK_MEMORY_DIR", str(state_dir))
    os.environ.setdefault("EASYSHARK_REPORTS_DIR", str(state_dir / "reports"))
    return state_dir


def main(argv=None):
    _ensure_utf8_stdio()
    parser = argparse.ArgumentParser(
        description="EasyShark — terminal-native Wireshark replacement with AI analysis.")
    parser.add_argument("pcap", nargs="?",
                        help="Path to a .pcap or .pcapng file (omit when resuming via --session)")
    parser.add_argument("--session", metavar="KEY",
                        help="Resume a saved session: ESK-XXXX-XXXX key or 'latest'")
    parser.add_argument("--sessions", action="store_true",
                        help="List saved sessions and exit")
    parser.add_argument("--forget", action="store_true",
                        help="Delete the session selected by --session and exit")
    parser.add_argument("--no-ai", action="store_true", help="Disable AI features")
    parser.add_argument("--autonomous", action="store_true",
                        help="Run one autonomous investigation and exit")
    parser.add_argument("--mission", default="Analyze the suspicious activity in this capture.",
                        help="Mission for --autonomous")
    parser.add_argument("--monitor", metavar="DIR",
                        help="Watch a directory and autonomously analyze new PCAPs")
    parser.add_argument("--interval", type=float, default=30.0,
                        help="Monitor polling interval in seconds")
    parser.add_argument("--once", action="store_true",
                        help="Run one monitor scan/queue drain and exit")
    parser.add_argument("--webhook", help="Optional alert webhook URL")
    parser.add_argument("--health-port", type=int,
                        help="Expose /health and /metrics for monitor mode")
    parser.add_argument("--event-log",
                        help="Write versioned JSONL mission events for SIEM ingestion")
    parser.add_argument("--event-webhook",
                        help="Optional HTTPS sink for versioned SIEM/SOAR events")
    parser.add_argument("--threat-feed",
                        help="Local JSON threat-intelligence feed for IOC enrichment")
    parser.add_argument("--debug", action="store_true", help="Verbose logging")
    args = parser.parse_args(argv)

    log_dir = _prepare_state_dir()
    handlers = [logging.FileHandler(log_dir / "easyshark.log", encoding="utf-8")]
    if args.debug:
        handlers.append(logging.StreamHandler())
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers,
    )

    from core.session_manager import SessionManager
    mgr = SessionManager()

    if args.monitor:
        from core.daemon import MissionDaemon
        try:
            MissionDaemon(args.monitor, args.mission, args.interval,
                          webhook=args.webhook,
                          health_port=args.health_port,
                          event_log=args.event_log,
                          threat_feed=args.threat_feed,
                          event_webhook=args.event_webhook).run(once=args.once)
        except Exception as exc:
            print(YELLOW + f"⚠ Monitor failed: {exc}" + RESET, file=sys.stderr)
            return 1
        return 0

    if args.sessions:
        _print_sessions(mgr)
        return 0

    if args.forget:
        if not args.session:
            print("--forget requires --session <key|latest>")
            return 2
        s = mgr.load(args.session) if args.session != "latest" else mgr.latest()
        if s is None:
            print(f"No session found for key {args.session!r} "
                  f"(use `--sessions` to list).")
            return 1
        mgr.delete(s.key)
        print(f"Forgot session {s.key} ({s.pcap_path})")
        return 0

    session = None
    pcap = args.pcap
    if args.session:
        session = mgr.load(args.session) if args.session != "latest" else mgr.latest()
        if session is None:
            print(f"No session found for key {args.session!r} "
                  f"(use `--sessions` to list).")
            return 1
        if not pcap:
            pcap = session.pcap_path
        if pcap:
            if not Path(pcap).exists():
                print(f"Warning: PCAP from session not found: {pcap}")
    if not pcap:
        print("No PCAP specified. Pass <pcap_path> or resume with --session <key>.")
        return 2

    if session is None:
        session = mgr.create(pcap)

    from cli.shell import InteractiveShell
    try:
        shell = InteractiveShell(pcap, enable_ai=not args.no_ai,
                                 session=session, session_manager=mgr)
    except FileNotFoundError as exc:
        print(YELLOW + "⚠ " + str(exc) + RESET, file=sys.stderr)
        print("  Check the path with `ls -l` and retry.", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(YELLOW + "⚠ " + str(exc) + RESET, file=sys.stderr)
        print("  Replace it with a non-empty .pcap/.pcapng file.", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - surface any load-time failure cleanly
        print(YELLOW + f"⚠ Failed to load PCAP: {exc}" + RESET, file=sys.stderr)
        if args.debug:
            raise
        return 1

    # Print TUI banner
    try:
        banner = _render_banner(shell)
        sys.stdout.write(banner + "\n")
        sys.stdout.flush()
    except UnicodeEncodeError:
        # ASCII-safe fallback banner (no em-dash, no box/Unicode glyphs).
        print("=" * 64)
        print("  EasyShark v1.00 - Interactive PCAP Shell")
        print("  Developed By: Sagnik Ray | Suraj Mishra")
        print("=" * 64)

    if args.autonomous:
        from cli.investigate_commands import InvestigateCommandHandler
        from core.threat_intel import ThreatIntel
        mission = args.mission.strip()
        if not mission:
            print("--mission must not be empty", file=sys.stderr)
            return 2
        try:
            intel = ThreatIntel(args.threat_feed or
                                os.environ.get("EASYSHARK_THREAT_FEED"))
        except Exception as exc:
            print(f"Invalid threat-intelligence feed: {exc}", file=sys.stderr)
            return 2
        handler = InvestigateCommandHandler(shell, threat_intel=intel)
        result = handler.handle("autonomous " + mission)
        if result:
            print(result, file=sys.stderr)
            return 1
        try:
            mgr.save(session)
        except Exception as exc:
            logging.getLogger(__name__).warning("session save failed: %s", exc)
        return 0

    shell.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
