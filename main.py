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
import re
import sys
import textwrap
from pathlib import Path


# ANSI colour constants (TUI redesign)
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


def _visible_len(text: str) -> int:
    """Return the visible length of text, excluding ANSI escape codes."""
    return len(_ANSI_RE.sub("", text))


def _ljust_visible(text: str, width: int) -> str:
    """Left-justify text to width, accounting for ANSI escape codes."""
    visible = _visible_len(text)
    pad = max(0, width - visible)
    return text + " " * pad


def _box(title: str, body_lines, width: int = 62) -> str:
    """Draw a thin bordered box around content."""
    c = CYAN
    r = RESET
    title_visible = _visible_len(title)
    top = c + "┌─ " + BOLD + title + r + c + " " + "─" * (width - title_visible - 4) + "┐" + r
    mid = []
    for line in body_lines:
        vlen = _visible_len(line)
        if vlen > width - 2:
            for wl in textwrap.wrap(line, width=width - 2):
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

    # Wordmark
    wordmark = BOLD + BRIGHT_CYAN + "███████  █████  ███████ ██   ██  █████  ██████  ██   ██" + c
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
    devs = BOLD + YELLOW + "Sagnik Ray | Suraj Mishra" + c
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


def main(argv=None):
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
    parser.add_argument("--debug", action="store_true", help="Verbose logging")
    args = parser.parse_args(argv)

    log_dir = Path.home() / ".easyshark"
    log_dir.mkdir(parents=True, exist_ok=True)
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
    shell = InteractiveShell(pcap, enable_ai=not args.no_ai,
                             session=session, session_manager=mgr)

    # Print TUI banner
    try:
        banner = _render_banner(shell)
        sys.stdout.write(banner + "\n")
        sys.stdout.flush()
    except UnicodeEncodeError:
        print("=" * 64)
        print("  EasyShark v1.00 — Interactive PCAP Shell")
        print("  Developed By: Sagnik Ray | Suraj Mishra")
        print("=" * 64)

    shell.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
