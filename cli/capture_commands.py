"""
capture_commands.py — live capture shell verbs (CONTEXT.md §16, Task 1).

Commands:
    capture interfaces                  — list capture interfaces
    capture start [interface] [filter]  — begin a live capture
    capture status                      — show elapsed + packet estimate
    capture stop                        — stop, hot-reload, auto-report

Adds a self.capture_session attribute to InteractiveShell (None when idle).
"""
from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Optional

from .formatter import OutputFormatter

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Handler                                                                      #
# --------------------------------------------------------------------------- #
class CaptureCommandHandler:
    """Mirrors cli.commands.CommandHandler interface."""

    def __init__(self, shell):
        self.shell = shell
        self.fmt = OutputFormatter()

    # ------------------------------------------------------------------ #
    # Entry                                                              #
    # ------------------------------------------------------------------ #
    def handle(self, line: str) -> Optional[str]:
        line = line.strip()
        if not line:
            return None
        parts = line.split(None, 2)
        verb = parts[0].lower()
        if verb != "capture":
            return self.fmt.error(f"unknown capture subcommand: {verb}")
        sub = parts[1].lower() if len(parts) > 1 else ""
        rest = parts[2] if len(parts) > 2 else ""
        return self._dispatch(sub, rest)

    def _dispatch(self, sub: str, rest: str) -> Optional[str]:
        table = {
            "interfaces":  lambda: self.cmd_interfaces(),
            "start":       lambda: self.cmd_start(rest),
            "stop":        lambda: self.cmd_stop(),
            "status":      lambda: self.cmd_status(),
        }
        fn = table.get(sub)
        if fn is None:
            return self.fmt.error(f"unknown capture subcommand: {sub}\n"
                                  f"(try: interfaces, start, stop, status)")
        try:
            return fn()
        except Exception as exc:
            logger.error("capture %s failed: %s", sub, exc, exc_info=True)
            return self.fmt.error(str(exc))

    # ------------------------------------------------------------------ #
    # interfaces                                                         #
    # ------------------------------------------------------------------ #
    def cmd_interfaces(self) -> str:
        from core import capture
        if capture.CAPTURE_TOOL is None:
            return capture.install_instructions()
        ifaces = capture.list_interfaces()
        if not ifaces:
            return (f"No interfaces returned by {capture.CAPTURE_TOOL}.\n"
                    f"(Try running: sudo {capture.CAPTURE_TOOL} -D)")
        lines = [f"Available interfaces (via {capture.CAPTURE_TOOL}):"]
        for i in ifaces:
            desc = i.get("description") or ""
            line = f"  [{i['index']}] {i['name']:<12s}"
            if desc:
                line += f"  — {desc}"
            lines.append(line)
        lines.append("")
        lines.append("Usage: capture start <name-or-index> [bpf-filter]")
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    # start                                                              #
    # ------------------------------------------------------------------ #
    def cmd_start(self, rest: str) -> str:
        from core import capture

        if self.shell.capture_session is not None:
            return ("A capture session is already running.\n"
                    "Type 'capture stop' first to finish it.")

        if capture.CAPTURE_TOOL is None:
            return capture.install_instructions()

        # Parse: first token is interface (name or numeric index);
        # remainder is treated as a single BPF filter string.
        rest = rest.strip()
        interface: Optional[str] = None
        bpf: str = ""
        if not rest:
            interface = "eth0"  # sensible default per spec
        else:
            tokens = rest.split(None, 1)
            head = tokens[0]
            bpf = tokens[1].strip() if len(tokens) > 1 else ""
            # Numeric index? Resolve to a name from list_interfaces.
            if head.isdigit():
                idx = int(head)
                ifaces = capture.list_interfaces()
                match = next((i for i in ifaces if i["index"] == idx), None)
                if match is None:
                    return (f"No interface with index {idx}.\n"
                            f"Run 'capture interfaces' to see the list.")
                interface = match["name"]
            else:
                interface = head

        try:
            session = capture.start_capture(interface, bpf)
        except capture.CaptureUnavailableError as exc:
            return f"Cannot start capture: {exc}"
        except PermissionError as exc:
            return (f"Permission denied starting capture on {interface}.\n"
                    f"Try: sudo setcap cap_net_raw+ep $(which {capture.CAPTURE_TOOL})\n"
                    f"Detail: {exc}")
        except FileNotFoundError as exc:
            # dumpcap/tcpdump binary disappeared mid-flight.
            return f"Capture tool not found: {exc}"
        except Exception as exc:
            # Subprocess launch error — try to extract stderr from session
            # if available; fall back to the exception text.
            stderr_text = ""
            try:
                stderr_text = (session.process.stderr.read(2000).decode("utf-8", "replace")
                               if session.process.stderr else "")
            except Exception:
                pass
            if not stderr_text:
                return f"Capture failed: {exc}"
            return (f"Capture failed on {interface}:\n"
                    f"  {stderr_text.strip().splitlines()[0] if stderr_text else str(exc)}\n"
                    f"  Run 'capture interfaces' to verify the name.")

        self.shell.capture_session = session

        # Spawn background status thread.
        thread = threading.Thread(
            target=_status_loop,
            args=(self.shell,),
            daemon=True,
            name="easyshark-capture-status",
        )
        thread.start()

        bpf_part = f" (filter: \"{bpf}\")" if bpf else ""
        return (f"Capturing on {interface}{bpf_part}...\n"
                f"  Output: {session.output_path}\n"
                f"  PID:    {session.pid}\n"
                f"  Tool:   {session.tool}\n"
                f"  Type 'capture stop' to finish.")

    # ------------------------------------------------------------------ #
    # stop                                                               #
    # ------------------------------------------------------------------ #
    def cmd_stop(self) -> str:
        from core import capture

        session = self.shell.capture_session
        if session is None:
            return "No active capture session."

        # Stop the process.
        out_path = capture.stop_capture(session)
        pkt_estimate = capture.get_packet_count(session)
        self.shell.capture_session = None

        if pkt_estimate == 0:
            try:
                real_size = os.path.getsize(out_path)
            except OSError:
                real_size = 0
            return (f"Capture stopped. 0 packets captured.\n"
                    f"  File: {out_path} ({real_size} bytes)\n"
                    f"  No hot-reload (empty capture).\n"
                    f"  Existing shell state unchanged.")

        # Hot-reload + packet summary.
        try:
            new_count = self.shell.reload_packets(out_path)
        except FileNotFoundError:
            return f"Capture stopped. File missing: {out_path}"

        return (
            f"Capture complete. {new_count:,} packets saved to {out_path}\n"
            f"  Hot-reloaded into current shell.\n"
            f"  Use `analyze <question>` to ask about this capture."
        )

    # ------------------------------------------------------------------ #
    # status                                                             #
    # ------------------------------------------------------------------ #
    def cmd_status(self) -> str:
        from core import capture

        session = self.shell.capture_session
        if session is None:
            return "No active capture session."

        if session.process.poll() is not None:
            return (f"Capture process exited unexpectedly (rc={session.process.returncode}).\n"
                    f"Run 'capture stop' to clean up.")

        elapsed = (datetime.now(timezone.utc) - session.start_time).total_seconds()
        pkt_estimate = capture.get_packet_count(session)
        return (f"Capture active on {session.interface} (PID {session.pid}).\n"
                f"  Elapsed:      {_fmt_dur(elapsed)}\n"
                f"  Packets (est): {pkt_estimate:,}\n"
                f"  Output:       {session.output_path}")


# --------------------------------------------------------------------------- #
# Background status printer                                                   #
# --------------------------------------------------------------------------- #
def _status_loop(shell):
    """Print a status line every 10s while a capture is active.

    Daemon thread; exits when ``shell.capture_session`` becomes None or
    the process exits.
    """
    from core import capture
    while True:
        if shell.capture_session is None:
            return
        session = shell.capture_session
        if session.process.poll() is not None:
            return
        elapsed = (datetime.now(timezone.utc) - session.start_time).total_seconds()
        pkt = capture.get_packet_count(session)
        print(f"  [live] {pkt:,} packets captured — {_fmt_dur(elapsed)} elapsed")
        time.sleep(10)


def _fmt_dur(seconds: float) -> str:
    if seconds < 60:    return f"{seconds:.0f}s"
    if seconds < 3600:  return f"{seconds/60:.1f}m"
    return f"{seconds/3600:.1f}h"
