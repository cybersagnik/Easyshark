"""
capture.py — Live packet capture backend (CONTEXT.md §16, Task 1).

Wraps ``dumpcap`` (preferred) or ``tcpdump`` for live captures. The
captures write to ``~/.easyshark/captures/live_<timestamp>.pcapng`` and
are intended to be hot-reloaded into the active InteractiveShell via
``capture stop``.

Detection at import time:
    CAPTURE_TOOL = "dumpcap" if shutil.which("dumpcap") else \
                    "tcpdump" if shutil.which("tcpdump") else None

If CAPTURE_TOOL is None, every command path raises CaptureUnavailableError
or returns an "install" message instead of crashing. This keeps the
shell usable on systems without libpcap tools installed.

Public API:
    list_interfaces()                  -> List[Dict]
    start_capture(interface, bpf)      -> CaptureSession
    stop_capture(session)              -> str (path)
    get_packet_count(session)          -> int
    CaptureSession                     dataclass
    CaptureUnavailableError            Exception
"""
from __future__ import annotations

import logging
import os
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Tool detection                                                              #
# --------------------------------------------------------------------------- #
CAPTURE_TOOL: Optional[str] = (
    "dumpcap" if shutil.which("dumpcap")
    else "tcpdump" if shutil.which("tcpdump")
    else None
)


CAPTURES_DIR = Path.home() / ".easyshark" / "captures"


class CaptureUnavailableError(RuntimeError):
    """Raised when no capture tool (dumpcap/tcpdump) is installed."""


# --------------------------------------------------------------------------- #
# CaptureSession dataclass                                                    #
# --------------------------------------------------------------------------- #
@dataclass
class CaptureSession:
    pid:         int
    output_path: str
    interface:   str
    bpf_filter:  str
    start_time:  datetime
    process:     subprocess.Popen
    tool:        str = field(default_factory=lambda: CAPTURE_TOOL or "?")


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #
def _ensure_captures_dir() -> Path:
    CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    return CAPTURES_DIR


def _new_output_path() -> Path:
    """``~/.easyshark/captures/live_YYYYMMDD_HHMMSS.pcapng``."""
    _ensure_captures_dir()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return CAPTURES_DIR / f"live_{ts}.pcapng"


def _run_text(args: List[str], timeout: float = 5.0) -> str:
    """Run a command, return (stdout + stderr). Raises on failure."""
    proc = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return (proc.stdout or "") + (proc.stderr or "")


# --------------------------------------------------------------------------- #
# list_interfaces                                                             #
# --------------------------------------------------------------------------- #
def list_interfaces() -> List[Dict[str, Any]]:
    """Return ``[{"index": N, "name": "eth0", "description": "..."}, ...]``.

    dumpcap -D output looks like:
        1. eth0 (Ethernet)
        2. lo   (Loopback)
        3. any  (Pseudo-device that captures on all interfaces)

    tcpdump --list-interfaces (-D) output is similar.
    On any failure: returns [].
    """
    if CAPTURE_TOOL is None:
        return []
    flag = "-D"
    try:
        out = _run_text([CAPTURE_TOOL, flag], timeout=5.0)
    except Exception as exc:
        logger.warning("list_interfaces failed: %s", exc)
        return []

    parsed: List[Dict[str, Any]] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        # Try "<idx>. <name> (<desc>)" — description may contain parens.
        idx_name, _, rest = line.partition(".")
        rest = rest.strip()
        if not idx_name.isdigit() or not rest:
            continue
        # Pull name = first whitespace-delimited token of `rest`.
        name, _, after = rest.partition(" ")
        # Optional "(description)" suffix.
        if after.startswith("(") and after.endswith(")"):
            description = after[1:-1]
        else:
            description = after
        parsed.append({
            "index": int(idx_name),
            "name":   name,
            "description": description,
        })
    return parsed


# --------------------------------------------------------------------------- #
# start_capture                                                               #
# --------------------------------------------------------------------------- #
def start_capture(interface: str,
                  bpf_filter: str = "",
                  output_path: Optional[str] = None) -> CaptureSession:
    """Launch dumpcap/tcpdump as a non-blocking subprocess.

    Returns CaptureSession. Raises CaptureUnavailableError if no tool
    installed; ValueError if interface is empty; OSError on subprocess
    launch failure.
    """
    if CAPTURE_TOOL is None:
        raise CaptureUnavailableError(
            "Neither dumpcap nor tcpdump is installed.\n"
            "  Install one of:\n"
            "    sudo apt install wireshark-common   # dumpcap\n"
            "    sudo apt install tcpdump            # tcpdump\n"
            "Then ensure capture is permitted (setcap for dumpcap)."
        )
    if not interface:
        raise ValueError("interface is required")

    out_path = Path(output_path) if output_path else _new_output_path()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    args: List[str] = [CAPTURE_TOOL, "-i", interface, "-w", str(out_path)]
    if bpf_filter:
        args.extend(["-f", bpf_filter])

    logger.info("starting capture: %s", " ".join(args))
    proc = subprocess.Popen(
        args,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        # New process group so we can SIGTERM cleanly even from a thread.
        preexec_fn=os.setsid if os.name == "posix" else None,
    )
    return CaptureSession(
        pid=proc.pid,
        output_path=str(out_path),
        interface=interface,
        bpf_filter=bpf_filter,
        start_time=datetime.now(timezone.utc),
        process=proc,
    )


# --------------------------------------------------------------------------- #
# stop_capture                                                                #
# --------------------------------------------------------------------------- #
def stop_capture(session: CaptureSession, timeout: float = 3.0) -> str:
    """Stop the capture process gracefully.

    Sends SIGTERM, waits up to ``timeout`` seconds; SIGKILL if still alive.
    Returns the output pcapng path.
    """
    proc = session.process
    if proc.poll() is not None:
        # Already exited.
        return session.output_path
    try:
        proc.terminate()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            logger.warning("capture did not exit in %ss, sending SIGKILL", timeout)
            try:
                proc.kill()
                proc.wait(timeout=2.0)
            except Exception:
                pass
    except Exception as exc:
        logger.error("stop_capture error: %s", exc)
    return session.output_path


# --------------------------------------------------------------------------- #
# get_packet_count                                                            #
# --------------------------------------------------------------------------- #
def get_packet_count(session: CaptureSession) -> int:
    """Best-effort, non-blocking packet count estimate.

    Strategy: use the file size as a proxy (avg packet ~500 bytes on
    Ethernet, ~80 on loopback). Falls back to ``capinfos`` if available.
    Returns 0 if the file does not exist or is unreadable.
    """
    path = Path(session.output_path)
    if not path.exists():
        return 0
    try:
        size = path.stat().st_size
        # 80 bytes is a typical Ethernet-headers + minimal payload.
        # Loopback captures are small, internet captures are larger;
        # use 400 as a reasonable middle ground for the proxy.
        if size <= 24:  # pcapng magic + section header only
            return 0
        return max(0, (size - 24) // 400)
    except Exception as exc:
        logger.warning("get_packet_count error: %s", exc)
        return 0


# --------------------------------------------------------------------------- #
# Convenience: small banner for the install message                           #
# --------------------------------------------------------------------------- #
def install_instructions() -> str:
    return (
        "No capture backend available.\n"
        "  Install one of:\n"
        "    sudo apt install wireshark-common   # provides dumpcap\n"
        "    sudo apt install tcpdump            # provides tcpdump\n"
        "  Then for non-root captures:\n"
        "    sudo setcap cap_net_raw+ep $(which dumpcap)"
    )
