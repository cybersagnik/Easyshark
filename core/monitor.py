"""Polling monitor for autonomous PCAP missions and webhook alerts."""
from __future__ import annotations

import json
import queue
import threading
import time
import urllib.request
from pathlib import Path
from typing import Callable, Dict, Optional, Set

from .audit import record
from .alert_outbox import AlertOutbox
from .observability import increment


class WebhookAlerter:
    def __init__(self, url: str, timeout: float = 10.0, retries: int = 3,
                 token: Optional[str] = None, outbox_path: Optional[str] = None,
                 approved: bool = False):
        import os
        from .policy import ActionTier, authorize
        if not authorize(ActionTier.EXTERNAL_NOTIFY, approved=approved):
            raise PermissionError(
                "external notifications require explicit approval")
        if not url.startswith("https://") and os.environ.get("EASYSHARK_ALLOW_HTTP_WEBHOOK") != "1":
            raise ValueError("webhook URL must use https (set EASYSHARK_ALLOW_HTTP_WEBHOOK=1 for local HTTP)")
        self.url, self.timeout = url, timeout
        self.retries, self.token = max(0, retries), token
        self._sent = set()
        self.outbox = AlertOutbox(outbox_path)

    def send(self, event: Dict) -> None:
        body = json.dumps(event, default=str).encode("utf-8")
        event_id = json.dumps(event, sort_keys=True, default=str)
        if event_id in self._sent:
            return
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        last = None
        for attempt in range(self.retries + 1):
            try:
                req = urllib.request.Request(self.url, data=body, method="POST",
                                             headers=headers)
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    if response.status >= 300:
                        raise RuntimeError(f"webhook returned HTTP {response.status}")
                self._sent.add(event_id)
                break
            except Exception as exc:
                last = exc
                if attempt < self.retries:
                    time.sleep(min(2 ** attempt, 8))
        else:
            self.outbox.put(event)
            raise RuntimeError(f"webhook delivery failed: {last}")
        record("external_alert", target=self.url, event=event)

    def drain(self, limit: int = 50) -> int:
        delivered = 0
        for row in self.outbox.pending(limit):
            try:
                self.send(row["event"])
                self.outbox.remove(row["id"])
                delivered += 1
            except Exception:
                break
        return delivered


class PCAPMonitor:
    def __init__(self, directory: str, on_capture: Callable[[str], None],
                 alerter: Optional[WebhookAlerter] = None,
                 workers: int = 1, stable_for: float = 2.0):
        self.directory = Path(directory).resolve()
        self.on_capture = on_capture
        self.alerter = alerter
        self.seen: Set[str] = set()
        self.stable_for = max(0.0, stable_for)
        self.workers = max(1, workers)
        self._jobs: "queue.Queue[str]" = queue.Queue()
        self._threads = []
        for i in range(self.workers):
            thread = threading.Thread(target=self._worker, daemon=True,
                                      name=f"easyshark-monitor-{i}")
            thread.start()
            self._threads.append(thread)

    def _worker(self):
        while True:
            path = self._jobs.get()
            try:
                self.on_capture(path)
            except Exception as exc:
                increment("monitor.errors")
                record("capture_failed", path=path, error=str(exc))
                if self.alerter:
                    try:
                        self.alerter.send({"event": "capture_failed", "path": path, "error": str(exc)})
                    except Exception as alert_exc:
                        record("alert_failed", error=str(alert_exc))
            finally:
                self._jobs.task_done()

    def scan_once(self) -> int:
        self.directory.mkdir(parents=True, exist_ok=True)
        found = 0
        for path in sorted(self.directory.iterdir()):
            if path.suffix.lower() not in (".pcap", ".pcapng") or not path.is_file():
                continue
            key = str(path) + ":" + str(path.stat().st_size) + ":" + str(path.stat().st_mtime_ns)
            if key in self.seen:
                continue
            if self.stable_for:
                size, mtime = path.stat().st_size, path.stat().st_mtime_ns
                time.sleep(self.stable_for)
                try:
                    current = path.stat()
                except OSError:
                    continue
                if current.st_size != size or current.st_mtime_ns != mtime:
                    continue
            self.seen.add(key)
            found += 1
            increment("monitor.captures")
            record("capture_detected", path=str(path))
            self._jobs.put(str(path))
        return found

    def run(self, interval: float = 30.0, once: bool = False) -> None:
        if interval <= 0:
            raise ValueError("interval must be positive")
        while True:
            self.scan_once()
            if once:
                return
            time.sleep(interval)
