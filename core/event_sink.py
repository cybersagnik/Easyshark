"""Pluggable event sinks for SIEM/SOAR adapters."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, Iterable


def envelope(event: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    return {"schema": "easyshark.event.v1", "event": event,
            "ts": time.time(), "payload": payload}


class JsonlSink:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def send(self, event: str, payload: Dict[str, Any]) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(envelope(event, payload), default=str) + "\n")


class WebhookSink:
    """Send versioned events through an existing durable webhook transport."""

    def __init__(self, alerter):
        self.alerter = alerter

    def send(self, event: str, payload: Dict[str, Any]) -> None:
        self.alerter.send(envelope(event, payload))


class MultiSink:
    def __init__(self, sinks: Iterable[Any]):
        self.sinks = list(sinks)

    def send(self, event: str, payload: Dict[str, Any]) -> None:
        for sink in self.sinks:
            sink.send(event, payload)
