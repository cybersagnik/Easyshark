"""Approved notification adapters built on EasyShark's durable webhook outbox."""
from __future__ import annotations

from typing import Any, Optional

from .monitor import WebhookAlerter


class IntegrationHub:
    def __init__(self, slack: Optional[str] = None, teams: Optional[str] = None,
                 pagerduty: Optional[str] = None, approved: bool = False):
        self._targets = {}
        for name, url in (("slack", slack), ("teams", teams), ("pagerduty", pagerduty)):
            if url:
                self._targets[name] = WebhookAlerter(url, approved=approved)

    def send(self, event: dict[str, Any]) -> int:
        sent = 0
        for name, target in self._targets.items():
            payload = {"text": event.get("message", event.get("event", "EasyShark event")),
                       "easyshark": event, "integration": name}
            try:
                target.send(payload)
                sent += 1
            except Exception:
                continue
        return sent

    def drain(self) -> int:
        return sum(target.drain() for target in self._targets.values())
