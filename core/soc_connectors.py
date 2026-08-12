"""Read-only connector boundary for importing remote SOC telemetry."""
from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

from .soc_store import SOCStore, _value


class HTTPSJSONConnector:
    """Pull bounded JSON from an explicitly allow-listed HTTPS endpoint."""

    def __init__(self, store: Optional[SOCStore] = None, timeout: float = 30.0,
                 max_bytes: int = 50 * 1024 * 1024):
        self.store = store or SOCStore()
        self.timeout = timeout
        self.max_bytes = max_bytes

    @staticmethod
    def _validate_url(url: str) -> None:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("connectors require an HTTPS endpoint")
        allowed = {host.strip().lower() for host in os.environ.get(
            "EASYSHARK_CONNECTOR_HOSTS", "").split(",") if host.strip()}
        if parsed.hostname.lower() not in allowed:
            raise ValueError(
                "connector host is not approved; add the exact hostname to "
                "EASYSHARK_CONNECTOR_HOSTS")

    def pull(self, source: str, url: str,
             token_env: Optional[str] = None) -> Dict[str, int]:
        self._validate_url(url)
        headers = {"Accept": "application/json", "User-Agent": "EasyShark-CYSOC/2"}
        if token_env:
            token = os.environ.get(token_env)
            if not token:
                raise ValueError(f"connector token environment variable is unset: {token_env}")
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            raw = response.read(self.max_bytes + 1)
        if len(raw) > self.max_bytes:
            raise ValueError("connector response exceeds size limit")
        payload: Any = json.loads(raw.decode("utf-8"))
        if isinstance(payload, list):
            rows = payload
        elif isinstance(payload, dict):
            rows = _value(payload, "events", "alerts", "data", "results", "items") or [payload]
        else:
            raise ValueError("connector response must contain JSON objects")
        if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
            raise ValueError("connector records must be JSON objects")
        result = self.store.ingest(rows, source, auto_triage=True)
        from .audit import record
        from .event_sink import event_bus
        safe_url = urllib.parse.urlunsplit(
            (urllib.parse.urlsplit(url).scheme, urllib.parse.urlsplit(url).netloc,
             urllib.parse.urlsplit(url).path, "", ""))
        record("soc_connector_pull", source=source, endpoint=safe_url, **result)
        event_bus.publish("soc_connector_pull", {
            "source": source, "endpoint": safe_url, **result})
        return result
