"""Offline-first IOC enrichment with optional HTTPS JSON feeds."""
from __future__ import annotations

import json
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, Optional


class ThreatIntel:
    def __init__(self, feed_path: Optional[str] = None, timeout: float = 10.0):
        self.timeout = timeout
        self.records: Dict[str, Dict[str, Any]] = {}
        if feed_path:
            self.load_file(feed_path)

    def add(self, value: str, verdict: str = "unknown", source: str = "local",
            tags: Optional[Iterable[str]] = None) -> None:
        value = str(value).strip().lower()
        if value:
            self.records[value] = {"value": value, "verdict": verdict,
                                   "source": source, "tags": list(tags or [])}

    def load_file(self, path: str) -> int:
        rows = json.loads(Path(path).read_text(encoding="utf-8"))
        return self._load_rows(rows)

    def _load_rows(self, rows) -> int:
        if isinstance(rows, dict):
            rows = rows.get("indicators", [])
        if not isinstance(rows, list):
            raise ValueError("threat-intel feed must be a JSON list")
        for row in rows:
            if isinstance(row, str):
                self.add(row)
            elif isinstance(row, dict) and row.get("value"):
                self.add(row["value"], row.get("verdict", "unknown"),
                         row.get("source", "local"), row.get("tags"))
        return len(rows)

    def load_url(self, url: str, max_bytes: int = 5 * 1024 * 1024) -> int:
        if not url.startswith("https://"):
            raise ValueError("threat-intel feeds must use HTTPS")
        with urllib.request.urlopen(url, timeout=self.timeout) as response:
            data = response.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError("threat-intel feed exceeds size limit")
        return self._load_rows(json.loads(data.decode("utf-8")))

    def lookup(self, value: str) -> Optional[Dict[str, Any]]:
        return self.records.get(str(value).strip().lower())

    def enrich(self, values: Iterable[str]) -> Dict[str, Dict[str, Any]]:
        return {str(v): hit for v in values if (hit := self.lookup(str(v)))}
