"""Offline-first IOC enrichment with optional HTTPS JSON feeds."""
from __future__ import annotations

import json
import time
import urllib.parse
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

    def _request_json(self, url: str, *, data: Optional[Dict[str, Any]] = None,
                      headers: Optional[Dict[str, str]] = None) -> Any:
        """Fetch a bounded HTTPS JSON response from a trusted feed provider."""
        if not url.startswith("https://"):
            raise ValueError("threat-intel providers must use HTTPS")
        body = (urllib.parse.urlencode(data).encode("utf-8")
                if data is not None else None)
        request = urllib.request.Request(
            url, data=body,
            headers={"Accept": "application/json", **(headers or {})})
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            raw = response.read(5 * 1024 * 1024 + 1)
        if len(raw) > 5 * 1024 * 1024:
            raise ValueError("threat-intel provider response exceeds size limit")
        return json.loads(raw.decode("utf-8"))

    def update_provider(self, provider: str, api_key: Optional[str] = None) -> int:
        """Update from an abuse.ch provider and return newly cached IOC count."""
        provider = provider.strip().lower()
        before = len(self.records)
        if provider == "feodo":
            rows = self._request_json(
                "https://feodotracker.abuse.ch/downloads/ipblocklist.json")
            for row in rows if isinstance(rows, list) else []:
                if isinstance(row, dict) and row.get("ip_address"):
                    self.add(row["ip_address"], "malicious", "feodo",
                             [row.get("malware"), row.get("status")])
        elif provider == "urlhaus":
            if not api_key:
                raise ValueError("urlhaus requires an Auth-Key")
            payload = self._request_json(
                "https://urlhaus-api.abuse.ch/v1/urls/recent/",
                headers={"Auth-Key": api_key})
            for row in payload.get("urls", []) if isinstance(payload, dict) else []:
                if not isinstance(row, dict) or not row.get("url"):
                    continue
                value = str(row["url"]).strip().lower()
                tags = row.get("tags") or []
                if isinstance(tags, str):
                    tags = [tag.strip() for tag in tags.split(",") if tag.strip()]
                self.add(value, "malicious", "urlhaus", tags)
                host = urllib.parse.urlsplit(value).hostname
                if host:
                    self.add(host, "malicious", "urlhaus", tags)
        elif provider == "threatfox":
            if not api_key:
                raise ValueError("threatfox requires an Auth-Key")
            payload = self._request_json(
                "https://threatfox-api.abuse.ch/api/v1/",
                data={"query": "get_iocs", "days": "7"},
                headers={"Auth-Key": api_key})
            for row in payload.get("data", []) if isinstance(payload, dict) else []:
                if not isinstance(row, dict) or not row.get("ioc"):
                    continue
                value = str(row["ioc"]).strip().lower()
                tags = list(row.get("tags") or [])
                if row.get("malware"):
                    tags.append(str(row["malware"]))
                self.add(value, "malicious", "threatfox", tags)
                host = value.rsplit(":", 1)[0] if value.count(":") == 1 else value
                if host != value:
                    self.add(host, "malicious", "threatfox", tags)
        else:
            raise ValueError("provider must be feodo, urlhaus, or threatfox")
        return len(self.records) - before

    def save_file(self, path: str) -> int:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps({"updated_at": time.time(),
                                      "indicators": list(self.records.values())},
                                     indent=2), encoding="utf-8")
        return len(self.records)

    def lookup(self, value: str) -> Optional[Dict[str, Any]]:
        return self.records.get(str(value).strip().lower())

    def enrich(self, values: Iterable[str]) -> Dict[str, Dict[str, Any]]:
        return {str(v): hit for v in values if (hit := self.lookup(str(v)))}
