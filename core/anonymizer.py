"""Reversible-in-process-safe anonymization helpers for external analysis."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
from typing import Any

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)


class Anonymizer:
    def __init__(self, secret: str = "easyshark-local-anonymizer"):
        self.secret = secret.encode("utf-8")
        self._ips: dict[str, str] = {}
        self._emails: dict[str, str] = {}

    def ip(self, value: str) -> str:
        if not value:
            return value
        if value in self._ips:
            return self._ips[value]
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return value
        digest = hmac.new(self.secret, value.encode(), hashlib.sha256).digest()
        mapped = f"10.{digest[0]}.{digest[1]}.{max(1, digest[2])}"
        self._ips[value] = mapped
        return mapped

    def text(self, value: str) -> str:
        def replace_ip(match):
            return self.ip(match.group(0))
        def replace_email(match):
            original = match.group(0).lower()
            if original not in self._emails:
                token = hashlib.sha256(self.secret + original.encode()).hexdigest()[:12]
                self._emails[original] = f"user-{token}@example.invalid"
            return self._emails[original]
        value = _IP_RE.sub(replace_ip, value or "")
        return _EMAIL_RE.sub(replace_email, value)

    def metadata(self, item: Any) -> dict[str, Any]:
        """Copy a PacketMetadata-like object into an LLM-safe dictionary."""
        fields = ("index", "timestamp", "length", "src_ip", "dst_ip",
                  "src_port", "dst_port", "protocol", "tcp_flags", "ttl")
        return {field: self.ip(getattr(item, field)) if field in ("src_ip", "dst_ip")
                else getattr(item, field, None) for field in fields}

    def bundle(self, packets) -> list[dict[str, Any]]:
        return [self.metadata(packet) for packet in packets or []]


def anonymize_text(value: str, secret: str = "easyshark-local-anonymizer") -> str:
    return Anonymizer(secret).text(value)


def anonymize_packets(packets, secret: str = "easyshark-local-anonymizer") -> list[dict[str, Any]]:
    return Anonymizer(secret).bundle(packets)
