"""Treat packet and connector content as evidence, never as instructions."""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List


_INJECTION_PATTERNS = (
    re.compile(r"\bignore\s+(?:all\s+)?(?:previous|prior|system)\s+instructions?\b", re.I),
    re.compile(r"\b(?:system|assistant|developer)\s*(?:prompt|message|:)\b", re.I),
    re.compile(r"\b(?:call|invoke|execute|run)\s+(?:the\s+)?(?:tool|command|shell)\b", re.I),
    re.compile(r"<\/?(?:system|assistant|developer|tool)[^>]*>", re.I),
    re.compile(r"\b(?:reveal|print|exfiltrate)\b.{0,40}\b(?:secret|token|prompt|credential)\b", re.I),
)


def safe_text(value: Any, limit: int = 2000) -> str:
    """Bound text and remove terminal/control characters without hiding evidence."""
    text = str(value or "")[: max(0, limit)]
    return "".join(ch if ch in "\n\t" or ord(ch) >= 32 else "�" for ch in text)


def injection_signals(value: Any) -> List[str]:
    text = safe_text(value)
    return [pattern.pattern for pattern in _INJECTION_PATTERNS if pattern.search(text)]


def envelope(value: Any, *, source: str, field: str = "content",
             limit: int = 2000) -> Dict[str, Any]:
    """Typed representation suitable for placement in an LLM user message."""
    text = safe_text(value, limit)
    signals = injection_signals(text)
    return {
        "trust": "untrusted_observation",
        "source": safe_text(source, 120),
        "field": safe_text(field, 120),
        "content": text,
        "instruction_semantics": False,
        "prompt_injection_suspected": bool(signals),
        "signals": signals,
    }


def scan_packets(packets: Iterable[Any]) -> List[Dict[str, Any]]:
    findings = []
    for packet in packets or []:
        payload = getattr(packet, "payload", b"") or b""
        if not payload:
            continue
        text = payload[:4096].decode("utf-8", errors="replace")
        signals = injection_signals(text)
        if signals:
            findings.append({
                "packet": int(getattr(packet, "index", len(findings))),
                "src_ip": getattr(packet, "src_ip", None),
                "dst_ip": getattr(packet, "dst_ip", None),
                "signals": signals,
                "sample": safe_text(text, 240),
            })
    return findings
