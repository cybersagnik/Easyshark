"""Treat packet and connector content as evidence, never as instructions."""
from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
import urllib.parse
from typing import Any, Dict, Iterable, List


_INJECTION_PATTERNS = (
    re.compile(r"\bignore\s+(?:all\s+)?(?:previous|prior|system)\s+instructions?\b", re.I),
    re.compile(r"\b(?:system|assistant|developer)(?:\s+(?:prompt|message))?\s*:", re.I),
    re.compile(r"\b(?:call|invoke|execute|run)\s+(?:the\s+)?(?:tool|command|shell)\b", re.I),
    re.compile(r"<\/?(?:system|assistant|developer|tool)[^>]*>", re.I),
    re.compile(r"\b(?:reveal|print|exfiltrate)\b.{0,40}\b(?:secret|token|prompt|credential)\b", re.I),
    re.compile(r"\b(?:approve|authorize|deny)\b.{0,40}\b(?:action|response|containment|isolation)\b", re.I),
    re.compile(r"\b(?:suppress|disable|drop|hide)\b.{0,40}\b(?:alert|finding|verdict|detection)\b", re.I),
    re.compile(r"\b(?:change|modify|override|mark)\b.{0,40}\b(?:verdict|priority|severity|finding)\b", re.I),
)

_BASE64_TOKEN = re.compile(
    r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
_QUARANTINED = "[prompt-injection-like content quarantined; inspect local evidence]"


def safe_text(value: Any, limit: int = 2000) -> str:
    """Bound text and remove terminal/control characters without hiding evidence."""
    text = str(value or "")[: max(0, limit)]
    return "".join(ch if ch in "\n\t" or ord(ch) >= 32 else "\ufffd" for ch in text)


def _detection_views(value: Any, limit: int = 16000) -> List[str]:
    """Return bounded decoded views used only for deterministic detection."""
    original = safe_text(value, limit)
    views: List[str] = []

    def add(candidate: str) -> None:
        candidate = safe_text(unicodedata.normalize("NFKC", candidate), limit)
        if candidate and candidate not in views:
            views.append(candidate)

    add(original)
    add(html.unescape(original))
    add(urllib.parse.unquote_plus(original))
    for token in _BASE64_TOKEN.findall(original):
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        add(decoded)
    return views


def injection_signals(value: Any) -> List[str]:
    return list(dict.fromkeys(
        pattern.pattern
        for text in _detection_views(value)
        for pattern in _INJECTION_PATTERNS
        if pattern.search(text)
    ))


def quarantine(value: Any) -> Any:
    """Remove detected instruction text before it crosses an LLM boundary."""
    if isinstance(value, dict):
        return {str(quarantine(key)): quarantine(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [quarantine(item) for item in value]
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        text = safe_text(value, 16000)
        return _QUARANTINED if injection_signals(text) else text
    return value


def envelope(value: Any, *, source: str, field: str = "content",
             limit: int = 2000) -> Dict[str, Any]:
    """Typed representation suitable for placement in an LLM user message."""
    text = safe_text(value, limit)
    signals = injection_signals(text)
    return {
        "trust": "untrusted_observation",
        "source": safe_text(source, 120),
        "field": safe_text(field, 120),
        "content": _QUARANTINED if signals else text,
        "instruction_semantics": False,
        "prompt_injection_suspected": bool(signals),
        "quarantined": bool(signals),
        "signals": signals,
    }


def _text_fragments(value: Any) -> List[str]:
    if isinstance(value, bytes):
        return [value.decode("utf-8", errors="replace")]
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [text for key, item in value.items()
                for text in (*_text_fragments(key), *_text_fragments(item))]
    if isinstance(value, (list, tuple, set)):
        return [text for item in value for text in _text_fragments(item)]
    return []


def scan_packets(packets: Iterable[Any]) -> List[Dict[str, Any]]:
    findings = []
    flow_buffers: Dict[Any, tuple[str, List[int]]] = {}
    for packet in packets or []:
        payload = getattr(packet, "payload", b"") or b""
        attributes = getattr(packet, "attributes", {}) or {}
        parts = _text_fragments(payload) + _text_fragments(attributes)
        if not parts:
            continue
        text = "\n".join(parts)[:4096]
        signals = injection_signals(text)
        packet_index = int(getattr(packet, "index", len(findings)))
        packet_refs = [packet_index]
        flow_key = getattr(packet, "flow_key", None)
        if flow_key:
            prior_text, prior_refs = flow_buffers.get(flow_key, ("", []))
            if not signals and prior_text:
                combined = prior_text + text
                signals = injection_signals(combined)
                if signals:
                    text = combined
                    packet_refs = prior_refs + packet_refs
            flow_buffers[flow_key] = ((prior_text + text)[-4096:],
                                      (prior_refs + [packet_index])[-8:])
        if signals:
            findings.append({
                "packet": packet_index,
                "packets": list(dict.fromkeys(packet_refs)),
                "src_ip": getattr(packet, "src_ip", None),
                "dst_ip": getattr(packet, "dst_ip", None),
                "signals": signals,
                "sample": safe_text(text, 240),
            })
    return findings
