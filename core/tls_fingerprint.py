"""Deterministic JA3/JA4-style fingerprints for TLS ClientHello packets."""
from __future__ import annotations

import hashlib
from typing import Any, Iterable, Optional


def _number(value: Any) -> Optional[int]:
    try:
        return int(getattr(value, "val", value))
    except (TypeError, ValueError):
        return None


def _grease(value: int) -> bool:
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


def _values(items: Iterable[Any]) -> list[int]:
    return [n for n in (_number(item) for item in items or [])
            if n is not None and not _grease(n)]


def _client_hello(packet):
    try:
        from scapy.layers.tls.handshake import TLSClientHello
        return packet.getlayer(TLSClientHello) if packet.haslayer(TLSClientHello) else None
    except (ImportError, AttributeError):
        return None


def fingerprint_packet(packet) -> Optional[dict[str, Any]]:
    """Return JA3/JA4 components for one ClientHello, or ``None``."""
    hello = _client_hello(packet)
    if hello is None:
        return None
    version = _number(getattr(hello, "version", None)) or 0
    ciphers = _values(getattr(hello, "ciphers", []) or [])
    extensions = []
    groups: list[int] = []
    formats: list[int] = []
    sni = False
    for extension in getattr(hello, "ext", []) or []:
        kind = _number(getattr(extension, "type", None))
        if kind is not None and not _grease(kind):
            extensions.append(kind)
        name = extension.__class__.__name__.lower()
        if "servername" in name:
            sni = True
        if hasattr(extension, "groups"):
            groups.extend(_values(getattr(extension, "groups", []) or []))
        if hasattr(extension, "ecpl"):
            formats.extend(_values(getattr(extension, "ecpl", []) or []))
        if hasattr(extension, "elliptic_curves"):
            groups.extend(_values(getattr(extension, "elliptic_curves", []) or []))
    ja3_text = ",".join((str(version),
                          "-".join(map(str, ciphers)),
                          "-".join(map(str, extensions)),
                          "-".join(map(str, groups)),
                          "-".join(map(str, formats))))
    digest = hashlib.md5(ja3_text.encode()).hexdigest()
    # JA4's stable prefix and truncated component hash are useful even when
    # packet captures omit one optional TLS extension.
    tls_version = {0x0301: "10", 0x0302: "11", 0x0303: "12", 0x0304: "13"}.get(version, "00")
    ja4_prefix = f"t{tls_version}{'d' if sni else 'i'}{len(ciphers):02d}{len(extensions):02d}"
    ja4 = f"{ja4_prefix}_{hashlib.sha256(ja3_text.encode()).hexdigest()[:12]}"
    return {"ja3": digest, "ja3_text": ja3_text, "ja4": ja4,
            "version": version, "cipher_count": len(ciphers),
            "extension_count": len(extensions), "sni": sni}


def fingerprint_packets(packets: Iterable[Any]) -> list[dict[str, Any]]:
    results = []
    for index, packet in enumerate(packets or []):
        raw = getattr(packet, "raw_packet", packet)
        result = fingerprint_packet(raw)
        if result:
            results.append({"packet": index, **result})
    return results


def compute_fingerprint(packet) -> Optional[dict[str, Any]]:
    """Compatibility name for callers that prefer a compute-style API."""
    return fingerprint_packet(packet)


def compute_ja3(packet) -> Optional[str]:
    result = fingerprint_packet(packet)
    return result.get("ja3") if result else None


def compute_ja4(packet) -> Optional[str]:
    result = fingerprint_packet(packet)
    return result.get("ja4") if result else None
