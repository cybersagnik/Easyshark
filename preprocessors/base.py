"""Preprocessors — per-packet annotation hooks.

Each preprocessor exposes:
    preprocessor.name    -> str
    preprocessor.enabled -> bool
    preprocessor.process(meta) -> None  (mutates meta.attributes)

Annotations written to ``meta.attributes`` are picked up by:
  * Detection rules (e.g. TLSAnomalyRule uses meta.attributes['tls'])
  * AI tool registry (tool_get_packet_detail surfaces them)
  * OutputFormatter (when present)

All parsing is defensive — a malformed packet never raises.
"""
from __future__ import annotations

import logging
import re
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


def _attr(meta, key: str, value: Any) -> None:
    """Idempotent attribute setter."""
    meta.attributes.setdefault(key, value)


# --------------------------------------------------------------------------- #
# Flow preprocessor — aggregates per-flow stats for downstream consumers.
# --------------------------------------------------------------------------- #
class FlowPreprocessor:
    name = "flow"

    def __init__(self):
        self.enabled = True
        self._flows: Dict[Tuple, Dict[str, Any]] = {}

    def process(self, meta) -> None:
        fk = getattr(meta, "flow_key", None)
        if not fk:
            return
        slot = self._flows.setdefault(
            fk,
            {"pkts": 0, "bytes": 0, "first_ts": meta.timestamp,
             "last_ts": meta.timestamp, "src_ip": meta.src_ip,
             "dst_ip": meta.dst_ip, "src_port": meta.src_port,
             "dst_port": meta.dst_port, "proto": meta.protocol},
        )
        slot["pkts"] += 1
        slot["bytes"] += meta.length
        slot["last_ts"] = meta.timestamp
        _attr(meta, "flow", slot)


# --------------------------------------------------------------------------- #
# DNS — extracts qname, qtype, qclass from raw UDP payloads.
# --------------------------------------------------------------------------- #
_DNS_QTYPE = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 41: "OPT",
    65: "HTTPS", 255: "ANY",
}


def _extract_dns_name(payload: bytes, offset: int) -> str:
    """Best-effort DNS name extraction (handles simple labels only)."""
    if offset >= len(payload):
        return ""
    labels: List[bytes] = []
    pos = offset
    while pos < len(payload):
        if payload[pos] == 0:
            break
        length = payload[pos]
        if length & 0xC0 or length > 63:
            return ""
        pos += 1
        if pos + length > len(payload):
            return ""
        labels.append(payload[pos:pos + length])
        pos += length
    if not labels:
        return ""
    return b".".join(labels).decode("ascii", "replace")


class DNSPreprocessor:
    name = "dns"

    def __init__(self):
        self.enabled = True

    def process(self, meta) -> None:
        if meta.protocol != "UDP":
            return
        if meta.dst_port != 53 and meta.src_port != 53:
            return
        payload = meta.payload or b""
        if len(payload) < 12:
            return
        try:
            flags = payload[2]
            qdcount = (payload[4] << 8) | payload[5]
            ancount = (payload[6] << 8) | payload[7]
            qr = bool(flags & 0x80)
        except Exception:
            return
        if qdcount == 0 and ancount == 0:
            return
        qname, qtype, qclass = "", 0, 0
        try:
            # Parse one Q — start at offset 12.
            name = _extract_dns_name(payload, 12)
            # After name: 2 bytes qtype, 2 bytes qclass.
            # Find end of name (the 0 byte) safely by walking labels again.
            pos = 12
            while pos < len(payload) and payload[pos] != 0:
                pos += 1 + payload[pos]
            qname = name
            pos += 1  # past terminator
            if pos + 4 <= len(payload):
                qtype = (payload[pos] << 8) | payload[pos + 1]
                qclass = (payload[pos + 2] << 8) | payload[pos + 3]
        except Exception:
            return
        _attr(meta, "dns", {
            "qr": qr,
            "qname": qname,
            "qtype": qtype,
            "qtype_name": _DNS_QTYPE.get(qtype, str(qtype)),
            "qclass": qclass,
            "ancount": ancount,
            "qdcount": qdcount,
        })


# --------------------------------------------------------------------------- #
# TLS — record-layer / ClientHello annotations.
# --------------------------------------------------------------------------- #
_TLS_VERSIONS = {
    0x0300: "SSLv3", 0x0301: "TLSv1.0", 0x0302: "TLSv1.1",
    0x0303: "TLSv1.2", 0x0304: "TLSv1.3",
}


def _parse_tls_hello(payload: bytes) -> Optional[Dict[str, Any]]:
    """Return dict with version + SNI + cipher_suites count, or None."""
    if len(payload) < 6 or payload[0] != 0x16:
        return None
    if payload[5] != 0x01:
        return None
    if len(payload) < 43:
        return None
    version_int = (payload[9] << 8) | payload[10]
    if version_int not in _TLS_VERSIONS:
        return None
    pos = 43
    sid_len = payload[pos]
    pos += 1 + sid_len
    if pos + 2 > len(payload):
        return None
    cs_len = (payload[pos] << 8) | payload[pos + 1]
    pos += 2 + cs_len
    if pos + 1 > len(payload):
        return None
    cm_len = payload[pos]
    pos += 1 + cm_len
    sni = ""
    if pos + 2 <= len(payload):
        ext_total = (payload[pos] << 8) | payload[pos + 1]
        ext_pos = pos + 2
        ext_end = pos + 2 + ext_total
        while ext_pos + 4 <= ext_end and ext_end <= len(payload):
            ext_type = (payload[ext_pos] << 8) | payload[ext_pos + 1]
            ext_len = (payload[ext_pos + 2] << 8) | payload[ext_pos + 3]
            ext_pos += 4
            if ext_type == 0x0000 and ext_len >= 5:
                # SNI layout inside extension data:
                #   [0..1] list_length (skip)
                #   [2]    name_type
                #   [3..4] name_length
                #   [5..]  name
                name_len = (payload[ext_pos + 3] << 8) | payload[ext_pos + 4]
                if name_len <= ext_len - 5:
                    name_end = ext_pos + 5 + name_len
                    sni = payload[ext_pos + 5:name_end].decode("ascii", "replace")
            ext_pos += ext_len
    return {
        "version_int": version_int,
        "version": _TLS_VERSIONS.get(version_int, f"0x{version_int:04x}"),
        "sni": sni,
        "cipher_suites": cs_len // 2,
    }


class TLSPreprocessor:
    name = "tls"

    def __init__(self):
        self.enabled = True
        self._reported: Dict[Tuple, bool] = {}

    def process(self, meta) -> None:
        if meta.protocol != "TCP":
            return
        if meta.dst_port != 443 and meta.src_port != 443:
            return
        info = _parse_tls_hello(meta.payload or b"")
        if not info:
            return
        _attr(meta, "tls", info)


# --------------------------------------------------------------------------- #
# ARP — opcode + sender info.
# --------------------------------------------------------------------------- #
_ARP_OP = {1: "request", 2: "reply"}


class ARPPreprocessor:
    name = "arp"

    def __init__(self):
        self.enabled = True

    def process(self, meta) -> None:
        if meta.protocol != "ARP" or not meta.raw_packet:
            return
        try:
            from scapy.all import ARP
            if ARP not in meta.raw_packet:
                return
            a = meta.raw_packet[ARP]
            _attr(meta, "arp", {
                "op": a.op,
                "op_name": _ARP_OP.get(a.op, f"op{a.op}"),
                "psrc": a.psrc,
                "hwsrc": a.hwsrc,
                "pdst": a.pdst,
                "hwdst": a.hwdst,
            })
        except Exception:
            return


# --------------------------------------------------------------------------- #
# HTTP — request line + Host header + status line.
# --------------------------------------------------------------------------- #
_HTTP_REQ = re.compile(rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)\s+"
                       rb"([^\s]+)\s+HTTP/\d\.\d", re.IGNORECASE)
_HTTP_RES = re.compile(rb"^HTTP/(\d\.\d)\s+(\d{3})\s*(.*)", re.IGNORECASE)
_HTTP_HOST = re.compile(rb"^[Hh]ost:\s*([^\r\n]+)")
_HTTP_AUTH = re.compile(rb"^[Aa]uthorization:\s*([^\r\n]+)")
_HTTP_CT = re.compile(rb"^[Cc]ontent-[Tt]ype:\s*([^\r\n]+)")
_HTTP_UA = re.compile(rb"^[Uu]ser-[Aa]gent:\s*([^\r\n]+)")


class HTTPPreprocessor:
    name = "http"

    COMMON_PORTS = (80, 8080, 8000, 8443, 3128, 8888)

    def __init__(self):
        self.enabled = True

    def process(self, meta) -> None:
        if meta.protocol != "TCP":
            return
        if (meta.dst_port not in self.COMMON_PORTS
                and meta.src_port not in self.COMMON_PORTS):
            return
        payload = meta.payload or b""
        if len(payload) < 4:
            return
        info: Dict[str, Any] = {}
        m = _HTTP_REQ.match(payload)
        if m:
            try:
                path = m.group(2).decode("latin-1", "replace")
            except Exception:
                path = ""
            info.update({
                "kind": "request",
                "method": m.group(1).decode("latin-1", "replace").upper(),
                "path": path,
            })
        else:
            m = _HTTP_RES.match(payload)
            if m:
                info.update({
                    "kind": "response",
                    "http_version": m.group(1).decode("latin-1", "replace"),
                    "status_code": int(m.group(2)),
                    "reason": m.group(3).decode("latin-1", "replace").strip(),
                })
            else:
                return
        head_end = payload.find(b"\r\n\r\n")
        head = payload[:head_end] if head_end > 0 else payload[:1024]
        for line in head.split(b"\r\n")[1:]:
            for rx, key in ((_HTTP_HOST, "host"),
                            (_HTTP_AUTH, "authorization"),
                            (_HTTP_CT, "content_type"),
                            (_HTTP_UA, "user_agent")):
                lm = rx.match(line)
                if lm:
                    info[key] = lm.group(1).decode("latin-1", "replace").strip()
                    break
        if info:
            _attr(meta, "http", info)
