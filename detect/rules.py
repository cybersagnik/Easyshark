"""
Detection rules.

Each rule exposes:
    rule.name        -> str (rule identifier used in alerts)
    rule.severity    -> str ('low' | 'medium' | 'high' | 'critical')
    rule.alerts      -> List[Alert]
    rule.analyze(context) -> None  (populates self.alerts)
    rule.enabled     -> bool
    rule.get_alerts() -> List[Alert]
"""
from __future__ import annotations

import logging
import math
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class Alert:
    rule_name:   str
    severity:    str
    message:     str
    timestamp:   float = 0.0
    metadata:    Dict[str, Any] = field(default_factory=dict)

    def short(self) -> str:
        return f"[{self.severity.upper()}] {self.rule_name}: {self.message}"


# ---------------------------------------------------------------------------
# Behavioral rules
# ---------------------------------------------------------------------------
class PortScanRule:
    name = "portscan"
    severity = "medium"

    def __init__(self, threshold: int = 20, time_window: float = 60.0):
        self.threshold = threshold
        self.time_window = time_window
        self.enabled = True
        self.alerts: List[Alert] = []
        self._seen: Dict[str, List[float]] = {}

    def analyze(self, context: Dict[str, Any]) -> None:
        packets = context.get("packets", [])
        for pkt in packets:
            if pkt.protocol != "TCP":
                continue
            fk = pkt.flow_key
            if not fk:
                continue
            sig = f"{pkt.src_ip}->{pkt.dst_ip}:SYN"
            ts = pkt.timestamp
            self._seen.setdefault(sig, []).append(ts)
            self._seen[sig] = [t for t in self._seen[sig] if ts - t <= self.time_window]
            if len(self._seen[sig]) == self.threshold:
                self.alerts.append(Alert(
                    rule_name=self.name, severity=self.severity,
                    message=f"Possible portscan from {pkt.src_ip} to {pkt.dst_ip}",
                    timestamp=ts,
                    metadata={"src": pkt.src_ip, "dst": pkt.dst_ip,
                              "syn_count": self.threshold},
                ))

    def get_alerts(self) -> List[Alert]:
        return list(self.alerts)


# ---------------------------------------------------------------------------
# Helpers used by DNS / TLS rules — kept module-private so they can be reused.
# ---------------------------------------------------------------------------
def _shannon_entropy(s: bytes) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


_DNS_HEADER_RE = re.compile(
    rb"\x00\x00\x00\x00\x00\x00",  # not used; placeholder, real parse below
)


def _parse_dns_query_name(payload: bytes, offset: int = 12) -> str:
    """Best-effort DNS name extraction from a UDP payload. Returns "" if it
    doesn't look like DNS. Skips name compression (we only want the simple
    case for tunnel detection)."""
    if len(payload) < offset + 1:
        return ""
    # Top two bits = 11 -> pointer (compression); bail.
    if payload[offset] & 0xC0:
        return ""
    labels: List[bytes] = []
    pos = offset
    while pos < len(payload):
        length = payload[pos]
        if length == 0:
            break
        if length & 0xC0:
            return ""
        pos += 1
        if pos + length > len(payload):
            return ""
        labels.append(payload[pos:pos + length])
        pos += length
    if not labels:
        return ""
    try:
        return b".".join(labels).decode("ascii", "replace")
    except Exception:
        return ""


def _is_dns_packet(pkt) -> Optional[bytes]:
    """Return UDP payload bytes if this packet is a DNS query/response, else None."""
    if pkt.protocol != "UDP":
        return None
    if pkt.dst_port != 53 and pkt.src_port != 53:
        return None
    if not pkt.payload:
        return None
    return pkt.payload


class DNSTunnelRule:
    """Detect DNS tunnelling / data exfil over DNS.

    Two independent heuristics — either one fires an alert:
      1. Volume — too many distinct DNS queries from one src in a short
         window (default 50 in 5 min).
      2. Entropy — high Shannon entropy of the queried subdomain
         (typical of base32/64-encoded exfil).
    """
    name = "dns_tunnel"
    severity = "high"

    def __init__(self, query_threshold: int = 50,
                 entropy_threshold: float = 3.5,
                 entropy_min_queries: int = 10,
                 window: float = 300.0):
        self.query_threshold = query_threshold
        self.entropy_threshold = entropy_threshold
        self.entropy_min_queries = entropy_min_queries
        self.window = window
        self.enabled = True
        self.alerts: List[Alert] = []
        self._src_queries: Dict[str, List[Tuple[float, str]]] = defaultdict(list)
        self._src_alerted: set = set()

    def analyze(self, context: Dict[str, Any]) -> None:
        packets = context.get("packets", [])
        for pkt in packets:
            payload = _is_dns_packet(pkt)
            if not payload or len(payload) < 12:
                continue
            try:
                flags = payload[2]
                qdcount = (payload[4] << 8) | payload[5]
            except Exception:
                continue
            if flags & 0x80 or qdcount == 0:
                continue
            name = _parse_dns_query_name(payload, 12)
            if not name:
                continue
            if not pkt.src_ip:
                continue
            bucket = self._src_queries[pkt.src_ip]
            bucket.append((pkt.timestamp, name))
            self._src_queries[pkt.src_ip] = [
                (t, n) for (t, n) in bucket if pkt.timestamp - t <= self.window
            ]
            if pkt.src_ip in self._src_alerted:
                continue
            rec = self._src_queries[pkt.src_ip]
            n = len(rec)
            avg_entropy = (sum(_shannon_entropy(x.encode()) for _, x in rec) / n
                           if n else 0.0)
            triggered = (
                n >= self.query_threshold
                or (n >= self.entropy_min_queries
                    and avg_entropy >= self.entropy_threshold)
            )
            if not triggered:
                continue
            reason = ("volume" if n >= self.query_threshold else "entropy")
            self.alerts.append(Alert(
                rule_name=self.name, severity=self.severity,
                message=(f"Possible DNS tunnel from {pkt.src_ip} "
                         f"({reason}: {n} queries, avg entropy {avg_entropy:.2f})"),
                timestamp=pkt.timestamp,
                metadata={"src": pkt.src_ip,
                          "query_count": n,
                          "avg_entropy": round(avg_entropy, 3),
                          "reason": reason,
                          "samples": rec[:5]},
            ))
            self._src_alerted.add(pkt.src_ip)

    def get_alerts(self) -> List[Alert]:
        return list(self.alerts)


class BeaconingRule:
    """Detect periodic outbound connections (C2-style beaconing).

    Groups flows by (src_ip, dst_ip, dst_port) and flags those whose
    inter-arrival times have a low coefficient of variation (i.e. regular).
    """
    name = "beaconing"
    severity = "medium"

    def __init__(self, min_connections: int = 10,
                 interval_tolerance: float = 0.2):
        self.min_connections = min_connections
        self.interval_tolerance = interval_tolerance
        self.enabled = True
        self.alerts: List[Alert] = []
        # Keep timestamps of first packet in each (src,dst,dport,proto) burst.
        self._buckets: Dict[Tuple, List[float]] = defaultdict(list)
        self._reported: set = set()

    def analyze(self, context: Dict[str, Any]) -> None:
        packets = context.get("packets", [])
        for pkt in packets:
            if pkt.protocol not in ("TCP", "UDP"):
                continue
            if not pkt.dst_ip or not pkt.dst_port:
                continue
            # Only consider client->server initiations (SYN or first UDP datagram).
            is_new = (pkt.protocol == "TCP" and "S" in (pkt.tcp_flags or "")
                      and "A" not in (pkt.tcp_flags or ""))
            if pkt.protocol == "UDP":
                is_new = True
            if not is_new:
                continue
            key = (pkt.src_ip, pkt.dst_ip, pkt.dst_port, pkt.protocol)
            self._buckets[key].append(pkt.timestamp)
        for key, ts_list in self._buckets.items():
            if len(ts_list) < self.min_connections:
                continue
            if key in self._reported:
                continue
            ts_list.sort()
            deltas = [ts_list[i + 1] - ts_list[i] for i in range(len(ts_list) - 1)]
            if not deltas:
                continue
            mean = sum(deltas) / len(deltas)
            if mean <= 0:
                continue
            variance = sum((d - mean) ** 2 for d in deltas) / len(deltas)
            std = math.sqrt(variance)
            cv = std / mean  # coefficient of variation
            if cv <= self.interval_tolerance:
                src, dst, dport, proto = key
                self.alerts.append(Alert(
                    rule_name=self.name, severity=self.severity,
                    message=(f"Beaconing: {src} -> {dst}:{dport}/{proto} "
                             f"every {mean:.1f}s (cv={cv:.2f})"),
                    timestamp=ts_list[-1],
                    metadata={"src": src, "dst": dst, "port": dport,
                              "proto": proto, "interval_mean_s": round(mean, 2),
                              "cv": round(cv, 3),
                              "samples": len(ts_list)},
                ))
                self._reported.add(key)

    def get_alerts(self) -> List[Alert]:
        return list(self.alerts)


# ---------------------------------------------------------------------------
# TLS — parse ClientHello from raw bytes (works without decryption).
# ---------------------------------------------------------------------------
_TLS_VERSIONS = {
    0x0300: "SSLv3",
    0x0301: "TLSv1.0",
    0x0302: "TLSv1.1",
    0x0303: "TLSv1.2",
    0x0304: "TLSv1.3",
}


def _parse_tls_clienthello(payload: bytes) -> Optional[Dict[str, Any]]:
    """Very small TLS ClientHello parser. Returns dict with version, sni,
    cipher_suites; None if the payload is not a recognisable ClientHello."""
    if len(payload) < 5 or payload[0] != 0x16:  # not a TLS handshake record
        return None
    # Reassemble first handshake message — payload[5:] is the handshake body.
    hs_type = payload[5]
    if hs_type != 0x01:  # not ClientHello
        return None
    if len(payload) < 43:
        return None
    # client_version at payload[9:11]
    version_int = (payload[9] << 8) | payload[10]
    if version_int not in _TLS_VERSIONS:
        return None
    # Random (32 bytes) at payload[11:43]
    random = payload[11:43]  # noqa: F841 — preserved for callers wanting it
    pos = 43
    if pos + 1 > len(payload):
        return None
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
    # Extensions
    sni = ""
    if pos + 2 <= len(payload):
        ext_total = (payload[pos] << 8) | payload[pos + 1]
        ext_pos = pos + 2
        ext_end = pos + 2 + ext_total
        while ext_pos + 4 <= ext_end and ext_end <= len(payload):
            ext_type = (payload[ext_pos] << 8) | payload[ext_pos + 1]
            ext_len = (payload[ext_pos + 2] << 8) | payload[ext_pos + 3]
            ext_pos += 4
            if ext_type == 0x0000 and ext_len >= 5:  # SNI extension
                name_len = (payload[ext_pos + 3] << 8) | payload[ext_pos + 4]
                if name_len <= ext_len - 5:
                    name_end = ext_pos + 5 + name_len
                    sni = payload[ext_pos + 5:name_end].decode("ascii", "replace")
            ext_pos += ext_len
    return {
        "version_int": version_int,
        "version": _TLS_VERSIONS.get(version_int, f"0x{version_int:04x}"),
        "sni": sni,
        "raw_len": len(payload),
    }


class TLSAnomalyRule:
    """Detect weak TLS: version < 1.2, missing SNI, very short handshake."""
    name = "tls_anomaly"
    severity = "medium"

    WEAK_VERSIONS = {0x0300, 0x0301, 0x0302}  # SSLv3, TLS 1.0, TLS 1.1

    def __init__(self):
        self.enabled = True
        self.alerts: List[Alert] = []
        self._reported: set = set()

    def analyze(self, context: Dict[str, Any]) -> None:
        packets = context.get("packets", [])
        for pkt in packets:
            if pkt.protocol != "TCP":
                continue
            if pkt.dst_port != 443 and pkt.src_port != 443:
                continue
            if not pkt.payload or len(pkt.payload) < 6:
                continue
            info = _parse_tls_clienthello(pkt.payload)
            if info is None:
                continue
            key = (pkt.src_ip, pkt.dst_ip, info["sni"], info["version"])
            if key in self._reported:
                continue
            self._reported.add(key)
            if info["version_int"] in self.WEAK_VERSIONS:
                self.alerts.append(Alert(
                    rule_name=self.name, severity="high",
                    message=(f"Weak TLS {info['version']} from "
                             f"{pkt.src_ip} to {pkt.dst_ip}:443 "
                             f"SNI={info['sni']!r}"),
                    timestamp=pkt.timestamp,
                    metadata={"src": pkt.src_ip, "dst": pkt.dst_ip,
                              "version": info["version"],
                              "sni": info["sni"]},
                ))
            elif not info["sni"]:
                self.alerts.append(Alert(
                    rule_name=self.name, severity=self.severity,
                    message=(f"TLS ClientHello without SNI from "
                             f"{pkt.src_ip} to {pkt.dst_ip}:443"),
                    timestamp=pkt.timestamp,
                    metadata={"src": pkt.src_ip, "dst": pkt.dst_ip,
                              "version": info["version"]},
                ))

    def get_alerts(self) -> List[Alert]:
        return list(self.alerts)


class ARPSpoofRule:
    name = "arp_spoof"
    severity = "high"

    def __init__(self):
        self.enabled = True
        self.alerts: List[Alert] = []
        self._ip_to_mac: Dict[str, str] = {}

    def analyze(self, context: Dict[str, Any]) -> None:
        packets = context.get("packets", [])
        for pkt in packets:
            if pkt.protocol != "ARP" or not pkt.raw_packet:
                continue
            try:
                from scapy.all import ARP
                if ARP in pkt.raw_packet:
                    psrc = pkt.raw_packet[ARP].psrc
                    hwsrc = pkt.raw_packet[ARP].hwsrc
                    if psrc in self._ip_to_mac and self._ip_to_mac[psrc] != hwsrc:
                        self.alerts.append(Alert(
                            rule_name=self.name, severity=self.severity,
                            message=f"ARP spoof: {psrc} changed MAC",
                            timestamp=pkt.timestamp,
                            metadata={"ip": psrc,
                                      "old_mac": self._ip_to_mac[psrc],
                                      "new_mac": hwsrc},
                        ))
                    self._ip_to_mac[psrc] = hwsrc
            except Exception:
                continue

    def get_alerts(self) -> List[Alert]:
        return list(self.alerts)


# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------
class SignatureEngine:
    name = "signatures"
    severity = "low"

    def __init__(self):
        self.enabled = True
        self.alerts: List[Alert] = []
        self._sigs = [
            (b"USER\x20root", "Possible default-account login attempt"),
            (b"wget\x20http://", "Suspicious download command"),
            (b"cmd.exe", "Windows shell command in payload"),
        ]

    def analyze(self, context: Dict[str, Any]) -> None:
        packets = context.get("packets", [])
        for pkt in packets:
            payload = getattr(pkt, "payload", b"") or b""
            for sig, msg in self._sigs:
                if sig in payload:
                    self.alerts.append(Alert(
                        rule_name=self.name, severity=self.severity,
                        message=msg,
                        timestamp=pkt.timestamp,
                        metadata={"pkt": pkt.index, "signature": sig.decode("latin-1")},
                    ))

    def get_alerts(self) -> List[Alert]:
        return list(self.alerts)


# ---------------------------------------------------------------------------
# Hybrid — C2 / data exfil
# ---------------------------------------------------------------------------
class C2ExfilRule:
    """Heuristic for TCP/UDP exfil: long-lived flow that pushes large
    volumes of data outbound (src->dst bytes >> dst->src bytes), where
    dst is a non-RFC1918 address. Flags the flow once the imbalance
    crosses a threshold."""
    name = "c2_exfil"
    severity = "critical"

    def __init__(self,
                 min_total_bytes: int = 1_000_000,
                 imbalance_ratio: float = 10.0):
        self.min_total_bytes = min_total_bytes
        self.imbalance_ratio = imbalance_ratio
        self.enabled = True
        self.alerts: List[Alert] = []
        self._flows: Dict[Tuple, Dict[str, int]] = {}
        self._reported: set = set()

    def _is_external(self, ip: Optional[str]) -> bool:
        """Best-effort: consider external if not RFC1918 / loopback / link-local."""
        if not ip:
            return False
        try:
            o = [int(x) for x in ip.split(".")]
        except Exception:
            return False
        if len(o) != 4:
            # IPv6 -> treat as external for now.
            return True
        if o[0] == 10:
            return False
        if o[0] == 172 and 16 <= o[1] <= 31:
            return False
        if o[0] == 192 and o[1] == 168:
            return False
        if o[0] == 127:
            return False
        if o[0] == 169 and o[1] == 254:
            return False
        return True

    def analyze(self, context: Dict[str, Any]) -> None:
        packets = context.get("packets", [])
        for pkt in packets:
            if pkt.protocol not in ("TCP", "UDP"):
                continue
            if not (pkt.src_ip and pkt.dst_ip and pkt.dst_port):
                continue
            key = pkt.flow_key
            if not key:
                continue
            slot = self._flows.setdefault(
                key, {"out_bytes": 0, "in_bytes": 0, "pkts": 0, "ts": pkt.timestamp})
            slot["pkts"] += 1
            slot["ts"] = pkt.timestamp
            # Approximate "outbound" by RFC1918 source + external dst.
            if not self._is_external(pkt.src_ip) and self._is_external(pkt.dst_ip):
                slot["out_bytes"] += pkt.length
            elif self._is_external(pkt.src_ip) and not self._is_external(pkt.dst_ip):
                slot["in_bytes"] += pkt.length
        for key, slot in self._flows.items():
            if key in self._reported:
                continue
            total = slot["out_bytes"] + slot["in_bytes"]
            if total < self.min_total_bytes:
                continue
            smaller = max(slot["in_bytes"], 1)
            bigger = max(slot["out_bytes"], slot["in_bytes"])
            if bigger < smaller * self.imbalance_ratio:
                continue
            direction = "outbound" if slot["out_bytes"] > slot["in_bytes"] else "inbound"
            proto, sip, sport, dip, dport = key
            self.alerts.append(Alert(
                rule_name=self.name, severity=self.severity,
                message=(f"Possible data exfil ({direction}): "
                         f"{sip}:{sport} <-> {dip}:{dport}/{proto} "
                         f"({slot['out_bytes']} out / {slot['in_bytes']} in "
                         f"over {slot['pkts']} pkts)"),
                timestamp=slot["ts"],
                metadata={"src": sip, "sport": sport,
                          "dst": dip, "dport": dport, "proto": proto,
                          "out_bytes": slot["out_bytes"],
                          "in_bytes": slot["in_bytes"],
                          "pkts": slot["pkts"]},
            ))
            self._reported.add(key)

    def get_alerts(self) -> List[Alert]:
        return list(self.alerts)
