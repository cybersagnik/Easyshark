"""
detectors.py — Layer 1 of the auto-analyst pipeline (context.md §14.3).

Eight deterministic anomaly detectors that score behavioral signals in a
PCAP. No LLM — pure Python over PacketMetadata.

Public API:
    run_all(packets, flows) -> List[Anomaly]

Each detector is a free function that takes (packets, flows) and returns
a List[Anomaly]. `run_all` chains them and returns the merged list
sorted by score (descending).

Detector thresholds are derived from context.md §14.3 and the existing
detection-rule config; do not modify them without updating the brief.

The Anomaly dataclass is the wire format consumed by
``core.narrative.build``.
"""
from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# --------------------------------------------------------------------------- #
# Anomaly dataclass                                                           #
# --------------------------------------------------------------------------- #
@dataclass
class Anomaly:
    """One detector finding. See context.md §14.3 output format."""
    type:        str                       # beaconing | dns_volume | dns_entropy | ...
    score:       float                     # 0.0–1.0
    hosts:       List[str] = field(default_factory=list)
    remote:      str = ""                  # dst_ip:port or domain
    evidence:    str = ""                  # one-line human readable
    packets:     List[int] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #
_SUSPECT_TLDS = (".xyz", ".top", ".pw", ".cc", ".tk", ".ml", ".ga", ".cf", ".info")

# Ports < 1024 that carry an unexpected protocol = always suspicious.
# Mid-range ports that are not in this set but carry HTTP/TLS/SSH get a
# reduced score (0.3) — there are legitimate non-web apps on these ports.
# Ephemeral ports (>= 32768) are excluded entirely: client-chosen, no signal.
# Threshold is broader than the IANA 49152 to suppress Linux's default
# ephemeral range (32768–60999), which produces false positives when
# proxied HTTP lands on a client-allocated high port (e.g. arppoison
# capture ports 45691/45692).
SUSPICIOUS_NONSTANDARD_PORTS = frozenset({
    1080,    # SOCKS proxy
    3128,    # Squid default
    4444,    # Metasploit default handler
    4445,    # Metasploit alt
    8080,    # HTTP alt (caught by web_ports but if mismatched still flagged)
    8443,    # HTTPS alt
    8888,    # common backdoor / dev server
    9090,    # common admin UI / C2
    9999,    # common backdoor
})
EPHEMERAL_PORT_MIN = 32768  # Linux default ephemeral port start


def _is_internal(ip: str) -> bool:
    """RFC1918 + link-local heuristic. Conservative."""
    if not ip:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        o = [int(p) for p in parts]
    except ValueError:
        return False
    if o[0] == 10:
        return True
    if o[0] == 172 and 16 <= o[1] <= 31:
        return True
    if o[0] == 192 and o[1] == 168:
        return True
    if o[0] == 169 and o[1] == 254:
        return True
    return False


def _octets(ip: str) -> Tuple[int, int, int, int]:
    try:
        a, b, c, d = ip.split(".")
        return (int(a), int(b), int(c), int(d))
    except Exception:
        return (-1, -1, -1, -1)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _tls_record_byte(payload: bytes) -> bool:
    """First byte of TLS record is 0x16 (Handshake) for ClientHello."""
    return len(payload) >= 1 and payload[0] == 0x16


def _ssh_banner(payload: bytes) -> bool:
    return payload.startswith(b"SSH-")


def _http_keyword(payload: bytes) -> bool:
    head = payload[:16]
    return (head.startswith(b"GET ") or head.startswith(b"POST ") or
            head.startswith(b"HEAD ") or head.startswith(b"PUT ") or
            head.startswith(b"DELETE ") or head.startswith(b"OPTIONS ") or
            head.startswith(b"HTTP/"))


# --------------------------------------------------------------------------- #
# Detector 1 — Beaconing                                                      #
# --------------------------------------------------------------------------- #
def detect_beaconing(packets, flows) -> List[Anomaly]:
    """Group (src, dst, dport) into connection series; flag low-CV intervals."""
    out: List[Anomaly] = []
    series: Dict[Tuple[str, str, Optional[int]], List[float]] = defaultdict(list)
    pkt_index_map: Dict[Tuple[str, str, Optional[int]], List[int]] = defaultdict(list)
    for m in packets:
        if m.protocol != "TCP" or not m.src_ip or not m.dst_ip:
            continue
        # Use SYN-ish packets as connection markers (handshake initiation).
        if m.tcp_flags and "S" in m.tcp_flags and "A" not in m.tcp_flags:
            key = (m.src_ip, m.dst_ip, m.dst_port)
            series[key].append(m.timestamp)
            pkt_index_map[key].append(m.index)

    for key, times in series.items():
        if len(times) < 5:
            continue
        times = sorted(times)
        intervals = [times[i + 1] - times[i] for i in range(len(times) - 1)]
        if len(intervals) < 4:
            continue
        mu = sum(intervals) / len(intervals)
        if mu <= 0:
            continue
        var = sum((x - mu) ** 2 for x in intervals) / len(intervals)
        sigma = math.sqrt(var)
        cv = sigma / mu
        if cv < 0.15:
            score = max(0.0, min(1.0, 1.0 - cv))
            src, dst, dport = key
            out.append(Anomaly(
                type="beaconing",
                score=score,
                hosts=[src],
                remote=f"{dst}:{dport or '?'}",
                evidence=(f"{len(times)} connections, "
                          f"{mu:.1f}s interval ±{sigma:.1f}s "
                          f"(CV {cv:.3f})"),
                packets=list(pkt_index_map[key])[:20],
            ))
    return out


# --------------------------------------------------------------------------- #
# Detector 2 — DNS anomaly (volume + entropy + TTL + NXDOMAIN ratio)          #
# --------------------------------------------------------------------------- #
def detect_dns_anomaly(packets, flows) -> List[Anomaly]:
    """Four sub-checks, each emits its own Anomaly if triggered.

    Heuristics operate on the raw packet bytes since DNS preprocessor
    state isn't exposed as a tidy list. We use the well-known DNS
    record pattern (Transaction ID + flags + question/answer sections).
    """
    out: List[Anomaly] = []

    # Walk UDP/53 packets and sniff for query and response records.
    queries_by_host: Counter = Counter()        # host -> query count
    query_names_by_host: Dict[str, List[str]] = defaultdict(list)
    nxdomain_by_host: Counter = Counter()       # host -> NXDOMAIN count
    response_total_by_host: Counter = Counter()
    ttl_anomalies_by_host: Counter = Counter()

    for m in packets:
        if m.protocol != "UDP" or m.dst_port != 53 and m.src_port != 53:
            continue
        # only consider port 53 packets
        if m.dst_port != 53 and m.src_port != 53:
            continue
        payload = m.payload or b""
        if len(payload) < 12:
            continue
        # Parse flags: byte 2 low 5 bits. 0x00 query, 0x80 standard response.
        flags = payload[2] if len(payload) > 2 else 0
        is_response = bool(flags & 0x80)
        rcode = flags & 0x0F
        is_nxdomain = is_response and rcode == 3

        if not is_response and m.src_ip:
            queries_by_host[m.src_ip] += 1
            # Decode the question name: skip 12-byte header, then length-prefixed labels.
            name = _decode_dns_name(payload, 12)
            if name:
                query_names_by_host[m.src_ip].append(name.lower())

        if is_response and m.dst_ip:
            response_total_by_host[m.dst_ip] += 1
            if is_nxdomain:
                nxdomain_by_host[m.dst_ip] += 1
            # TTL: bytes 32-35 in the ANSWER section; rough parse of first answer.
            ttl = _first_answer_ttl(payload)
            if ttl is not None and ttl < 10 and ttl > 0:
                ttl_anomalies_by_host[m.dst_ip] += 1

    # ----- Volume --------------------------------------------------------- #
    for host, qc in queries_by_host.items():
        if qc > 50:
            score = min(1.0, qc / 200.0)
            out.append(Anomaly(
                type="dns_volume",
                score=score,
                hosts=[host],
                remote="dns:53",
                evidence=f"{host}: {qc} DNS queries in capture",
                packets=[],
            ))

    # ----- Entropy -------------------------------------------------------- #
    for host, names in query_names_by_host.items():
        if len(names) < 3:
            continue
        # Shannon entropy of the leftmost label (subdomain).
        ent_per_name = []
        for n in names:
            sub = n.split(".")[0] if "." in n else n
            if len(sub) >= 8:
                ent_per_name.append(_shannon_entropy(sub))
        if not ent_per_name:
            continue
        avg_ent = sum(ent_per_name) / len(ent_per_name)
        if avg_ent > 3.5:
            score = min(1.0, (avg_ent - 3.5) / 1.5)
            out.append(Anomaly(
                type="dns_entropy",
                score=score,
                hosts=[host],
                remote="dns:53",
                evidence=(f"{host}: subdomain entropy {avg_ent:.2f} bits "
                          f"({len(ent_per_name)} high-entropy queries)"),
                packets=[],
            ))

    # ----- NXDOMAIN ratio ------------------------------------------------- #
    for host, nx in nxdomain_by_host.items():
        total = response_total_by_host[host]
        if total < 5:
            continue
        ratio = nx / total
        if ratio > 0.30:
            score = min(1.0, ratio)
            out.append(Anomaly(
                type="dns_nxdomain_ratio",
                score=score,
                hosts=[host],
                remote="dns:53",
                evidence=f"{host}: {nx}/{total} NXDOMAIN ({ratio*100:.0f}%)",
                packets=[],
            ))

    # ----- TTL anomaly ---------------------------------------------------- #
    for host, n in ttl_anomalies_by_host.items():
        if n >= 1:
            out.append(Anomaly(
                type="dns_fast_flux",
                score=min(1.0, n / 5.0),
                hosts=[host],
                remote="dns:53",
                evidence=f"{host}: {n} DNS responses with TTL<10s (fast-flux candidate)",
                packets=[],
            ))

    return out


def _decode_dns_name(payload: bytes, offset: int) -> Optional[str]:
    """Decode a length-prefixed DNS name starting at `offset` in `payload`.
    Returns None if parsing fails. Stops at label length 0."""
    try:
        labels = []
        while offset < len(payload):
            length = payload[offset]
            if length == 0:
                break
            # Top two bits set = compression pointer; bail.
            if length & 0xC0:
                return None
            offset += 1
            labels.append(payload[offset:offset + length].decode("latin-1", "replace"))
            offset += length
        return ".".join(labels) if labels else None
    except Exception:
        return None


def _first_answer_ttl(payload: bytes) -> Optional[int]:
    """Rough TTL extraction from the first ANSWER RR. Returns None on error."""
    try:
        if len(payload) < 32:
            return None
        # Skip 12-byte header + question section. We don't fully parse
        # the question name; just bail if we can't find a likely answer.
        off = 12
        qdcount = (payload[4] << 8) | payload[5]
        for _ in range(qdcount):
            if off >= len(payload):
                return None
            while off < len(payload):
                ln = payload[off]
                if ln == 0:
                    off += 1
                    break
                if ln & 0xC0:
                    off += 2
                    break
                off += 1 + ln
            off += 4  # QTYPE + QCLASS
        if off + 10 > len(payload):
            return None
        # Skip name in answer (could be pointer or labels).
        first = payload[off]
        if first & 0xC0:
            off += 2
        else:
            while off < len(payload):
                ln = payload[off]
                if ln == 0:
                    off += 1
                    break
                off += 1 + ln
        # TYPE(2) CLASS(2) TTL(4) RDLENGTH(2)
        if off + 10 > len(payload):
            return None
        ttl = int.from_bytes(payload[off + 4:off + 8], "big")
        return ttl
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Detector 3 — Exfiltration ratio                                             #
# --------------------------------------------------------------------------- #
def detect_exfiltration(packets, flows) -> List[Anomaly]:
    """Per flow: bytes sent by initiator / bytes received. Ratio > 10x is suspicious."""
    out: List[Anomaly] = []

    # Build a (low_ip, low_port) -> Flow map; reuse flows (canonical key
    # already orders endpoints low->high so we can use src=lower to get
    # the initiator bytes).
    for f in flows:
        if f.packet_count < 4:
            continue
        # Spec says "per external connection": at least one endpoint
        # must be external. Skip pure internal flows (NetBIOS / ARP /
        # AIM-intranet) and skip pure inbound external flows (C2 command
        # delivery) — exfil is by definition *outbound* from an
        # internal host.
        if not (f.src_ip and f.dst_ip):
            continue
        if _is_internal(f.src_ip) and _is_internal(f.dst_ip):
            continue
        # Identify the internal endpoint (may be src OR dst depending
        # on which side is the canonical-low in FlowEngine).
        if _is_internal(f.src_ip):
            internal, external = f.src_ip, f.dst_ip
        elif _is_internal(f.dst_ip):
            internal, external = f.dst_ip, f.src_ip
        else:
            continue  # external-to-external — out of scope
        if f.src_port is None:
            continue

        # Attribute bytes to direction. internal_upload = bytes sent by
        # the internal endpoint (regardless of which side FlowEngine
        # labeled as src). external_response = bytes sent back by the
        # external endpoint.
        internal_upload = 0
        external_response = 0
        for pkt_index in f.packets:
            if pkt_index >= len(packets):
                continue
            m = packets[pkt_index]
            if m.src_ip == internal:
                internal_upload += m.length
            elif m.src_ip == external:
                external_response += m.length
        if internal_upload == 0:
            continue
        ratio = internal_upload / max(external_response, 1)
        if ratio > 10:
            # Score: log10(ratio) normalised into [0, 1] over [10, 1000].
            score = max(0.0, min(1.0, (math.log10(ratio) - 1.0) / 3.0))
            out.append(Anomaly(
                type="exfil_ratio",
                score=score,
                hosts=[internal],
                remote=f"{external}:{f.dst_port or '?'}",
                evidence=(f"{internal} -> {external}:{f.dst_port or '?'}: "
                          f"{internal_upload} bytes up / {external_response} bytes down "
                          f"({ratio:.0f}× ratio)"),
                packets=list(f.packets)[:20],
            ))
    return out


# --------------------------------------------------------------------------- #
# Detector 4 — Port scan                                                      #
# --------------------------------------------------------------------------- #
def detect_port_scan(packets, flows) -> List[Anomaly]:
    """Horizontal (>20 dst pairs in 60s) and vertical (>10 ports on 1 dst)."""
    out: List[Anomaly] = []

    # Bucket SYNs by source IP and time window.
    series_by_src: Dict[str, List[Tuple[float, str, Optional[int], int]]] = defaultdict(list)
    for m in packets:
        if m.protocol != "TCP" or not m.src_ip or not m.dst_ip:
            continue
        if m.tcp_flags and "S" in m.tcp_flags and "A" not in m.tcp_flags:
            series_by_src[m.src_ip].append((m.timestamp, m.dst_ip, m.dst_port, m.index))

    for src, syns in series_by_src.items():
        if len(syns) < 10:
            continue
        syns.sort(key=lambda x: x[0])

        # ---- Horizontal scan ------------------------------------------- #
        pairs_in_window: Dict[float, set] = defaultdict(set)
        pkts_in_window: Dict[float, List[int]] = defaultdict(list)
        for ts, dip, dport, idx in syns:
            bucket = int(ts // 60.0)
            pairs_in_window[bucket].add((dip, dport))
            pkts_in_window[bucket].append(idx)
        for bucket, pairs in pairs_in_window.items():
            if len(pairs) > 20:
                # Compute distinct (dst_ip, port) pairs in this 60s window.
                score = min(1.0, len(pairs) / 80.0)
                out.append(Anomaly(
                    type="port_scan_horizontal",
                    score=score,
                    hosts=[src],
                    remote=f"{len(pairs)} dst pairs",
                    evidence=f"{src}: {len(pairs)} distinct (dst_ip,port) in 60s",
                    packets=list(pkts_in_window[bucket])[:20],
                ))
                break  # one report per scanner is plenty

        # ---- Vertical scan --------------------------------------------- #
        port_count_by_dst: Dict[str, set] = defaultdict(set)
        pkts_vertical: Dict[str, List[int]] = defaultdict(list)
        for ts, dip, dport, idx in syns:
            port_count_by_dst[dip].add(dport)
            pkts_vertical[dip].append(idx)
        for dst, ports in port_count_by_dst.items():
            if len(ports) > 10:
                score = min(1.0, len(ports) / 50.0)
                out.append(Anomaly(
                    type="port_scan_vertical",
                    score=score,
                    hosts=[src],
                    remote=f"{dst}:{len(ports)} ports",
                    evidence=f"{src}: {len(ports)} distinct ports to {dst}",
                    packets=list(pkts_vertical[dst])[:20],
                ))
                break
    return out


# --------------------------------------------------------------------------- #
# Detector 5 — Protocol-port mismatch                                         #
# --------------------------------------------------------------------------- #
def detect_proto_port_mismatch(packets, flows) -> List[Anomaly]:
    """HTTP keywords on non-web ports, TLS on 53, SSH on 80, etc.

    Scoring rules (context.md §14.3):
      - Ephemeral ports (> 49151): EXCLUDED entirely (client-chosen,
        no anomaly signal).
      - Ports in SUSPICIOUS_NONSTANDARD_PORTS or < 1024 with wrong
        protocol: full score (count/20).
      - Other mid-range ports (1024–49151): reduced score 0.3.

    See SUSPICIOUS_NONSTANDARD_PORTS for the list.
    """
    out: List[Anomaly] = []

    web_ports = {80, 443, 8080, 8443}
    by_remote: Dict[Tuple[str, int, str], int] = defaultdict(int)
    sample_pkts: Dict[Tuple[str, int, str], List[int]] = defaultdict(list)

    for m in packets:
        if m.protocol != "TCP" or not m.dst_ip or m.dst_port is None:
            continue
        payload = m.payload or b""
        if not payload:
            continue
        port = m.dst_port
        # Ephemeral port: skip entirely.
        if port >= EPHEMERAL_PORT_MIN:
            continue
        # HTTP on non-web port
        if _http_keyword(payload) and port not in web_ports:
            key = (m.dst_ip, port, "http_on_non_web_port")
            by_remote[key] += 1
            sample_pkts[key].append(m.index)
            continue
        # TLS on port 53
        if _tls_record_byte(payload) and port == 53:
            key = (m.dst_ip, port, "tls_on_53")
            by_remote[key] += 1
            sample_pkts[key].append(m.index)
            continue
        # SSH on port 80
        if _ssh_banner(payload) and port in (80, 8080):
            key = (m.dst_ip, port, "ssh_on_web_port")
            by_remote[key] += 1
            sample_pkts[key].append(m.index)
            continue

    for (dst, port, kind), n in by_remote.items():
        if n < 2:  # require a few occurrences to avoid noise
            continue
        # Score gating per the spec.
        if port < 1024 or port in SUSPICIOUS_NONSTANDARD_PORTS:
            score = min(1.0, n / 20.0)
        else:
            # mid-range, not in suspicious set: reduced score
            score = 0.3
        label = {
            "http_on_non_web_port": f"HTTP traffic on port {port}",
            "tls_on_53": f"TLS ClientHello on port 53 (DoT or tunnel)",
            "ssh_on_web_port": f"SSH banner on port {port}",
        }.get(kind, kind)
        out.append(Anomaly(
            type="proto_port_mismatch",
            score=score,
            hosts=[],
            remote=f"{dst}:{port}",
            evidence=f"{label}: {n} packets",
            packets=sample_pkts[(dst, port, kind)][:10],
        ))
    return out


# --------------------------------------------------------------------------- #
# Detector 6 — Lateral movement                                               #
# --------------------------------------------------------------------------- #
def detect_lateral_movement(packets, flows) -> List[Anomaly]:
    """Internal src connecting to many internal dsts; ARP scan; SMB from non-server."""
    out: List[Anomaly] = []

    # ---- Internal -> many internal ----------------------------------- #
    by_src: Dict[str, set] = defaultdict(set)
    pkts: Dict[str, List[int]] = defaultdict(list)
    for m in packets:
        if not (m.src_ip and m.dst_ip):
            continue
        if not (_is_internal(m.src_ip) and _is_internal(m.dst_ip)):
            continue
        if m.src_ip == m.dst_ip:
            continue
        if m.src_ip.endswith(".1") and m.dst_ip.endswith(".1"):
            continue  # ignore gateway-to-gateway edge cases
        by_src[m.src_ip].add(m.dst_ip)
        pkts[m.src_ip].append(m.index)

    for src, dsts in by_src.items():
        # Exclude gateway-like srcs (.1 addresses) from this sub-check.
        if src.endswith(".1"):
            continue
        if len(dsts) > 3:
            score = min(1.0, len(dsts) / 20.0)
            out.append(Anomaly(
                type="lateral_movement",
                score=score,
                hosts=[src],
                remote=f"{len(dsts)} internal dsts",
                evidence=f"{src}: connections to {len(dsts)} distinct internal IPs",
                packets=pkts[src][:20],
            ))

    # ---- ARP scan: requests to > 50% of observed /24 ------------------ #
    arp_targets_by_src: Dict[str, set] = defaultdict(set)
    arp_pkts: Dict[str, List[int]] = defaultdict(list)
    for m in packets:
        if m.protocol != "ARP":
            continue
        if not m.dst_ip:
            continue
        arp_targets_by_src[m.src_ip or "?"].add(m.dst_ip)
        arp_pkts[m.src_ip or "?"].append(m.index)

    # Build a /24 universe from observed IPs.
    universe: set = set()
    for m in packets:
        if m.dst_ip and _is_internal(m.dst_ip):
            o = _octets(m.dst_ip)
            if o[0] != -1:
                universe.add((o[0], o[1], o[2]))
        if m.src_ip and _is_internal(m.src_ip):
            o = _octets(m.src_ip)
            if o[0] != -1:
                universe.add((o[0], o[1], o[2]))

    if universe:
        for src, targets in arp_targets_by_src.items():
            if len(targets) < 5:
                continue
            observed_24 = {t for t in targets
                           if _is_internal(t) and _octets(t)[:3] in universe}
            if not observed_24:
                continue
            # Count distinct /24s the targets belong to (rarely > 1).
            distinct_24 = {(t.split(".")[:3]) for t in targets}
            for d24 in distinct_24:
                if d24[0] == -1:
                    continue
                # We can't enumerate the full /24; use observed-IP count
                # vs captured-IP-universe proxy: > 50% of captured /24.
                # Use total observed distinct IPs in this /24 across capture.
                all_dst_in_subnet = sum(
                    1 for m2 in packets
                    if m2.dst_ip and m2.dst_ip.startswith(d24[0] + ".")
                )
                if all_dst_in_subnet < 8:
                    continue
                if len(observed_24) / max(all_dst_in_subnet, 1) > 0.5:
                    score = min(1.0, len(observed_24) / all_dst_in_subnet)
                    out.append(Anomaly(
                        type="arp_scan",
                        score=score,
                        hosts=[src],
                        remote=f"{'.'.join(d24)}.0/24",
                        evidence=(f"{src}: {len(observed_24)}/{all_dst_in_subnet} "
                                  f"ARP probes to {d24[0]}.{d24[1]}.{d24[2]}.0/24"),
                        packets=arp_pkts[src][:20],
                    ))
                    break

    # ---- SMB from non-server ----------------------------------------- #
    smb_from: Dict[str, int] = defaultdict(int)
    smb_pkts: Dict[str, List[int]] = defaultdict(list)
    for m in packets:
        if m.protocol != "TCP" or m.dst_port != 445 or not m.src_ip:
            continue
        # Skip obvious server IPs (.10, .20 patterns) heuristically.
        last = m.src_ip.split(".")[-1]
        try:
            if int(last) <= 50:
                continue  # likely a server range
        except ValueError:
            continue
        smb_from[m.src_ip] += 1
        smb_pkts[m.src_ip].append(m.index)

    for src, n in smb_from.items():
        if n >= 3:
            score = min(1.0, n / 20.0)
            out.append(Anomaly(
                type="smb_from_non_server",
                score=score,
                hosts=[src],
                remote="445/tcp",
                evidence=f"{src}: {n} SMB (445/tcp) packets from non-server host",
                packets=smb_pkts[src][:20],
            ))
    return out


# --------------------------------------------------------------------------- #
# Detector 7 — Long connection / low-and-slow                                 #
# --------------------------------------------------------------------------- #
def detect_long_connection(packets, flows) -> List[Anomaly]:
    """TCP sessions > 5 min duration with avg payload < 100 bytes/packet."""
    out: List[Anomaly] = []

    # Skip obvious keep-alive baselines: SSH (22), HTTPS (443), HTTP (80).
    skip_ports = {22, 80, 443, 8080, 8443}

    for f in flows:
        if f.protocol != "TCP":
            continue
        if f.dst_port in skip_ports:
            continue
        duration = f.duration
        if duration < 300.0:
            continue
        # Average payload per packet.
        payload_total = 0
        payload_pkts = 0
        for pkt_index in f.packets:
            if pkt_index >= len(packets):
                continue
            m = packets[pkt_index]
            if m.payload:
                payload_total += len(m.payload)
                payload_pkts += 1
        if payload_pkts == 0:
            continue
        avg = payload_total / payload_pkts
        if avg < 100:
            score = min(1.0, max(0.5, duration / 600.0))
            out.append(Anomaly(
                type="long_connection",
                score=score,
                hosts=[f.src_ip],
                remote=f"{f.dst_ip}:{f.dst_port or '?'}",
                evidence=(f"{f.src_ip}->{f.dst_ip}:{f.dst_port or '?'}: "
                          f"{duration/60:.1f}min, avg {avg:.0f} bytes/pkt "
                          f"({payload_pkts} pkts with payload)"),
                packets=list(f.packets)[:10],
            ))
    return out


# --------------------------------------------------------------------------- #
# Detector 8 — Domain reputation signals                                      #
# --------------------------------------------------------------------------- #
def detect_domain_reputation(packets, flows) -> List[Anomaly]:
    """Lightweight: suspect TLDs + high subdomain depth + IP-as-domain."""
    out: List[Anomaly] = []
    suspicious_domains: Counter = Counter()
    pkts_per_domain: Dict[str, List[int]] = defaultdict(list)
    sample_hosts: Dict[str, str] = {}

    for m in packets:
        if m.protocol != "UDP" or m.dst_port != 53 and m.src_port != 53:
            continue
        if m.dst_port != 53 and m.src_port != 53:
            continue
        payload = m.payload or b""
        if len(payload) < 12:
            continue
        # Only query packets (flags bit 7 = 0).
        if payload[2] & 0x80:
            continue
        name = _decode_dns_name(payload, 12)
        if not name:
            continue
        name = name.lower()
        flags = []
        # IP-shaped: looks like "1-2-3-4.evil.tld" or has many digits in SLD.
        sld = name.split(".")[0] if "." in name else name
        digit_ratio = sum(c.isdigit() for c in sld) / max(len(sld), 1)
        if digit_ratio > 0.5 and len(sld) >= 6:
            flags.append("ip_in_domain")
        # Suspect TLD.
        for tld in _SUSPECT_TLDS:
            if name.endswith(tld):
                flags.append("suspect_tld")
                break
        # Subdomain depth.
        depth = name.count(".")
        if depth >= 4:
            flags.append("deep_subdomain")
        # Random-looking SLD: high entropy + short.
        if 6 <= len(sld) <= 24 and _shannon_entropy(sld) > 3.5:
            flags.append("high_entropy_sld")
        if flags:
            key = name
            suspicious_domains[key] += 1
            pkts_per_domain[key].append(m.index)
            sample_hosts[key] = m.src_ip or "?"

    for name, hits in suspicious_domains.items():
        score = min(1.0, hits / 10.0 + 0.3)
        flags_str = ",".join([
            "ip_in_domain" if "ip_in_domain" in str(name) else "",
            "suspect_tld" if any(name.endswith(t) for t in _SUSPECT_TLDS) else "",
            "deep_subdomain" if name.count(".") >= 4 else "",
            "high_entropy_sld" if _shannon_entropy(name.split(".")[0]) > 3.5 else "",
        ]).strip(",") or "composite"
        out.append(Anomaly(
            type="domain_reputation",
            score=score,
            hosts=[sample_hosts[name]],
            remote=name,
            evidence=f"{name}: {hits} queries ({flags_str})",
            packets=pkts_per_domain[name][:10],
        ))
    return out


# --------------------------------------------------------------------------- #
# Detector 9 — encrypted-traffic metadata                                    #
# --------------------------------------------------------------------------- #
def detect_encrypted_traffic(packets, flows) -> List[Anomaly]:
    """Surface suspicious TLS ClientHello metadata without decrypting content."""
    from core.tls_fingerprint import fingerprint_packets
    results = fingerprint_packets(packets)
    out: List[Anomaly] = []
    missing_sni: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in results:
        packet_index = int(row["packet"])
        packet = packets[packet_index]
        peer = f"{packet.dst_ip or '?'}:{packet.dst_port or '?'}"
        if not row.get("sni"):
            missing_sni[peer].append(row)
    for peer, rows in missing_sni.items():
        if len(rows) < 3:
            continue
        hosts = []
        for row in rows:
            src = packets[int(row["packet"])].src_ip
            if src and src not in hosts:
                hosts.append(src)
        out.append(Anomaly(
            type="tls_fingerprint_anomaly", score=min(.8, .35 + len(rows) / 20),
            hosts=hosts, remote=peer,
            evidence=(f"{len(rows)} TLS ClientHello packets without SNI; "
                      f"JA3={rows[0]['ja3']} JA4={rows[0]['ja4']}"),
            packets=[int(row["packet"]) for row in rows[:20]],
        ))
    return out


# --------------------------------------------------------------------------- #
# Detector 10 — prompt injection in observed content                         #
# --------------------------------------------------------------------------- #
def detect_prompt_injection(packets, flows) -> List[Anomaly]:
    """Packet text that attempts to control an analyst model is itself a finding."""
    from core.untrusted import scan_packets
    out = []
    for row in scan_packets(packets):
        packet_refs = row.get("packets") or [row["packet"]]
        out.append(Anomaly(
            type="prompt_injection_payload", score=.9,
            hosts=[row["src_ip"]] if row.get("src_ip") else [],
            remote=str(row.get("dst_ip") or ""),
            evidence=("Untrusted packet content contains instruction-like text; "
                      f"packet(s) {','.join(map(str, packet_refs))} were isolated "
                      "from prompt semantics"),
            packets=packet_refs,
        ))
    return out


# --------------------------------------------------------------------------- #
# Orchestrator                                                                #
# --------------------------------------------------------------------------- #
def run_all(packets, flows) -> List[Anomaly]:
    """Run deterministic detectors; return merged list sorted by score desc."""
    all_anoms: List[Anomaly] = []
    for fn in (
        detect_beaconing,
        detect_dns_anomaly,
        detect_exfiltration,
        detect_port_scan,
        detect_proto_port_mismatch,
        detect_lateral_movement,
        detect_long_connection,
        detect_domain_reputation,
        detect_encrypted_traffic,
        detect_prompt_injection,
    ):
        try:
            all_anoms.extend(fn(packets, flows))
        except Exception:
            # A buggy detector must not kill the whole pipeline.
            continue
    all_anoms.sort(key=lambda a: a.score, reverse=True)
    return all_anoms
