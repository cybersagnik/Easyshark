"""
PacketMetadata — unified per-packet record.

FROZEN behaviour (per brief §1):
  - Dataclass with the attributes downstream code reads.
  - Constructed once per packet by the loader.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PacketMetadata:
    """Snapshot of one packet, as seen by every downstream consumer.

    Fields are intentionally permissive: dissectors, preprocessors, and
    detection rules all attach their findings to `.attributes` rather than
    growing this dataclass.
    """
    index:        int                          # 0-based position in the capture
    timestamp:    float                        # epoch seconds (scapy time)
    length:       int                          # total bytes on wire
    src_ip:       Optional[str] = None
    dst_ip:       Optional[str] = None
    src_port:     Optional[int] = None
    dst_port:     Optional[int] = None
    protocol:     Optional[str] = None         # 'TCP' / 'UDP' / 'ICMP' / 'ARP' / ...
    ip_proto:     Optional[int] = None         # numeric (6 = TCP, 17 = UDP)
    src_mac:      Optional[str] = None
    dst_mac:      Optional[str] = None
    tcp_flags:    Optional[str] = None         # 'S', 'PA', 'FA', etc.
    tcp_seq:      Optional[int] = None
    tcp_ack:      Optional[int] = None
    ttl:          Optional[int] = None
    payload:      bytes = b""                  # L4 payload bytes (may be empty)
    payload_size: int = 0
    raw_packet:   Any = None                   # original scapy packet, kept
    attributes:   Dict[str, Any] = field(default_factory=dict)

    @property
    def flow_key(self) -> Optional[tuple]:
        """5-tuple (proto, src_ip, src_port, dst_ip, dst_port) for flow join.
        Returns None if any of the 5 components is missing."""
        if not (self.src_ip and self.dst_ip and self.protocol):
            return None
        return (self.protocol, self.src_ip, self.src_port, self.dst_ip, self.dst_port)

    def reverse_flow_key(self) -> Optional[tuple]:
        """Same 5-tuple with src/dst swapped. Used to merge A->B and B->A
        flows into one conversation."""
        fk = self.flow_key
        if fk is None:
            return None
        proto, sip, sport, dip, dport = fk
        return (proto, dip, dport, sip, sport)

    @classmethod
    def from_packet(cls, pkt, index: int, fast_parsed: Optional[Dict[str, Any]] = None) -> "PacketMetadata":
        """Build a PacketMetadata from a scapy packet + optional fast_parse
        hints. Tolerant of malformed packets — every field is best-effort."""
        from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, Raw, Ether
        ts = float(getattr(pkt, "time", 0.0) or 0.0)
        total_len = len(pkt)

        src_ip = dst_ip = src_mac = dst_mac = None
        ip_proto_num = None
        ttl_v = None
        if IP in pkt:
            src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
            ip_proto_num = int(pkt[IP].proto)
            ttl_v = int(pkt[IP].ttl)
        elif IPv6 in pkt:
            src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst
            ip_proto_num = int(pkt[IPv6].nh)
            ttl_v = int(pkt[IPv6].hlim)
        if Ether in pkt:
            src_mac, dst_mac = pkt[Ether].src, pkt[Ether].dst

        proto_name = None
        src_port = dst_port = None
        tcp_flags = tcp_seq = tcp_ack = None
        payload = b""
        if TCP in pkt:
            proto_name = "TCP"
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
            tcp_seq = int(pkt[TCP].seq)
            tcp_ack = int(pkt[TCP].ack)
            flags_int = int(pkt[TCP].flags)
            tcp_flags = _tcp_flags_to_str(flags_int)
            payload = bytes(pkt[TCP].payload) if Raw in pkt else b""
        elif UDP in pkt:
            proto_name = "UDP"
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)
            payload = bytes(pkt[UDP].payload) if Raw in pkt else b""
        elif ICMP in pkt:
            proto_name = "ICMP"
            payload = bytes(pkt[ICMP].payload) if Raw in pkt else b""
        elif ARP in pkt:
            proto_name = "ARP"

        return cls(
            index=index,
            timestamp=ts,
            length=total_len,
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port,
            protocol=proto_name,
            ip_proto=ip_proto_num,
            src_mac=src_mac, dst_mac=dst_mac,
            tcp_flags=tcp_flags,
            tcp_seq=tcp_seq, tcp_ack=tcp_ack,
            ttl=ttl_v,
            payload=payload,
            payload_size=len(payload),
            raw_packet=pkt,
        )

    def short(self) -> str:
        """One-line summary, used by the formatter / TUI."""
        proto = self.protocol or "?"
        sip = self.src_ip or "?"
        dip = self.dst_ip or "?"
        if self.src_port and self.dst_port:
            return f"{self.index:>5}  {self.timestamp:.6f}  {proto}  {sip}:{self.src_port} -> {dip}:{self.dst_port}  len={self.length}"
        return f"{self.index:>5}  {self.timestamp:.6f}  {proto}  {sip} -> {dip}  len={self.length}"


def _tcp_flags_to_str(flags_int: int) -> str:
    """Compact TCP-flag string like 'S', 'SA', 'PA', 'FA', 'R'."""
    parts = []
    if flags_int & 0x01: parts.append("F")
    if flags_int & 0x02: parts.append("S")
    if flags_int & 0x04: parts.append("R")
    if flags_int & 0x08: parts.append("P")
    if flags_int & 0x10: parts.append("A")
    if flags_int & 0x20: parts.append("U")
    if flags_int & 0x40: parts.append("E")
    if flags_int & 0x80: parts.append("C")
    return "".join(parts)
