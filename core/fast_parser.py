"""
FastParser — byte-level header sniffer. Pre-scapy, no allocations.

Used by the loader to extract the few fields every downstream consumer
needs (src/dst IP+port, L4 proto, payload length) before falling back to
scapy for full dissection.

FROZEN signature (per brief §1): FastParser.quick_parse(pkt_bytes) -> dict.
"""
from __future__ import annotations

import struct
from typing import Any, Dict, Optional


class FastParser:
    """All methods are classmethods/static; the class is a namespace."""

    ETHER_TYPE_IPV4 = 0x0800
    ETHER_TYPE_IPV6 = 0x86DD
    ETHER_TYPE_ARP  = 0x0806

    IP_PROTO_TCP = 6
    IP_PROTO_UDP = 17
    IP_PROTO_ICMP = 1

    @staticmethod
    def quick_parse(pkt_bytes: bytes) -> Dict[str, Any]:
        """Return a dict of fields that can be extracted without instantiating
        any scapy layer objects. Fields are best-effort; missing data yields
        None. Keys:
            src_ip, dst_ip         (str or None)
            src_port, dst_port     (int or None)
            ip_proto               (int, the L4 protocol number)
            protocol_name          (str or None)
            payload_size           (int)
            payload_offset         (int, byte index where L4 payload starts)
        """
        out: Dict[str, Any] = {
            "src_ip": None, "dst_ip": None,
            "src_port": None, "dst_port": None,
            "ip_proto": None, "protocol_name": None,
            "payload_size": 0, "payload_offset": None,
            "ether_type": None, "src_mac": None, "dst_mac": None,
            "ttl": None, "ip_version": None,
        }
        if not pkt_bytes or len(pkt_bytes) < 14:
            return out
        try:
            dst_mac = ":".join(f"{b:02x}" for b in pkt_bytes[0:6])
            src_mac = ":".join(f"{b:02x}" for b in pkt_bytes[6:12])
            ether_type = struct.unpack("!H", pkt_bytes[12:14])[0]
            out["dst_mac"] = dst_mac
            out["src_mac"] = src_mac
            out["ether_type"] = ether_type

            if ether_type == FastParser.ETHER_TYPE_IPV4:
                _parse_ipv4(pkt_bytes, out)
            elif ether_type == FastParser.ETHER_TYPE_IPV6:
                _parse_ipv6(pkt_bytes, out)
            elif ether_type == FastParser.ETHER_TYPE_ARP:
                out["protocol_name"] = "ARP"
        except Exception:
            # Malformed packet — return what we have.
            pass
        return out


def _parse_ipv4(pkt_bytes: bytes, out: Dict[str, Any]) -> None:
    if len(pkt_bytes) < 34:
        return
    ver_ihl = pkt_bytes[14]
    version = ver_ihl >> 4
    ihl = (ver_ihl & 0x0F) * 4
    if version != 4 or ihl < 20 or len(pkt_bytes) < 14 + ihl:
        return
    out["ip_version"] = 4
    total_len = struct.unpack("!H", pkt_bytes[16:18])[0]
    ttl = pkt_bytes[22]
    proto = pkt_bytes[23]
    src_ip = ".".join(str(b) for b in pkt_bytes[26:30])
    dst_ip = ".".join(str(b) for b in pkt_bytes[30:34])
    out["src_ip"] = src_ip
    out["dst_ip"] = dst_ip
    out["ttl"] = ttl
    out["ip_proto"] = proto
    payload_offset = 14 + ihl
    out["payload_offset"] = payload_offset
    if proto == FastParser.IP_PROTO_TCP and len(pkt_bytes) >= payload_offset + 20:
        out["protocol_name"] = "TCP"
        src_port, dst_port = struct.unpack("!HH", pkt_bytes[payload_offset:payload_offset+4])
        out["src_port"] = src_port
        out["dst_port"] = dst_port
        data_offset = (pkt_bytes[payload_offset + 12] >> 4) * 4
        l4_payload_start = payload_offset + data_offset
        out["payload_size"] = max(0, total_len - (l4_payload_start - 14))
    elif proto == FastParser.IP_PROTO_UDP and len(pkt_bytes) >= payload_offset + 8:
        out["protocol_name"] = "UDP"
        src_port, dst_port, udp_len = struct.unpack("!HHH", pkt_bytes[payload_offset:payload_offset+6])
        out["src_port"] = src_port
        out["dst_port"] = dst_port
        out["payload_size"] = max(0, udp_len - 8)
    elif proto == FastParser.IP_PROTO_ICMP:
        out["protocol_name"] = "ICMP"


def _parse_ipv6(pkt_bytes: bytes, out: Dict[str, Any]) -> None:
    if len(pkt_bytes) < 54:
        return
    ver_tc_fl = struct.unpack("!I", pkt_bytes[14:18])[0]
    version = ver_tc_fl >> 28
    if version != 6:
        return
    out["ip_version"] = 6
    payload_len = struct.unpack("!H", pkt_bytes[18:20])[0]
    proto = pkt_bytes[20]
    out["ip_proto"] = proto
    out["src_ip"] = _ipv6_str(pkt_bytes[22:38])
    out["dst_ip"] = _ipv6_str(pkt_bytes[38:54])
    payload_offset = 14 + 40
    out["payload_offset"] = payload_offset
    out["payload_size"] = payload_len
    if proto == FastParser.IP_PROTO_TCP and len(pkt_bytes) >= payload_offset + 20:
        out["protocol_name"] = "TCP"
        src_port, dst_port = struct.unpack("!HH", pkt_bytes[payload_offset:payload_offset+4])
        out["src_port"] = src_port
        out["dst_port"] = dst_port
    elif proto == FastParser.IP_PROTO_UDP and len(pkt_bytes) >= payload_offset + 8:
        out["protocol_name"] = "UDP"
        src_port, dst_port = struct.unpack("!HH", pkt_bytes[payload_offset:payload_offset+4])
        out["src_port"] = src_port
        out["dst_port"] = dst_port


def _ipv6_str(b: bytes) -> str:
    """Render 16 raw bytes as a colon-separated IPv6 string."""
    parts = []
    for i in range(0, 16, 2):
        parts.append(f"{(b[i] << 8) | b[i+1]:x}")
    # Compress the longest run of zeros (simple).
    s = ":".join(parts)
    # Skip full zero compression here; keep the literal form for now.
    return s
