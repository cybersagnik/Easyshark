"""
StatsEngine — running traffic counters used by get_statistics tool and the
"stats" shell command.

FROZEN behaviour (per brief §1): minimal counters; no rolling windows.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class TrafficStats:
    total_packets:    int = 0
    total_bytes:      int = 0
    protocols:        Counter = field(default_factory=Counter)
    src_ips:          Counter = field(default_factory=Counter)
    dst_ips:          Counter = field(default_factory=Counter)
    src_ports:        Counter = field(default_factory=Counter)
    dst_ports:        Counter = field(default_factory=Counter)
    tcp_flags:        Counter = field(default_factory=Counter)
    start_ts:         Optional[float] = None
    end_ts:           Optional[float] = None

    def to_dict(self) -> Dict:
        return {
            "total_packets":    self.total_packets,
            "total_bytes":      self.total_bytes,
            "protocols":        dict(self.protocols.most_common(10)),
            "top_src_ips":      dict(self.src_ips.most_common(10)),
            "top_dst_ips":      dict(self.dst_ips.most_common(10)),
            "top_src_ports":    dict(self.src_ports.most_common(10)),
            "top_dst_ports":    dict(self.dst_ports.most_common(10)),
            "tcp_flags":        dict(self.tcp_flags.most_common(10)),
            "start_ts":         self.start_ts,
            "end_ts":           self.end_ts,
            "duration_seconds": (self.end_ts or 0) - (self.start_ts or 0),
        }


class StatsEngine:
    """Walks every packet once; counters never expire."""

    def __init__(self):
        self.stats = TrafficStats()

    def update(self, meta) -> None:
        s = self.stats
        s.total_packets += 1
        s.total_bytes += meta.length
        if meta.protocol:
            s.protocols[meta.protocol] += 1
        if meta.src_ip:
            s.src_ips[meta.src_ip] += 1
        if meta.dst_ip:
            s.dst_ips[meta.dst_ip] += 1
        if meta.src_port is not None:
            s.src_ports[meta.src_port] += 1
        if meta.dst_port is not None:
            s.dst_ports[meta.dst_port] += 1
        if meta.tcp_flags:
            s.tcp_flags[meta.tcp_flags] += 1
        if s.start_ts is None or meta.timestamp < s.start_ts:
            s.start_ts = meta.timestamp
        if s.end_ts is None or meta.timestamp > s.end_ts:
            s.end_ts = meta.timestamp

    def summary(self) -> Dict:
        return self.stats.to_dict()
