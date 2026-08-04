"""
FlowEngine — Zeek-style 5-tuple flow tracker.

FROZEN behaviour (per brief §1): one method per upstream consumer.

Public surface used downstream:
    fe.process_packet(meta)
    fe.get_all_flows()  -> list[Flow]
    fe.flows            -> dict[flow_key -> Flow]
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class Flow:
    """One TCP or UDP conversation. Created on first packet, updated on each."""
    key:        Tuple
    src_ip:     str
    dst_ip:     str
    src_port:   Optional[int]
    dst_port:   Optional[int]
    protocol:   str
    packets:    List[int] = field(default_factory=list)   # packet indices
    sizes:      List[int] = field(default_factory=list)
    timestamps: List[float] = field(default_factory=list)
    payload_bytes: bytes = b""
    start_ts:   float = 0.0
    end_ts:     float = 0.0
    state:      str = "open"     # open / closing / closed

    @property
    def packet_count(self) -> int:
        return len(self.packets)

    @property
    def total_bytes(self) -> int:
        return sum(self.sizes)

    @property
    def duration(self) -> float:
        if not self.timestamps:
            return 0.0
        return self.timestamps[-1] - self.timestamps[0]

    def short(self) -> str:
        return (f"{self.protocol} {self.src_ip}:{self.src_port or '?'} -> "
                f"{self.dst_ip}:{self.dst_port or '?'}  "
                f"pkts={self.packet_count}  bytes={self.total_bytes}  "
                f"dur={self.duration:.2f}s")


class FlowEngine:
    """Groups packets into bidirectional 5-tuple flows. Bi-directional
    means A->B and B->A share the same Flow record (key normalized)."""

    def __init__(self, flow_timeout: float = 300.0):
        self.flow_timeout = flow_timeout
        self.flows: Dict[Tuple, Flow] = {}

    def _normalize_key(self, meta) -> Optional[Tuple]:
        fk = meta.flow_key
        if fk is None:
            return None
        # Ensure (lower-IP, lower-port) is always first so A->B == B->A
        proto, sip, sport, dip, dport = fk
        if (sip, sport or 0) > (dip, dport or 0):
            return (proto, dip, dport, sip, sport)
        return fk

    def process_packet(self, meta) -> Optional[Flow]:
        key = self._normalize_key(meta)
        if key is None:
            return None
        flow = self.flows.get(key)
        if flow is None:
            # First packet in this conversation.
            proto, sip, sport, dip, dport = key
            flow = Flow(
                key=key,
                src_ip=sip, src_port=sport,
                dst_ip=dip, dst_port=dport,
                protocol=proto,
                packets=[meta.index],
                sizes=[meta.length],
                timestamps=[meta.timestamp],
                payload_bytes=meta.payload,
                start_ts=meta.timestamp,
                end_ts=meta.timestamp,
            )
            self.flows[key] = flow
            return flow
        flow.packets.append(meta.index)
        flow.sizes.append(meta.length)
        flow.timestamps.append(meta.timestamp)
        flow.end_ts = meta.timestamp
        if meta.payload:
            # Append payload bytes; full TCP reassembly is the job of
            # tcp_reassembly.py (separate module, not duplicated here).
            flow.payload_bytes += meta.payload
        # Update state based on TCP flags if present
        if meta.protocol == "TCP":
            if meta.tcp_flags and "R" in meta.tcp_flags:
                flow.state = "closed"
            elif meta.tcp_flags and "F" in meta.tcp_flags:
                flow.state = "closing"
        return flow

    def get_all_flows(self) -> List[Flow]:
        return list(self.flows.values())

    def get_flow(self, key: Tuple) -> Optional[Flow]:
        return self.flows.get(key)

    def cleanup_expired(self, now_ts: Optional[float] = None) -> int:
        """Close flows idle for > flow_timeout. Returns number closed."""
        now = now_ts if now_ts is not None else time.time()
        closed = 0
        for key, flow in list(self.flows.items()):
            if flow.state == "closed":
                continue
            if (now - flow.end_ts) > self.flow_timeout:
                flow.state = "closed"
                closed += 1
        return closed
