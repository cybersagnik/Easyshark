"""
Zeek-style 5-tuple flow tracking engine
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
import time

@dataclass
class Flow:
    flow_key: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packets: List[int] = field(default_factory=list)
    bytes_sent: int = 0
    bytes_recv: int = 0
    start_time: float = 0.0
    last_time: float = 0.0
    syn_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    state: str = "NEW"
    
    def duration(self) -> float:
        """Get flow duration in seconds"""
        return self.last_time - self.start_time if self.last_time > self.start_time else 0.0
    
    def pps(self) -> float:
        """Get packets per second"""
        dur = self.duration()
        return len(self.packets) / dur if dur > 0 else 0.0
    
    def bps(self) -> float:
        """Get bytes per second"""
        dur = self.duration()
        total_bytes = self.bytes_sent + self.bytes_recv
        return total_bytes / dur if dur > 0 else 0.0

class FlowEngine:
    def __init__(self, timeout: float = 300.0):
        self.timeout = timeout
        self.flows: Dict[str, Flow] = {}
        self.reverse_flows: Dict[str, str] = {}
        
    def get_flow_key(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str) -> Tuple[str, bool]:
        """Get flow key, returns (key, is_reverse)"""
        forward_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}/{proto}"
        reverse_key = f"{dst_ip}:{dst_port}->{src_ip}:{src_port}/{proto}"
        
        if forward_key in self.flows:
            return forward_key, False
        elif reverse_key in self.flows:
            return reverse_key, True
        else:
            return forward_key, False
    
    def process_packet(self, meta) -> Optional[Flow]:
        """Process packet and update flow state"""
        if not meta.src_ip or not meta.dst_ip:
            return None
            
        src_port = meta.src_port or 0
        dst_port = meta.dst_port or 0
        
        flow_key, is_reverse = self.get_flow_key(
            meta.src_ip, meta.dst_ip, src_port, dst_port, meta.protocol
        )
        
        if flow_key not in self.flows:
            flow = Flow(
                flow_key=flow_key,
                src_ip=meta.src_ip,
                dst_ip=meta.dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=meta.protocol,
                start_time=meta.timestamp,
                last_time=meta.timestamp
            )
            self.flows[flow_key] = flow
        else:
            flow = self.flows[flow_key]
            flow.last_time = meta.timestamp
        
        flow.packets.append(meta.index)
        
        if is_reverse:
            flow.bytes_recv += meta.length
        else:
            flow.bytes_sent += meta.length
        
        if meta.protocol == "TCP" and meta.tcp_flags:
            if 'SYN' in meta.tcp_flags:
                flow.syn_count += 1
                if flow.syn_count == 1:
                    flow.state = "SYN_SENT"
                elif flow.syn_count == 2:
                    flow.state = "ESTABLISHED"
            if 'FIN' in meta.tcp_flags:
                flow.fin_count += 1
                flow.state = "FIN_WAIT"
            if 'RST' in meta.tcp_flags:
                flow.rst_count += 1
                flow.state = "RESET"
        
        return flow
    
    def get_all_flows(self) -> List[Flow]:
        """Get all tracked flows"""
        return list(self.flows.values())
    
    def get_flows_by_ip(self, ip: str) -> List[Flow]:
        """Get all flows involving an IP"""
        return [f for f in self.flows.values() if ip in (f.src_ip, f.dst_ip)]
    
    def get_flows_by_port(self, port: int) -> List[Flow]:
        """Get all flows involving a port"""
        return [f for f in self.flows.values() if port in (f.src_port, f.dst_port)]
    
    def get_top_talkers(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Get top talkers by packet count"""
        ip_counts = defaultdict(int)
        for flow in self.flows.values():
            ip_counts[flow.src_ip] += len(flow.packets)
            ip_counts[flow.dst_ip] += len(flow.packets)
        return sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:limit]