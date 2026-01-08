"""
Port scan detection rule
"""
from ..base_rule import BaseRule, Alert
from typing import List, Dict, Any
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Set

@dataclass
class PortScanData:
    ports: Set[int] = field(default_factory=set)
    timestamps: List[float] = field(default_factory=list)
    indices: List[int] = field(default_factory=list)

class PortScanRule(BaseRule):
    def __init__(self, threshold: int = 20, time_window: float = 60.0):
        super().__init__("PortScan", severity="HIGH")
        self.threshold = threshold
        self.time_window = time_window
    
    def analyze(self, context: Dict[str, Any]) -> List[Alert]:
        """Detect port scanning behavior"""
        packets = context.get('packets', [])
        alerts = []
        
        src_to_dst_ports = defaultdict(PortScanData)
        
        for meta in packets:
            if meta.protocol != "TCP":
                continue
            
            if not meta.tcp_flags or 'SYN' not in meta.tcp_flags:
                continue
            
            if 'ACK' in meta.tcp_flags:
                continue
            
            key = (meta.src_ip, meta.dst_ip)
            data = src_to_dst_ports[key]
            if meta.dst_port is not None:
                data.ports.add(meta.dst_port)
            data.timestamps.append(meta.timestamp)
            data.indices.append(meta.index)
        
        for (src_ip, dst_ip), data in src_to_dst_ports.items():
            ports = data.ports
            timestamps = data.timestamps
            indices = data.indices
            
            if len(ports) < self.threshold:
                continue
            
            if timestamps:
                time_span = max(timestamps) - min(timestamps)
                
                if time_span <= self.time_window:
                    message = f"Port scan detected: {src_ip} -> {dst_ip} ({len(ports)} ports in {time_span:.2f}s)"
                    alert = self.create_alert(
                        message=message,
                        packet_index=indices[0],
                        timestamp=timestamps[0],
                        metadata={
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'port_count': len(ports),
                            'time_span': time_span,
                            'ports': sorted(ports)[:20]
                        }
                    )
                    alerts.append(alert)
                    
                    for idx in indices:
                        if idx < len(packets):
                            packets[idx].is_portscan = True
        
        self.stats['packets_analyzed'] = len(packets)
        return alerts 