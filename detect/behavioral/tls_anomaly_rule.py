"""
TLS anomaly detection rule
"""
from ..base_rule import BaseRule, Alert
from typing import List, Dict, Any
from collections import defaultdict

class TLSAnomalyRule(BaseRule):
    def __init__(self):
        super().__init__("TLSAnomaly", severity="MEDIUM")
        self.non_standard_ports = set()
    
    def analyze(self, context: Dict[str, Any]) -> List[Alert]:
        """Detect TLS anomalies"""
        packets = context.get('packets', [])
        alerts = []
        
        tls_on_non_standard_ports = defaultdict(list)
        
        for meta in packets:
            if not meta.dst_port or not meta.src_port:
                continue
            
            if meta.dst_port not in (443, 8443) and meta.src_port not in (443, 8443):
                if meta.raw_packet:
                    from scapy.all import Raw
                    if Raw in meta.raw_packet:
                        payload = bytes(meta.raw_packet[Raw].load)
                        
                        if len(payload) > 5:
                            if payload[0] == 0x16 and payload[1] == 0x03:
                                key = (meta.src_ip, meta.dst_ip, meta.dst_port)
                                tls_on_non_standard_ports[key].append(meta.index)
        
        for (src_ip, dst_ip, port), indices in tls_on_non_standard_ports.items():
            if len(indices) > 3:
                message = f"TLS traffic on non-standard port: {src_ip} -> {dst_ip}:{port}"
                alert = self.create_alert(
                    message=message,
                    packet_index=indices[0],
                    timestamp=packets[indices[0]].timestamp if indices[0] < len(packets) else 0,
                    metadata={
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'port': port,
                        'packet_count': len(indices)
                    }
                )
                alerts.append(alert)
        
        self.stats['packets_analyzed'] = len(packets)
        return alerts