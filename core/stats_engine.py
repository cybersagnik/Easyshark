"""
Packet statistics engine
"""
from collections import defaultdict, Counter
from typing import Dict, List, Any
from .packet_metadata import PacketMetadata

class StatsEngine:
    def __init__(self):
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counts = Counter()
        self.ip_counts = Counter()
        self.port_counts = Counter()
        self.dns_queries = []
        self.alerts = []
        
    def update(self, meta: PacketMetadata):
        """Update statistics with packet metadata"""
        self.total_packets += 1
        self.total_bytes += meta.length
        self.protocol_counts[meta.protocol] += 1
        
        if meta.src_ip:
            self.ip_counts[meta.src_ip] += 1
        if meta.dst_ip:
            self.ip_counts[meta.dst_ip] += 1
            
        if meta.src_port:
            self.port_counts[meta.src_port] += 1
        if meta.dst_port:
            self.port_counts[meta.dst_port] += 1
            
        if meta.dns_query:
            self.dns_queries.append(meta.dns_query)
            
        if meta.alerts:
            self.alerts.extend(meta.alerts)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get statistics summary"""
        return {
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'protocols': dict(self.protocol_counts.most_common()),
            'top_ips': dict(self.ip_counts.most_common(10)),
            'top_ports': dict(self.port_counts.most_common(10)),
            'unique_dns_queries': len(set(self.dns_queries)),
            'total_alerts': len(self.alerts)
        }
    
    def get_protocol_breakdown(self) -> List[tuple]:
        """Get protocol breakdown"""
        return self.protocol_counts.most_common()
    
    def get_top_talkers(self, limit: int = 10) -> List[tuple]:
        """Get top IP addresses by packet count"""
        return self.ip_counts.most_common(limit)
    
    def get_top_ports(self, limit: int = 10) -> List[tuple]:
        """Get top ports by usage"""
        return self.port_counts.most_common(limit)