"""
Packet indexing for fast lookups
"""
from typing import Dict, List, Set, Optional
from collections import defaultdict
from .packet_metadata import PacketMetadata

class PacketIndex:
    def __init__(self):
        self.by_ip: Dict[str, List[int]] = defaultdict(list)
        self.by_port: Dict[int, List[int]] = defaultdict(list)
        self.by_protocol: Dict[str, List[int]] = defaultdict(list)
        self.by_flow: Dict[str, List[int]] = defaultdict(list)
        self.packets: List[PacketMetadata] = []
    
    def add_packet(self, meta: PacketMetadata):
        """Add packet to index"""
        self.packets.append(meta)
        idx = meta.index
        
        if meta.src_ip:
            self.by_ip[meta.src_ip].append(idx)
        if meta.dst_ip:
            self.by_ip[meta.dst_ip].append(idx)
        
        if meta.src_port:
            self.by_port[meta.src_port].append(idx)
        if meta.dst_port:
            self.by_port[meta.dst_port].append(idx)
        
        if meta.protocol:
            self.by_protocol[meta.protocol].append(idx)
        
        if meta.flow_key:
            self.by_flow[meta.flow_key].append(idx)
    
    def get_by_index(self, index: int) -> Optional[PacketMetadata]:
        """Get packet by index"""
        if 0 <= index < len(self.packets):
            return self.packets[index]
        return None
    
    def get_by_ip(self, ip: str) -> List[PacketMetadata]:
        """Get all packets involving IP"""
        indices = self.by_ip.get(ip, [])
        return [self.packets[i] for i in indices if i < len(self.packets)]
    
    def get_by_port(self, port: int) -> List[PacketMetadata]:
        """Get all packets involving port"""
        indices = self.by_port.get(port, [])
        return [self.packets[i] for i in indices if i < len(self.packets)]
    
    def get_by_protocol(self, protocol: str) -> List[PacketMetadata]:
        """Get all packets of protocol"""
        indices = self.by_protocol.get(protocol, [])
        return [self.packets[i] for i in indices if i < len(self.packets)]
    
    def get_by_flow(self, flow_key: str) -> List[PacketMetadata]:
        """Get all packets in flow"""
        indices = self.by_flow.get(flow_key, [])
        return [self.packets[i] for i in indices if i < len(self.packets)]
    
    def get_all_packets(self) -> List[PacketMetadata]:
        """Get all packets"""
        return self.packets
    
    def get_unique_ips(self) -> Set[str]:
        """Get all unique IPs"""
        return set(self.by_ip.keys())
    
    def get_unique_ports(self) -> Set[int]:
        """Get all unique ports"""
        return set(self.by_port.keys())
    
    def get_unique_protocols(self) -> Set[str]:
        """Get all unique protocols"""
        return set(self.by_protocol.keys())
    
    def count(self) -> int:
        """Get total packet count"""
        return len(self.packets)