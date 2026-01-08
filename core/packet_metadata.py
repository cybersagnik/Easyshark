"""
Packet metadata storage and extraction
"""
from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from scapy.packet import Packet, Raw
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.layers.l2 import ARP
import time

@dataclass
class PacketMetadata:
    index: int
    timestamp: float
    length: int
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str = "Unknown"
    protocol_num: Optional[int] = None
    tcp_flags: Optional[str] = None
    payload_len: int = 0
    flow_key: Optional[str] = None
    dns_query: Optional[str] = None
    dns_response: Optional[str] = None
    http_method: Optional[str] = None
    http_host: Optional[str] = None
    tls_sni: Optional[str] = None
    arp_op: Optional[str] = None
    raw_packet: Optional[Packet] = None
    fast_parsed: Optional[Dict] = None
    alerts: list = field(default_factory=list)
    # Optional flags set by rules/preprocessors for filtering/type safety
    is_portscan: bool = False
    is_beacon: bool = False
    
    @staticmethod
    def from_packet(pkt: Packet, index: int, fast_parsed: Optional[Dict] = None) -> 'PacketMetadata':
        """Extract metadata from Scapy packet"""
        meta = PacketMetadata(
            index=index,
            timestamp=float(pkt.time) if hasattr(pkt, 'time') else time.time(),
            length=len(pkt),
            raw_packet=pkt,
            fast_parsed=fast_parsed
        )
        
        if IP in pkt:
            meta.src_ip = pkt[IP].src
            meta.dst_ip = pkt[IP].dst
            meta.protocol_num = pkt[IP].proto
            
            if TCP in pkt:
                meta.protocol = "TCP"
                meta.src_port = pkt[TCP].sport
                meta.dst_port = pkt[TCP].dport
                meta.tcp_flags = PacketMetadata._get_tcp_flags(pkt[TCP])
                meta.flow_key = f"{meta.src_ip}:{meta.src_port}-{meta.dst_ip}:{meta.dst_port}"
            elif UDP in pkt:
                meta.protocol = "UDP"
                meta.src_port = pkt[UDP].sport
                meta.dst_port = pkt[UDP].dport
                meta.flow_key = f"{meta.src_ip}:{meta.src_port}-{meta.dst_ip}:{meta.dst_port}"
            elif ICMP in pkt:
                meta.protocol = "ICMP"
        
        if ARP in pkt:
            meta.protocol = "ARP"
            meta.src_ip = pkt[ARP].psrc
            meta.dst_ip = pkt[ARP].pdst
            meta.arp_op = "request" if pkt[ARP].op == 1 else "reply"
        
        if DNS in pkt:
            if pkt[DNS].qd:
                meta.dns_query = pkt[DNS].qd.qname.decode() if isinstance(pkt[DNS].qd.qname, bytes) else str(pkt[DNS].qd.qname)
            if pkt[DNS].an:
                meta.dns_response = str(pkt[DNS].an)
        
        if Raw in pkt:
            meta.payload_len = len(pkt[Raw].load)
        
        return meta
    
    @staticmethod
    def _get_tcp_flags(tcp_layer) -> str:
        """Get TCP flags as string"""
        flags = []
        if tcp_layer.flags.F: flags.append('FIN')
        if tcp_layer.flags.S: flags.append('SYN')
        if tcp_layer.flags.R: flags.append('RST')
        if tcp_layer.flags.P: flags.append('PSH')
        if tcp_layer.flags.A: flags.append('ACK')
        if tcp_layer.flags.U: flags.append('URG')
        return '|'.join(flags) if flags else ''
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'index': self.index,
            'timestamp': self.timestamp,
            'length': self.length,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'tcp_flags': self.tcp_flags,
            'payload_len': self.payload_len,
            'dns_query': self.dns_query,
            'alerts': [str(a) for a in self.alerts]
        }