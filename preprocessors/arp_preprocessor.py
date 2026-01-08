"""
ARP spoofing detection preprocessor
"""
from .base_preprocessor import BasePreprocessor
from core.packet_metadata import PacketMetadata
from typing import List, Dict

class ARPPreprocessor(BasePreprocessor):
    def __init__(self):
        super().__init__("ARPMonitor")
        self.arp_cache: Dict[str, str] = {}
        self.arp_request_count: Dict[str, int] = {}
    
    def process(self, meta: PacketMetadata) -> List[str]:
        """Process ARP packets"""
        alerts = []
        
        if meta.protocol != "ARP":
            return alerts
        
        from scapy.layers.l2 import ARP
        if meta.raw_packet is None:
            return alerts
        if ARP not in meta.raw_packet:
            return alerts
        
        arp_pkt = meta.raw_packet[ARP]
        src_ip = arp_pkt.psrc
        src_mac = arp_pkt.hwsrc
        
        if arp_pkt.op == 2:
            if src_ip in self.arp_cache:
                cached_mac = self.arp_cache[src_ip]
                if cached_mac != src_mac:
                    alert = f"Possible ARP spoofing: {src_ip} changed MAC from {cached_mac} to {src_mac}"
                    self.add_alert(meta, alert)
                    alerts.append(alert)
            
            self.arp_cache[src_ip] = src_mac
        
        elif arp_pkt.op == 1:
            self.arp_request_count[src_ip] = self.arp_request_count.get(src_ip, 0) + 1
            
            if self.arp_request_count[src_ip] > 100:
                alert = f"Excessive ARP requests from {src_ip}: {self.arp_request_count[src_ip]}"
                self.add_alert(meta, alert)
                alerts.append(alert)
        
        self.update_stats()
        return alerts