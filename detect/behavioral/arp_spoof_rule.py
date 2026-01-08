"""
ARP spoofing detection rule
"""
from ..base_rule import BaseRule, Alert
from typing import List, Dict, Any

class ARPSpoofRule(BaseRule):
    def __init__(self):
        super().__init__("ARPSpoof", severity="CRITICAL")
        self.ip_mac_mapping = {}
    
    def analyze(self, context: Dict[str, Any]) -> List[Alert]:
        """Detect ARP spoofing"""
        packets = context.get('packets', [])
        alerts = []
        
        for meta in packets:
            if meta.protocol != "ARP":
                continue
            
            from scapy.layers.l2 import ARP
            if ARP not in meta.raw_packet:
                continue
            
            arp_pkt = meta.raw_packet[ARP]
            src_ip = arp_pkt.psrc
            src_mac = arp_pkt.hwsrc
            
            if arp_pkt.op == 2:
                if src_ip in self.ip_mac_mapping:
                    stored_mac = self.ip_mac_mapping[src_ip]
                    
                    if stored_mac != src_mac:
                        message = f"ARP spoofing detected: {src_ip} MAC changed from {stored_mac} to {src_mac}"
                        alert = self.create_alert(
                            message=message,
                            packet_index=meta.index,
                            timestamp=meta.timestamp,
                            metadata={
                                'ip': src_ip,
                                'old_mac': stored_mac,
                                'new_mac': src_mac,
                                'operation': 'reply'
                            }
                        )
                        alerts.append(alert)
                
                self.ip_mac_mapping[src_ip] = src_mac
        
        self.stats['packets_analyzed'] = len(packets)
        return alerts