"""
TLS/SSL analysis preprocessor
"""
from .base_preprocessor import BasePreprocessor
from core.packet_metadata import PacketMetadata
from scapy.all import Raw
from typing import List

class TLSPreprocessor(BasePreprocessor):
    def __init__(self):
        super().__init__("TLSAnalyzer")
        self.tls_flows = {}
    
    def process(self, meta: PacketMetadata) -> List[str]:
        """Process TLS packets"""
        alerts = []
        
        if meta.dst_port not in (443, 8443) and meta.src_port not in (443, 8443):
            return alerts
        
        if not meta.raw_packet or Raw not in meta.raw_packet:
            return alerts
        
        try:
            payload = bytes(meta.raw_packet[Raw].load)
            
            if len(payload) < 5:
                return alerts
            
            content_type = payload[0]
            version = (payload[1], payload[2])
            
            if content_type == 0x16:
                if len(payload) > 5:
                    handshake_type = payload[5]
                    
                    if handshake_type == 0x01:
                        alert = f"TLS ClientHello detected"
                        if version[0] == 3 and version[1] < 3:
                            alert = f"Old TLS version detected: {version[0]}.{version[1]}"
                            self.add_alert(meta, alert)
                            alerts.append(alert)
                    
                    if len(payload) > 43:
                        session_id_len = payload[43]
                        if session_id_len > 32:
                            alert = f"Abnormal TLS session ID length: {session_id_len}"
                            self.add_alert(meta, alert)
                            alerts.append(alert)
            
            elif content_type == 0x15:
                alert = "TLS Alert message detected"
                self.add_alert(meta, alert)
                alerts.append(alert)
        
        except Exception:
            pass
        
        self.update_stats()
        return alerts