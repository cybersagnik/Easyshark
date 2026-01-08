"""
HTTP analysis preprocessor
"""
from .base_preprocessor import BasePreprocessor
from core.packet_metadata import PacketMetadata
from scapy.all import Raw
from typing import List

class HTTPPreprocessor(BasePreprocessor):
    def __init__(self):
        super().__init__("HTTPAnalyzer")
        self.http_methods = [b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'OPTIONS', b'PATCH']
        self.suspicious_patterns = [b'../..', b'cmd.exe', b'/etc/passwd', b'<script>', b'union select']
    
    def process(self, meta: PacketMetadata) -> List[str]:
        """Process HTTP packets"""
        alerts = []
        
        if meta.dst_port not in (80, 8080, 8000) and meta.src_port not in (80, 8080, 8000):
            return alerts
        
        if not meta.raw_packet or Raw not in meta.raw_packet:
            return alerts
        
        try:
            payload = bytes(meta.raw_packet[Raw].load)
            
            if len(payload) < 10:
                return alerts
            
            is_http_request = any(payload.startswith(method + b' ') for method in self.http_methods)
            is_http_response = payload.startswith(b'HTTP/')
            
            if not is_http_request and not is_http_response:
                return alerts
            
            payload_lower = payload.lower()
            
            for pattern in self.suspicious_patterns:
                if pattern in payload_lower:
                    alert = f"Suspicious HTTP pattern detected: {pattern.decode('utf-8', errors='ignore')}"
                    self.add_alert(meta, alert)
                    alerts.append(alert)
                    break
            
            if is_http_request:
                lines = payload.split(b'\r\n')
                if lines:
                    request_line = lines[0].decode('utf-8', errors='ignore')
                    meta.http_method = request_line.split()[0] if request_line.split() else None
                    
                    for line in lines[1:]:
                        if line.lower().startswith(b'host:'):
                            meta.http_host = line.split(b':', 1)[1].strip().decode('utf-8', errors='ignore')
                            break
            
            if len(payload) > 10000:
                alert = f"Large HTTP payload: {len(payload)} bytes"
                self.add_alert(meta, alert)
                alerts.append(alert)
        
        except Exception:
            pass
        
        self.update_stats()
        return alerts