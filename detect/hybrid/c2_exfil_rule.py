"""
Hybrid C2 and data exfiltration detection rule
Combines behavioral and signature-based detection
"""
from ..base_rule import BaseRule, Alert
from typing import List, Dict, Any
from collections import defaultdict
from scapy.all import Raw

class C2ExfilRule(BaseRule):
    def __init__(self):
        super().__init__("C2Exfiltration", severity="CRITICAL")
        self.c2_indicators = [
            b'cmd.exe',
            b'powershell',
            b'/bin/sh',
            b'|curl',
            b'wget ',
        ]
    
    def analyze(self, context: Dict[str, Any]) -> List[Alert]:
        """Detect C2 and exfiltration activity"""
        packets = context.get('packets', [])
        flows = context.get('flows', [])
        alerts = []
        
        large_upload_flows = []
        for flow in flows:
            if flow.bytes_sent > 1000000:
                large_upload_flows.append(flow)
        
        suspicious_payloads = defaultdict(list)
        for meta in packets:
            if not meta.raw_packet or Raw not in meta.raw_packet:
                continue
            
            payload = bytes(meta.raw_packet[Raw].load)
            
            for indicator in self.c2_indicators:
                if indicator in payload:
                    key = (meta.src_ip, meta.dst_ip)
                    suspicious_payloads[key].append({
                        'index': meta.index,
                        'timestamp': meta.timestamp,
                        'indicator': indicator.decode('utf-8', errors='ignore')
                    })
                    break
        
        for (src_ip, dst_ip), detections in suspicious_payloads.items():
            matching_flows = [f for f in large_upload_flows 
                            if f.src_ip == src_ip and f.dst_ip == dst_ip]
            
            if matching_flows:
                flow = matching_flows[0]
                message = f"Possible C2 exfiltration: {src_ip} -> {dst_ip} (indicators: {len(detections)}, uploaded: {flow.bytes_sent} bytes)"
                alert = self.create_alert(
                    message=message,
                    packet_index=detections[0]['index'],
                    timestamp=detections[0]['timestamp'],
                    metadata={
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'indicator_count': len(detections),
                        'bytes_uploaded': flow.bytes_sent,
                        'indicators': [d['indicator'] for d in detections[:5]]
                    }
                )
                alerts.append(alert)
            elif len(detections) >= 3:
                message = f"Possible C2 activity: {src_ip} -> {dst_ip} ({len(detections)} command indicators)"
                alert = self.create_alert(
                    message=message,
                    packet_index=detections[0]['index'],
                    timestamp=detections[0]['timestamp'],
                    metadata={
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'indicator_count': len(detections),
                        'indicators': [d['indicator'] for d in detections[:5]]
                    }
                )
                alerts.append(alert)
        
        self.stats['packets_analyzed'] = len(packets)
        return alerts