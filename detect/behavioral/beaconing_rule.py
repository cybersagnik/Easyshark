"""
Beaconing detection rule
"""
from ..base_rule import BaseRule, Alert
from typing import List, Dict, Any
from collections import defaultdict
import statistics

class BeaconingRule(BaseRule):
    def __init__(self, min_connections: int = 10, interval_tolerance: float = 0.2):
        super().__init__("Beaconing", severity="HIGH")
        self.min_connections = min_connections
        self.interval_tolerance = interval_tolerance
    
    def analyze(self, context: Dict[str, Any]) -> List[Alert]:
        """Detect beaconing behavior"""
        flows = context.get('flows', [])
        alerts = []
        
        connection_groups = defaultdict(list)
        
        for flow in flows:
            key = (flow.src_ip, flow.dst_ip, flow.dst_port)
            connection_groups[key].append({
                'start_time': flow.start_time,
                'bytes': flow.bytes_sent + flow.bytes_recv,
                'packets': len(flow.packets)
            })
        
        for (src_ip, dst_ip, dst_port), connections in connection_groups.items():
            if len(connections) < self.min_connections:
                continue
            
            timestamps = sorted([c['start_time'] for c in connections])
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            
            if not intervals:
                continue
            
            mean_interval = statistics.mean(intervals)
            
            if mean_interval == 0:
                continue
            
            try:
                stdev_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
                coeff_of_variation = stdev_interval / mean_interval if mean_interval > 0 else 1
            except:
                coeff_of_variation = 1
            
            if coeff_of_variation < self.interval_tolerance:
                byte_sizes = [c['bytes'] for c in connections]
                mean_bytes = statistics.mean(byte_sizes)
                
                try:
                    stdev_bytes = statistics.stdev(byte_sizes) if len(byte_sizes) > 1 else 0
                    byte_consistency = 1 - (stdev_bytes / mean_bytes) if mean_bytes > 0 else 0
                except:
                    byte_consistency = 0
                
                message = f"Beaconing detected: {src_ip} -> {dst_ip}:{dst_port} ({len(connections)} connections, {mean_interval:.2f}s interval)"
                alert = self.create_alert(
                    message=message,
                    packet_index=0,
                    timestamp=timestamps[0],
                    metadata={
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'dst_port': dst_port,
                        'connection_count': len(connections),
                        'mean_interval': mean_interval,
                        'interval_consistency': 1 - coeff_of_variation,
                        'byte_consistency': byte_consistency
                    }
                )
                alerts.append(alert)
                
                packets = context.get('packets', [])
                for conn in connections:
                    for meta in packets:
                        if (meta.src_ip == src_ip and meta.dst_ip == dst_ip and 
                            abs(meta.timestamp - conn['start_time']) < 1.0):
                            meta.is_beacon = True
        
        self.stats['packets_analyzed'] = len(flows)
        return alerts