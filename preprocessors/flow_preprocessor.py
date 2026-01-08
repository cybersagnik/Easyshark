"""
Flow state tracking preprocessor
"""
from .base_preprocessor import BasePreprocessor
from core.packet_metadata import PacketMetadata
from typing import List, Dict

class FlowPreprocessor(BasePreprocessor):
    def __init__(self):
        super().__init__("FlowTracker")
        self.flow_states: Dict[str, dict] = {}
    
    def process(self, meta: PacketMetadata) -> List[str]:
        """Process packet and track flow state"""
        alerts = []
        
        if not meta.flow_key:
            return alerts
        
        flow_key = meta.flow_key
        
        if flow_key not in self.flow_states:
            self.flow_states[flow_key] = {
                'packet_count': 0,
                'byte_count': 0,
                'syn_seen': False,
                'established': False,
                'first_timestamp': meta.timestamp,
                'last_timestamp': meta.timestamp
            }
        
        state = self.flow_states[flow_key]
        state['packet_count'] += 1
        state['byte_count'] += meta.length
        state['last_timestamp'] = meta.timestamp
        
        if meta.protocol == "TCP" and meta.tcp_flags:
            if 'SYN' in meta.tcp_flags and not 'ACK' in meta.tcp_flags:
                state['syn_seen'] = True
            elif 'SYN' in meta.tcp_flags and 'ACK' in meta.tcp_flags:
                if state['syn_seen']:
                    state['established'] = True
            
            if 'RST' in meta.tcp_flags:
                alert = f"TCP RST detected in flow {flow_key}"
                self.add_alert(meta, alert)
                alerts.append(alert)
        
        self.update_stats()
        return alerts