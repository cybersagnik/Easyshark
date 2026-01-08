"""
Advanced filter engine for packets, flows, and alerts
"""
from typing import List, Optional, Callable
from .packet_metadata import PacketMetadata
from .flow_engine import Flow

class FilterEngine:
    def __init__(self):
        self.active_filters = []
    
    def add_filter(self, filter_func: Callable, description: str):
        """Add a filter function"""
        self.active_filters.append({
            'func': filter_func,
            'description': description
        })
    
    def clear_filters(self):
        """Clear all active filters"""
        self.active_filters.clear()
    
    def apply_filters(self, packets: List[PacketMetadata]) -> List[PacketMetadata]:
        """Apply all active filters to packet list"""
        if not self.active_filters:
            return packets
        
        filtered = packets
        for filter_dict in self.active_filters:
            filtered = [p for p in filtered if filter_dict['func'](p)]
        
        return filtered
    
    def filter_by_protocol(self, packets: List[PacketMetadata], protocol: str) -> List[PacketMetadata]:
        """Filter packets by protocol"""
        protocol_upper = protocol.upper()
        return [p for p in packets if p.protocol.upper() == protocol_upper]
    
    def filter_by_ip(self, packets: List[PacketMetadata], ip: str) -> List[PacketMetadata]:
        """Filter packets by IP address"""
        return [p for p in packets if p.src_ip == ip or p.dst_ip == ip]
    
    def filter_by_port(self, packets: List[PacketMetadata], port: int) -> List[PacketMetadata]:
        """Filter packets by port"""
        return [p for p in packets if p.src_port == port or p.dst_port == port]
    
    def filter_by_name(self, packets: List[PacketMetadata], name: str) -> List[PacketMetadata]:
        """Filter packets by name (protocol, alert, or rule name)"""
        name_lower = name.lower()
        results = []
        
        for p in packets:
            if p.protocol and name_lower in p.protocol.lower():
                results.append(p)
                continue
            
            if p.alerts:
                for alert in p.alerts:
                    alert_str = str(alert).lower()
                    if name_lower in alert_str:
                        results.append(p)
                        break
            
            if p.dns_query and name_lower == 'dns':
                results.append(p)
            elif name_lower == 'portscan' and hasattr(p, 'is_portscan') and p.is_portscan:
                results.append(p)
            elif name_lower == 'beacon' and hasattr(p, 'is_beacon') and p.is_beacon:
                results.append(p)
        
        return results
    
    def filter_flows_by_ip(self, flows: List[Flow], ip: str) -> List[Flow]:
        """Filter flows by IP address"""
        return [f for f in flows if f.src_ip == ip or f.dst_ip == ip]
    
    def filter_flows_by_port(self, flows: List[Flow], port: int) -> List[Flow]:
        """Filter flows by port"""
        return [f for f in flows if f.src_port == port or f.dst_port == port]
    
    def filter_flows_by_protocol(self, flows: List[Flow], protocol: str) -> List[Flow]:
        """Filter flows by protocol"""
        protocol_upper = protocol.upper()
        return [f for f in flows if f.protocol.upper() == protocol_upper]
    
    def filter_alerts_by_name(self, packets: List[PacketMetadata], alert_name: str) -> List[PacketMetadata]:
        """Filter packets that have alerts matching name"""
        name_lower = alert_name.lower()
        results = []
        
        for p in packets:
            if p.alerts:
                for alert in p.alerts:
                    if name_lower in str(alert).lower():
                        results.append(p)
                        break
        
        return results
    
    def create_filter(self, filter_type: str, value: str) -> Optional[Callable]:
        """Create a filter function based on type and value"""
        filter_type_lower = filter_type.lower()
        
        if filter_type_lower == 'protocol':
            return lambda p: p.protocol.upper() == value.upper()
        elif filter_type_lower == 'ip':
            return lambda p: p.src_ip == value or p.dst_ip == value
        elif filter_type_lower == 'port':
            try:
                port = int(value)
                return lambda p: p.src_port == port or p.dst_port == port
            except ValueError:
                return None
        elif filter_type_lower == 'name':
            value_lower = value.lower()
            def name_filter(p):
                if p.protocol and value_lower in p.protocol.lower():
                    return True
                if p.alerts:
                    for alert in p.alerts:
                        if value_lower in str(alert).lower():
                            return True
                return False
            return name_filter
        
        return None