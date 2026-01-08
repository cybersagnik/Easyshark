"""
Payload search engine with regex and string matching
"""
import re
from typing import List, Optional, Callable
from scapy.all import Raw
from .packet_metadata import PacketMetadata

class PayloadSearcher:
    def __init__(self):
        self.case_sensitive = False
    
    def search_string(self, packets: List[PacketMetadata], search_term: str) -> List[PacketMetadata]:
        """Search for string in packet payloads"""
        results = []
        
        search_bytes = search_term.encode()
        if not self.case_sensitive:
            search_term_lower = search_term.lower()
        
        for meta in packets:
            if not meta.raw_packet or Raw not in meta.raw_packet:
                continue
                
            payload = bytes(meta.raw_packet[Raw].load)
            
            if self.case_sensitive:
                if search_bytes in payload:
                    results.append(meta)
            else:
                if search_term_lower in payload.decode('utf-8', errors='ignore').lower():
                    results.append(meta)
        
        return results
    
    def search_regex(self, packets: List[PacketMetadata], pattern: str) -> List[PacketMetadata]:
        """Search for regex pattern in packet payloads"""
        results = []
        flags = 0 if self.case_sensitive else re.IGNORECASE
        
        try:
            compiled_pattern = re.compile(pattern.encode(), flags)
        except re.error:
            return results
        
        for meta in packets:
            if not meta.raw_packet or Raw not in meta.raw_packet:
                continue
                
            payload = bytes(meta.raw_packet[Raw].load)
            
            if compiled_pattern.search(payload):
                results.append(meta)
        
        return results
    
    def search_field(self, packets: List[PacketMetadata], field: str, value: str) -> List[PacketMetadata]:
        """Search packets by metadata field"""
        results = []
        value_lower = value.lower()
        
        for meta in packets:
            field_value = getattr(meta, field, None)
            
            if field_value is None:
                continue
            
            field_str = str(field_value).lower()
            
            if value_lower in field_str:
                results.append(meta)
        
        return results
    
    def search_port(self, packets: List[PacketMetadata], port: int) -> List[PacketMetadata]:
        """Search packets by port number"""
        return [
            meta for meta in packets
            if meta.src_port == port or meta.dst_port == port
        ]
    
    def search_ip(self, packets: List[PacketMetadata], ip: str) -> List[PacketMetadata]:
        """Search packets by IP address"""
        return [
            meta for meta in packets
            if meta.src_ip == ip or meta.dst_ip == ip
        ]
    
    def search_protocol(self, packets: List[PacketMetadata], protocol: str) -> List[PacketMetadata]:
        """Search packets by protocol"""
        protocol_upper = protocol.upper()
        return [
            meta for meta in packets
            if meta.protocol.upper() == protocol_upper
        ]
    
    def custom_search(self, packets: List[PacketMetadata], predicate: Callable[[PacketMetadata], bool]) -> List[PacketMetadata]:
        """Search packets using custom predicate function"""
        return [meta for meta in packets if predicate(meta)]