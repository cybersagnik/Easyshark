"""
TCP stream reassembly engine
"""
from typing import Dict, List, Optional
from collections import defaultdict
from dataclasses import dataclass, field

@dataclass
class TCPStream:
    flow_key: str
    segments: Dict[int, bytes] = field(default_factory=dict)
    min_seq: Optional[int] = None
    max_seq: Optional[int] = None
    
    def add_segment(self, seq: int, data: bytes):
        """Add TCP segment to stream"""
        if not data:
            return
            
        self.segments[seq] = data
        
        if self.min_seq is None or seq < self.min_seq:
            self.min_seq = seq
        if self.max_seq is None or seq > self.max_seq:
            self.max_seq = seq
    
    def reassemble(self) -> bytes:
        """Reassemble TCP stream in order"""
        if not self.segments:
            return b''
            
        ordered_seqs = sorted(self.segments.keys())
        reassembled = b''
        
        for seq in ordered_seqs:
            reassembled += self.segments[seq]
        
        return reassembled
    
    def get_payload_size(self) -> int:
        """Get total payload size"""
        return sum(len(data) for data in self.segments.values())

class TCPReassembler:
    def __init__(self):
        self.streams: Dict[str, TCPStream] = defaultdict(lambda: TCPStream(flow_key=''))
    
    def process_packet(self, meta, tcp_info: dict):
        """Process TCP packet for reassembly"""
        if not meta.flow_key:
            return
            
        flow_key = meta.flow_key
        
        if flow_key not in self.streams:
            self.streams[flow_key] = TCPStream(flow_key=flow_key)
        
        stream = self.streams[flow_key]
        
        if meta.payload_len > 0 and meta.raw_packet:
            from scapy.all import Raw
            if Raw in meta.raw_packet:
                payload = bytes(meta.raw_packet[Raw].load)
                seq = tcp_info.get('seq', 0)
                stream.add_segment(seq, payload)
    
    def get_stream(self, flow_key: str) -> Optional[TCPStream]:
        """Get TCP stream by flow key"""
        return self.streams.get(flow_key)
    
    def get_all_streams(self) -> List[TCPStream]:
        """Get all TCP streams"""
        return list(self.streams.values())
    
    def reassemble_stream(self, flow_key: str) -> Optional[bytes]:
        """Reassemble TCP stream"""
        stream = self.get_stream(flow_key)
        if stream:
            return stream.reassemble()
        return None