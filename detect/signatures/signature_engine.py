"""
Signature-based detection engine
"""
from typing import List, Dict, Any
from scapy.all import Raw
from .aho_corasick import AhoCorasick
from ..base_rule import BaseRule, Alert

class SignatureEngine(BaseRule):
    def __init__(self):
        super().__init__("SignatureEngine", severity="MEDIUM")
        self.ac = AhoCorasick()
        self.signatures = {}
        self.load_default_signatures()
    
    def load_default_signatures(self):
        """Load default threat signatures"""
        default_sigs = {
            'malware_cobalt_strike': b'MSSE',
            'malware_emotet': b'Emotet',
            'exploit_ms17_010': b'\\PIPE\\browser',
            'exploit_eternalblue': b'SMBr',
            'shellcode_metasploit': b'\x90\x90\x90\x90',
            'c2_callback': b'Mozilla/4.0 (compatible; MSIE 6.0;',
            'sql_injection': b'UNION SELECT',
            'xss_attack': b'<script>alert(',
            'directory_traversal': b'../',
            'cmd_injection': b'|cmd.exe'
        }
        
        for name, pattern in default_sigs.items():
            self.add_signature(name, pattern)
    
    def add_signature(self, name: str, pattern: bytes):
        """Add a signature pattern"""
        self.signatures[name] = pattern
        self.ac.add_pattern(pattern, name)
    
    def build_automaton(self):
        """Build Aho-Corasick automaton"""
        self.ac.build()
    
    def analyze(self, context: Dict[str, Any]) -> List[Alert]:
        """Analyze packets against signatures"""
        packets = context.get('packets', [])
        alerts = []
        
        self.build_automaton()
        
        for meta in packets:
            if not meta.raw_packet or Raw not in meta.raw_packet:
                continue
            
            payload = bytes(meta.raw_packet[Raw].load)
            
            matches = self.ac.search(payload)
            
            for position, sig_name in matches:
                message = f"Signature match: {sig_name} at offset {position}"
                alert = self.create_alert(
                    message=message,
                    packet_index=meta.index,
                    timestamp=meta.timestamp,
                    metadata={
                        'signature': sig_name,
                        'offset': position,
                        'payload_len': len(payload)
                    }
                )
                alerts.append(alert)
        
        self.stats['packets_analyzed'] = len(packets)
        return alerts