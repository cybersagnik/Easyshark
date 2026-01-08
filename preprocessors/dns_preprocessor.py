"""
DNS analysis preprocessor
"""
from .base_preprocessor import BasePreprocessor
from core.packet_metadata import PacketMetadata
from typing import List, Set

class DNSPreprocessor(BasePreprocessor):
    def __init__(self):
        super().__init__("DNSAnalyzer")
        self.dns_queries: Set[str] = set()
        self.suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc'}
        self.dga_threshold = 20
    
    def process(self, meta: PacketMetadata) -> List[str]:
        """Process DNS packets"""
        alerts = []
        
        if not meta.dns_query:
            return alerts
        
        query = meta.dns_query.rstrip('.')
        self.dns_queries.add(query)
        
        if any(query.endswith(tld) for tld in self.suspicious_tlds):
            alert = f"Suspicious TLD in DNS query: {query}"
            self.add_alert(meta, alert)
            alerts.append(alert)
        
        if len(query) > 50:
            alert = f"Unusually long DNS query: {query} ({len(query)} chars)"
            self.add_alert(meta, alert)
            alerts.append(alert)
        
        parts = query.split('.')
        if len(parts) > 0:
            subdomain = parts[0]
            if len(subdomain) > self.dga_threshold:
                consonant_count = sum(1 for c in subdomain if c.lower() in 'bcdfghjklmnpqrstvwxyz')
                vowel_count = sum(1 for c in subdomain if c.lower() in 'aeiou')
                
                if consonant_count > vowel_count * 2:
                    alert = f"Possible DGA domain: {query}"
                    self.add_alert(meta, alert)
                    alerts.append(alert)
        
        self.update_stats()
        return alerts