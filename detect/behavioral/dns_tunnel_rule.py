"""
DNS tunneling detection rule
"""
from ..base_rule import BaseRule, Alert
from typing import List, Dict, Any
from collections import defaultdict
import math

class DNSTunnelRule(BaseRule):
    def __init__(self, query_threshold: int = 50, entropy_threshold: float = 3.5):
        super().__init__("DNSTunnel", severity="HIGH")
        self.query_threshold = query_threshold
        self.entropy_threshold = entropy_threshold
    
    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of string"""
        if not text:
            return 0.0
        
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        entropy = 0.0
        for count in freq.values():
            prob = count / len(text)
            entropy -= prob * math.log2(prob)
        
        return entropy
    
    def analyze(self, context: Dict[str, Any]) -> List[Alert]:
        """Detect DNS tunneling"""
        packets = context.get('packets', [])
        alerts = []
        
        domain_queries = defaultdict(list)
        
        for meta in packets:
            if not meta.dns_query:
                continue
            
            query = meta.dns_query.rstrip('.')
            parts = query.split('.')
            
            if len(parts) < 2:
                continue
            
            base_domain = '.'.join(parts[-2:])
            subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''
            
            domain_queries[base_domain].append({
                'query': query,
                'subdomain': subdomain,
                'index': meta.index,
                'timestamp': meta.timestamp
            })
        
        for domain, queries in domain_queries.items():
            if len(queries) < self.query_threshold:
                continue
            
            high_entropy_count = 0
            long_subdomain_count = 0
            
            for q in queries:
                subdomain = q['subdomain']
                
                if len(subdomain) > 20:
                    long_subdomain_count += 1
                
                if subdomain:
                    entropy = self.calculate_entropy(subdomain)
                    if entropy > self.entropy_threshold:
                        high_entropy_count += 1
            
            suspicion_score = high_entropy_count / len(queries)
            
            if suspicion_score > 0.3 or long_subdomain_count > len(queries) * 0.5:
                message = f"Possible DNS tunneling to {domain} ({len(queries)} queries, {high_entropy_count} high-entropy)"
                alert = self.create_alert(
                    message=message,
                    packet_index=queries[0]['index'],
                    timestamp=queries[0]['timestamp'],
                    metadata={
                        'domain': domain,
                        'query_count': len(queries),
                        'high_entropy_count': high_entropy_count,
                        'suspicion_score': suspicion_score
                    }
                )
                alerts.append(alert)
        
        self.stats['packets_analyzed'] = len(packets)
        return alerts