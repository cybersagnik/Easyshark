"""
AI-powered detection rule generation
"""
from .llm_client import LLMClient
from typing import Optional
import logging

logger = logging.getLogger(__name__)

class RuleGenerator:
    def __init__(self, llm_client: LLMClient):
        self.llm = llm_client
    
    def generate_snort_rule(self, description: str) -> Optional[str]:
        """Generate Snort-style detection rule"""
        if not self.llm.is_available():
            return None
        
        prompt = f"""Generate a Snort rule for this detection requirement:

{description}

Format the rule following Snort syntax:
alert <protocol> <src_ip> <src_port> -> <dst_ip> <dst_port> (msg:"..."; content:"..."; sid:1000001; rev:1;)

Snort Rule:"""
        
        response = self.llm.query_coder(prompt, "Snort rule generation")
        return response
    
    def generate_yara_rule(self, description: str) -> Optional[str]:
        """Generate YARA detection rule"""
        if not self.llm.is_available():
            return None
        
        prompt = f"""Generate a YARA rule for this detection requirement:

{description}

Format the rule following YARA syntax with strings and condition sections.

YARA Rule:"""
        
        response = self.llm.query_coder(prompt, "YARA rule generation")
        return response
    
    def generate_python_detector(self, description: str) -> Optional[str]:
        """Generate Python detection function"""
        if not self.llm.is_available():
            return None
        
        prompt = f"""Generate a Python function to detect this network behavior:

{description}

The function should:
1. Accept packet metadata as input
2. Return True if suspicious behavior is detected
3. Include comments explaining the logic

Python code:"""
        
        response = self.llm.query_coder(prompt, "Python detector generation")
        return response
    
    def suggest_signatures(self, malware_family: str) -> Optional[str]:
        """Suggest detection signatures for malware family"""
        if not self.llm.is_available():
            return None
        
        prompt = f"""List network signatures and IOCs for detecting {malware_family} malware:

Provide:
1. Common C2 domains/IPs
2. Network behavior patterns
3. Payload signatures
4. Port usage

Detection Signatures:"""
        
        response = self.llm.query_coder(prompt, f"Signatures for {malware_family}")
        return response