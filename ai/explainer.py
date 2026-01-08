"""
AI-powered traffic analysis and explanation
"""
from .llm_client import LLMClient
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)

class TrafficExplainer:
    def __init__(self, llm_client: LLMClient):
        self.llm = llm_client
    
    def explain_traffic(self, question: str, packets: list, flows: list, alerts: list) -> str:
        """Generate natural language explanation of traffic"""
        data_summary = self._create_summary(packets, flows, alerts)
        
        if not self.llm.is_available():
            return self._fallback_analysis(question, data_summary)
        
        response = self.llm.query_explainer(question, data_summary)
        
        if response:
            return response
        else:
            return self._fallback_analysis(question, data_summary)
    
    def _create_summary(self, packets: list, flows: list, alerts: list) -> Dict[str, Any]:
        """Create data summary for LLM"""
        from collections import Counter
        
        protocols = Counter()
        ips = Counter()
        ports = Counter()
        
        for pkt in packets[:1000]:
            if pkt.protocol:
                protocols[pkt.protocol] += 1
            if pkt.src_ip:
                ips[pkt.src_ip] += 1
            if pkt.dst_ip:
                ips[pkt.dst_ip] += 1
            if pkt.src_port:
                ports[pkt.src_port] += 1
            if pkt.dst_port:
                ports[pkt.dst_port] += 1
        
        alert_types = Counter()
        for alert in alerts[:100]:
            alert_types[alert.rule_name] += 1
        
        return {
            'total_packets': len(packets),
            'total_flows': len(flows),
            'total_alerts': len(alerts),
            'top_protocols': dict(protocols.most_common(5)),
            'top_ips': dict(ips.most_common(10)),
            'top_ports': dict(ports.most_common(10)),
            'alert_types': dict(alert_types.most_common(10))
        }
    
    def _fallback_analysis(self, question: str, summary: Dict[str, Any]) -> str:
        """Fallback analysis when LLM is unavailable"""
        lines = []
        lines.append("Traffic Analysis Summary:")
        lines.append(f"- Total packets: {summary['total_packets']}")
        lines.append(f"- Total flows: {summary['total_flows']}")
        lines.append(f"- Total alerts: {summary['total_alerts']}")
        
        if summary['top_protocols']:
            lines.append("\nTop Protocols:")
            for proto, count in summary['top_protocols'].items():
                lines.append(f"  - {proto}: {count}")
        
        if summary['top_ips']:
            lines.append("\nTop IPs:")
            for ip, count in list(summary['top_ips'].items())[:5]:
                lines.append(f"  - {ip}: {count} packets")
        
        if summary['alert_types']:
            lines.append("\nAlert Types:")
            for alert_type, count in summary['alert_types'].items():
                lines.append(f"  - {alert_type}: {count}")
        
        lines.append(f"\nQuery: {question}")
        lines.append("\n(Note: AI analysis unavailable - Ollama may not be running or models not loaded)")
        lines.append("To enable AI features:")
        lines.append("  1. Ensure Ollama is running: 'ollama serve'")
        lines.append("  2. Pull required models: 'ollama pull llama3.1:8b'")
        
        return '\n'.join(lines)
    
    def explain_alert(self, alert) -> str:
        """Explain a specific alert"""
        if not self.llm.is_available():
            return f"{alert.rule_name}: {alert.message}"
        
        prompt = f"""Explain this security alert in simple terms:

Rule: {alert.rule_name}
Severity: {alert.severity}
Message: {alert.message}
Metadata: {alert.metadata}

Provide a brief explanation of what this means and what action should be taken.

Explanation:"""
        
        response = self.llm.query(prompt, model_type='explainer', temperature=0.5)
        
        if response:
            return response
        else:
            return f"{alert.rule_name}: {alert.message}"