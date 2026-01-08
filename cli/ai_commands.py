"""
AI-powered command handlers
"""
import logging
from ai.llm_client import LLMClient
from ai.explainer import TrafficExplainer
from ai.rule_generator import RuleGenerator

logger = logging.getLogger(__name__)

class AICommandHandler:
    def __init__(self, shell, llm_client: LLMClient):
        self.shell = shell
        self.llm = llm_client
        self.explainer = TrafficExplainer(llm_client) if llm_client else None
        self.rule_gen = RuleGenerator(llm_client) if llm_client else None
    
    def analyze_traffic(self, query: str):
        """Analyze traffic using AI"""
        if not query:
            print("Usage: analyze <query>")
            print("Example: analyze What suspicious DNS queries are present?")
            return
        
        if not self.llm or not self.llm.is_available():
            print("AI features not available (Ollama not running or not reachable)")
            print("Check: http://localhost:11434/api/tags")
            return
        
        if not self.explainer:
            print("AI explainer not initialized")
            return
        
        print(f"\nAnalyzing: {query}")
        print("Querying AI model (this may take 10-30 seconds)...\\n")
        
        packets = self.shell.get_packets()
        flows = self.shell.flow_engine.get_all_flows()
        alerts = []
        for rule in self.shell.rules:
            alerts.extend(rule.get_alerts())
        
        try:
            response = self.explainer.explain_traffic(query, packets, flows, alerts)
            print(response)
        except Exception as e:
            logger.error(f"AI analysis error: {e}", exc_info=True)
            print(f"Error during analysis: {e}")
            print("\\nTip: Run with --debug flag to see detailed logs")
    
    def explain_alert(self, alert):
        """Explain a specific alert using AI"""
        if not self.explainer:
            return str(alert)
        
        try:
            return self.explainer.explain_alert(alert)
        except Exception as e:
            logger.error(f"Alert explanation error: {e}")
            return str(alert)
    
    def generate_rule(self, description: str):
        """Generate detection rule from description"""
        if not self.rule_gen:
            print("AI features not available (Ollama not running)")
            return
        
        print(f"\nGenerating rule for: {description}\n")
        
        try:
            rule = self.rule_gen.generate_snort_rule(description)
            if rule:
                print("Generated Snort Rule:")
                print(rule)
            else:
                print("Failed to generate rule")
        except Exception as e:
            logger.error(f"Rule generation error: {e}")
            print(f"Error generating rule: {e}")