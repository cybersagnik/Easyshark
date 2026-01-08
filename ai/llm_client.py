"""
Unified LLM client for Ollama models
Routes prompts to appropriate models based on task
"""
import requests
import json
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

class LLMClient:
    def __init__(self, base_url: str = "http://localhost:11434"):
        self.base_url = base_url
        self.models = {
            'planner': 'gemma3:1b',  # Fast, lightweight model
            'explainer': 'gemma3:1b',  # Fast responses
            'coder': 'qwen2.5-coder:7b'
        }
        self.timeout = 45  # Reasonable timeout
    
    def query(self, prompt: str, model_type: str = 'planner', temperature: float = 0.7) -> Optional[str]:
        """Query LLM with prompt"""
        model_name = self.models.get(model_type, self.models['planner'])
        
        try:
            logger.debug(f"Querying {model_name} (timeout: {self.timeout}s)...")
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    'model': model_name,
                    'prompt': prompt,
                    'stream': False,
                    'options': {
                        'temperature': temperature,
                        'num_predict': 300  # Limit for faster responses
                    }
                },
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                response_text = result.get('response', '').strip()
                logger.debug(f"Received response ({len(response_text)} chars)")
                return response_text
            else:
                logger.error(f"LLM request failed: {response.status_code}")
                return None
                
        except requests.exceptions.Timeout:
            logger.warning(f"LLM request timed out after {self.timeout}s (model: {model_name})")
            return None
        except requests.exceptions.ConnectionError:
            logger.error(f"Cannot connect to Ollama at {self.base_url}. Is Ollama running?")
            return None
        except Exception as e:
            logger.error(f"LLM error: {e}")
            return None
    
    def query_planner(self, user_input: str, context: Dict[str, Any]) -> Optional[str]:
        """Query planning model (llama3.1:8b)"""
        prompt = f"""You are a network security analyst. Parse this user query and extract the intent.

User Query: {user_input}

Context:
- Total packets: {context.get('packet_count', 0)}
- Protocols: {', '.join(context.get('protocols', []))}
- Alerts: {context.get('alert_count', 0)}

Respond with ONLY the action to take, one of:
- filter: <type> <value>
- search: <field> <value>
- show: <index>
- stats
- analyze: <detailed question>

Response:"""
        
        return self.query(prompt, model_type='planner', temperature=0.3)
    
    def query_explainer(self, question: str, data: Dict[str, Any]) -> Optional[str]:
        """Query explanation model (gemma3:1b)"""
        
        prompt = f"""As a SOC analyst, briefly analyze this network traffic:

Traffic: {data.get('total_packets', 0)} packets, {data.get('total_flows', 0)} flows, {data.get('total_alerts', 0)} alerts
Alerts: {', '.join([f"{k}({v})" for k, v in data.get('alert_types', {}).items()]) if data.get('alert_types') else 'none'}
Top IPs: {', '.join([k for k in list(data.get('top_ips', {}).keys())[:2]])}

Question: {question}

Answer in 2-3 sentences:"""
        
        return self.query(prompt, model_type='explainer', temperature=0.5)
    
    def query_coder(self, task: str, context: str) -> Optional[str]:
        """Query code generation model (qwen2.5-coder:7b)"""
        prompt = f"""Generate a detection rule or code snippet for this task.

Task: {task}

Context: {context}

Provide ONLY the code, no explanations.

Code:"""
        
        return self.query(prompt, model_type='coder', temperature=0.2)
    
    def is_available(self) -> bool:
        """Check if Ollama is available"""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            return response.status_code == 200
        except:
            return False