"""
AI-powered command planning and intent parsing
"""
from .llm_client import LLMClient
from typing import Dict, Any, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

class CommandPlanner:
    def __init__(self, llm_client: LLMClient):
        self.llm = llm_client
    
    def parse_natural_language(self, user_input: str, context: Dict[str, Any]) -> Optional[Tuple[str, list]]:
        """Parse natural language into command and arguments"""
        user_input_lower = user_input.lower().strip()
        
        simple_patterns = {
            'stats': (['stats'], []),
            'help': (['help'], []),
            'exit': (['exit'], []),
            'quit': (['quit'], [])
        }
        
        for pattern, (cmd, args) in simple_patterns.items():
            if user_input_lower == pattern:
                return (cmd[0], args)
        
        if user_input_lower.startswith('show '):
            parts = user_input.split()
            if len(parts) == 2:
                try:
                    idx = int(parts[1])
                    return ('show', [str(idx)])
                except ValueError:
                    pass
        
        if user_input_lower.startswith('filter '):
            parts = user_input.split(maxsplit=2)
            if len(parts) == 3:
                return ('filter', [parts[1], parts[2]])
        
        if user_input_lower.startswith('search '):
            parts = user_input.split(maxsplit=2)
            if len(parts) == 3:
                return ('search', [parts[1], parts[2]])
        
        if user_input_lower.startswith('analyze '):
            query = user_input[8:].strip()
            return ('analyze', [query])
        
        if not self.llm.is_available():
            return ('analyze', [user_input])
        
        response = self.llm.query_planner(user_input, context)
        
        if response:
            return self._parse_llm_response(response, user_input)
        
        return ('analyze', [user_input])
    
    def _parse_llm_response(self, response: str, original_input: str) -> Tuple[str, list]:
        """Parse LLM response into command and args"""
        response = response.strip().lower()
        
        if response.startswith('filter:'):
            parts = response[7:].strip().split(maxsplit=1)
            if len(parts) == 2:
                return ('filter', parts)
        
        elif response.startswith('search:'):
            parts = response[7:].strip().split(maxsplit=1)
            if len(parts) == 2:
                return ('search', parts)
        
        elif response.startswith('show:'):
            idx = response[5:].strip()
            return ('show', [idx])
        
        elif response.startswith('stats'):
            return ('stats', [])
        
        elif response.startswith('analyze:'):
            query = response[8:].strip() or original_input
            return ('analyze', [query])
        
        return ('analyze', [original_input])