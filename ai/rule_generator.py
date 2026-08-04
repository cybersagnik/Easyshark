"""
RuleGenerator — emits Snort / YARA / Python detection rules from a
natural-language task description.

Strict single-shot prompt for the small Ollama coder model. The system
prompt in config.settings.OLLAMA_SYSTEM_PROMPTS['coder'] already pins
the output format.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from .llm_client import LLMClient

logger = logging.getLogger(__name__)


class RuleGenerator:
    def __init__(self, llm_client: Optional[LLMClient]):
        self.llm = llm_client

    def generate_snort_rule(self, description: str, context: str = "") -> Optional[str]:
        if not self.llm or not self.llm.is_available():
            return None
        task = f"Write one Snort rule for: {description}"
        full_context = f"Detection context:\n{context}" if context else ""
        return self.llm.query_coder(task, full_context)

    def generate_yara_rule(self, description: str, context: str = "") -> Optional[str]:
        if not self.llm or not self.llm.is_available():
            return None
        task = f"Write one YARA rule for: {description}"
        full_context = f"Sample context:\n{context}" if context else ""
        return self.llm.query_coder(task, full_context)

    def generate_python_detector(self,
                                 description: str,
                                 context: str = "") -> Optional[str]:
        if not self.llm or not self.llm.is_available():
            return None
        task = f"Write one Python detection function for: {description}"
        full_context = f"Code context:\n{context}" if context else ""
        return self.llm.query_coder(task, full_context)
