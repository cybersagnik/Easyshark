"""
heuristic_qa.py — DECOMMISSIONED (Phase 15, 2026-08-04).

The deterministic regex fast-path was removed because regex intent matching
caused false positives and wrong answers on novel phrasings. The LLM tool
loop (Zen → OpenRouter → Groq) plus the premise-mismatch gate in
cli/ai_commands.py now answers all questions.

This file is retained as a stub so any lingering import (tmp/ scripts,
historical references) still works: try_answer() always returns None, which
the caller treats as "fall through to the LLM".
"""

from typing import Any, Dict, List, Optional


def try_answer(question: str,
               packets: List[Any],
               flows: List[Any],
               alerts: List[Any],
               triage: Optional[Dict[str, bool]] = None) -> Optional[str]:
    """Decommissioned — always returns None (delegate to the LLM).

    Signature preserved for backward compatibility with tmp/ scripts.
    """
    return None


__all__ = ["try_answer"]
