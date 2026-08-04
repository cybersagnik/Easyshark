"""Phase 14 TASK 2 — token-optimized system prompts.

Builds compact role prompts that inject only what a single call needs:

  - up to 3 relevant tool names (from usage patterns)
  - up to 3 capture-type facts (from triage)
  - up to 2 top usage patterns (from pattern_learner.read_patterns(2))

and enforces a token budget (default 500 tokens; target ~420).

The base prompt is the role's stock prompt from config.settings with its
"TOOLS YOU CAN CALL" bullet list removed (the names are re-injected, so
the duplication is dropped). Callers with schema-critical prompts
(critic JSON, executor verdict JSON) pass them via ``base=`` so the
schema text is preserved and only triage/pattern hints are appended.

Token estimation: ``len(text.split()) * 1.3`` — a cheap, deliberately
conservative proxy (no tiktoken dependency on the CPU-only box).
"""
import re
from typing import Any, Dict, List, Optional

from config.settings import OLLAMA_SYSTEM_PROMPTS

__all__ = ["estimate_tokens", "build_system_prompt", "top_patterns"]

# Words-per-token inflation factor. >1 keeps us under budget in practice.
TOKEN_EST_FACTOR = 1.3

_TOOL_LIST_RE = re.compile(
    r"TOOLS YOU CAN CALL.*?(?=\n\s*\n|RULES|TYPICAL)", re.DOTALL)
_EXTRA_BLANK = re.compile(r"\n{3,}")


def estimate_tokens(text: str) -> int:
    """Rough token estimate: words * 1.3 (safe over-estimate)."""
    return int(len(text.split()) * TOKEN_EST_FACTOR)


def _compress_base(base: str) -> str:
    """Drop the stock prompt's tool-name bullet list (names are injected
    fresh below), normalise run-on blank lines."""
    if not base:
        return ""
    out = _TOOL_LIST_RE.sub("", base)
    out = _EXTRA_BLANK.sub("\n\n", out)
    return out.strip()


def _pattern_lines(patterns) -> List[str]:
    """Turn 1-2 pattern dicts into one short line each.

    Accepts a dict (single pattern) or a list of dicts. Recognises the
    pattern_learner schema (question_keywords / tool_sequence /
    success_rate) and the generic schema (tools_used / description).
    """
    rows: List[Any] = []
    if isinstance(patterns, dict):
        rows = [patterns]
    else:
        rows = list(patterns or [])[:2]

    lines: List[str] = []
    tools_seen: List[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        seq = row.get("tool_sequence") or row.get("tools_used") or []
        seq = [str(t) for t in seq if t] if isinstance(seq, (list, tuple)) else []
        kws = row.get("question_keywords") or []
        kws = [str(k) for k in kws] if isinstance(kws, (list, tuple)) else []
        if not seq:
            continue
        rate = row.get("success_rate")
        rate_s = f" ({float(rate) * 100:.0f}% success)" if isinstance(rate, (int, float)) else ""
        if kws:
            kw_s = ", ".join(kws[:3])
            lines.append(f"'{kw_s}' -> {', '.join(seq[:3])}{rate_s}")
        else:
            lines.append(f"prefer {', '.join(seq[:3])}{rate_s}")
        for t in seq:
            if t not in tools_seen:
                tools_seen.append(t)
    return lines[:2], tools_seen[:3]


def _triage_facts(triage: Optional[Dict[str, bool]]) -> List[str]:
    """Up to 3 one-line capture-type facts from the triage dict."""
    if not triage:
        return []
    label = {
        "smtp": "SMTP mail (AUTH/DATA)",
        "im": "IM/chat traffic",
        "http": "HTTP",
        "tls": "TLS",
        "dns_tunneling_suspect": "possible DNS tunneling",
        "ad_network": "an ad network is contacted",
        "docx_carved": "a .docx was carved",
        "encrypted_heavy": "mostly encrypted payloads",
    }
    facts = [label[k] for k in label if triage.get(k)]
    return facts[:3]


def top_patterns(limit: int = 2) -> List[Dict[str, Any]]:
    """Load the top usage patterns (empty list when the store is empty)."""
    try:
        from ai.pattern_learner import read_patterns
        return read_patterns(limit=limit)
    except Exception:
        return []


def build_system_prompt(role: str,
                        triage: Optional[Dict[str, bool]] = None,
                        patterns: Optional[Any] = None,
                        token_budget: int = 500,
                        base: Optional[str] = None) -> str:
    """Return a compact system prompt for ``role``.

    Args:
        role: 'planner' | 'explainer' | 'coder' | 'critic'.
        triage: triage_capabilities dict (3 capture facts injected).
        patterns: pattern_learner output (dict or list) — up to 2 usage
            lines + up to 3 tool names injected.
        token_budget: hard cap on the returned prompt (default 500).
        base: override the base prompt text (kept for schema-critical
            prompts like the critic / executor verdict JSON).
    """
    stock = OLLAMA_SYSTEM_PROMPTS.get(role, OLLAMA_SYSTEM_PROMPTS["explainer"])
    body = _compress_base(base or stock)

    pattern_lines: List[str] = []
    tools: List[str] = []
    if patterns:
        pattern_lines, tools = _pattern_lines(patterns)
    facts = _triage_facts(triage)

    def assemble(with_patterns: bool, with_tools: bool, with_facts: bool) -> str:
        parts: List[str] = [body]
        if with_tools and tools:
            parts.append("Tools to prefer: " + ", ".join(tools))
        if with_patterns and pattern_lines:
            parts.append("Known usage patterns:\n" + "\n".join(
                "- " + ln for ln in pattern_lines))
        if with_facts and facts:
            parts.append("Capture: " + " | ".join(facts))
        return "\n\n".join(parts)

    prompt = assemble(True, True, True)
    # Shrink under budget: drop patterns first, then tools, then facts.
    if estimate_tokens(prompt) > token_budget:
        prompt = assemble(False, True, True)
    if estimate_tokens(prompt) > token_budget:
        prompt = assemble(False, False, True)
    if estimate_tokens(prompt) > token_budget:
        prompt = assemble(False, False, False)
    return prompt
