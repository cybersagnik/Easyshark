"""
critic.py — Phase 9 §9.3 evidence critic for the multi-agent DAG.

A single-pass auditor. Given one executor verdict plus the raw tool
transcript it was based on, the critic:

  1. checks that every concrete claim (IP, port, hash, username,
     filename, count) is grounded in the tool output,
  2. checks the numeric confidence (0.0-1.0) is consistent with the
     strength of the evidence,
  3. returns {approved, corrected_verdict, issues}.

If not approved, the DAG runner retries the executor once with the
issues fed back. Max 1 retry per hypothesis (no infinite loop).

All LLM calls go through LLMClient (Zen → OpenRouter → Groq with the
Phase 9 rate limiter). Uses the "critic" role = OPENROUTER_CRITIC_MODEL.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


CRITIC_SYSTEM_PROMPT = """You are a rigorous evidence critic in a SOC. An executor agent verified a
hypothesis against a packet capture using forensic tools. You must audit
its verdict.

Audit checklist:
1. Grounding — every concrete claim in the verdict (IPs, ports, MD5
   hashes, usernames, filenames, counts) must appear in the raw tool
   output below. Flag any claim that is NOT present.
2. Confidence — is the numeric confidence (0.0-1.0) consistent with the
   quantity and specificity of the evidence?
3. Verdict fit — does "confirmed" / "weakened" / "ruled_out" match the
   evidence? "confirmed" requires specific tool evidence; absent
   evidence means "ruled_out" or at most "weakened".

Return ONLY a JSON object, no prose, no markdown fences:
{
  "approved": true|false,
  "corrected_verdict": "short corrected summary or null",
  "issues": ["short issue 1", "short issue 2"]
}

- approved=true only when every claim is grounded AND the confidence fits.
- For small problems set corrected_verdict; for severe problems set
  approved=false with issues.
- Never invent evidence that is not in the tool output."""


class Critic:
    """Audits one executor verdict against its raw tool transcript."""

    def __init__(self, llm_client: Optional[Any] = None):
        self.llm = llm_client

    # ------------------------------------------------------------------ #
    # Public entry                                                        #
    # ------------------------------------------------------------------ #
    def review(self,
               hypothesis: str,
               verdict: Dict[str, Any],
               tool_outputs: List[Dict[str, Any]],
               max_tools_shown: int = 6) -> Dict[str, Any]:
        """Return {approved, corrected_verdict, issues}.

        If the LLM is unavailable or the response is unparseable, this
        returns {"approved": False, "corrected_verdict": None,
        "issues": ["critic unavailable"]} so the executor is NOT silently
        trusted — the DAG runner records the concern and moves on.
        """
        if self.llm is None or not getattr(self.llm, "is_available", lambda: False)():
            return {"approved": False, "corrected_verdict": None,
                    "issues": ["critic unavailable — verdict unverified"]}

        user = self._build_prompt(hypothesis, verdict, tool_outputs, max_tools_shown)
        from ai.investigator import _single_completion, _extract_json_obj
        # Phase 14 TASK 2 — compact prompt; base keeps the JSON schema.
        system = CRITIC_SYSTEM_PROMPT
        try:
            from ai.prompt_optimizer import build_system_prompt, top_patterns
            system = build_system_prompt(
                "critic", patterns=top_patterns(2), base=CRITIC_SYSTEM_PROMPT)
        except Exception as exc:
            logger.debug("prompt_optimizer critic failed: %s", exc)
        raw = _single_completion(
            self.llm, system, user,
            model_type="critic", temperature=0.1, max_tokens=2000,
        )
        if not raw:
            return {"approved": False, "corrected_verdict": None,
                    "issues": ["critic returned empty response"]}
        parsed = _extract_json_obj(raw)
        if not parsed:
            logger.warning("Critic: unparseable response: %.200s", raw)
            return {"approved": False, "corrected_verdict": None,
                    "issues": ["critic response was not valid JSON"]}

        approved = bool(parsed.get("approved", False))
        corrected = parsed.get("corrected_verdict")
        if corrected is not None:
            corrected = str(corrected)[:500] or None
        issues = [str(i)[:200] for i in (parsed.get("issues") or [])][:8]
        return {
            "approved": approved,
            "corrected_verdict": corrected,
            "issues": issues,
        }

    # ------------------------------------------------------------------ #
    # Prompt building                                                     #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _build_prompt(hypothesis: str,
                      verdict: Dict[str, Any],
                      tool_outputs: List[Dict[str, Any]],
                      max_tools_shown: int) -> str:
        verdict_text = json.dumps(verdict, indent=2, default=str)
        tool_lines = []
        for entry in tool_outputs[:max_tools_shown]:
            name = entry.get("tool", "?")
            args = entry.get("args", {})
            result = entry.get("result", "")
            result_str = (result if isinstance(result, str)
                          else json.dumps(result, default=str))
            if len(result_str) > 1500:
                result_str = result_str[:1500] + "... [truncated]"
            tool_lines.append(f"TOOL {name}({json.dumps(args, default=str)[:300]})")
            tool_lines.append(f"  -> {result_str}")
        if not tool_lines:
            tool_lines.append("  (no tool calls were made)")

        return (
            f"HYPOTHESIS: {hypothesis}\n\n"
            f"EXECUTOR VERDICT:\n{verdict_text}\n\n"
            f"RAW TOOL OUTPUT:\n" + "\n".join(tool_lines) + "\n\n"
            "Audit the verdict against the raw tool output. Reply with the JSON object."
        )
