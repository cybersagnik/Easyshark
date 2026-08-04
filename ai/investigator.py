"""
investigator.py — Agentic hypothesis-verify-conclude loop (CONTEXT.md §16, Task 2).

Three LLM calls per investigation:
    1. Hypothesis generation  — single completion, narrative -> ranked hypotheses
    2. Hypothesis verification — tool-calling loop (max 8 steps), gather evidence
    3. Final conclusion       — single completion, all verdicts -> incident JSON

The tool calls in (2) reuse the existing ai.llm_client.LLMClient.query_with_tools
infrastructure (11 forensic tools). The conclusion (3) reuses the same JSON
schema as ai.auto_analyst so the existing renderer in cli.report_commands can
format it without modification.

Public API:
    investigate(shell) -> InvestigationReport
    InvestigationReport dataclass with all intermediate state

Use --auto flag for non-interactive (scripted) runs.
"""
from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Prompts                                                                     #
# --------------------------------------------------------------------------- #
HYPOTHESIS_SYSTEM_PROMPT = """You are a senior SOC analyst. You will be given a structured summary of a
packet capture produced by deterministic anomaly detectors.

Generate up to 3 hypotheses about what happened in this capture. For each:
- name: short label (e.g. "DNS C2 tunneling", "Credential theft via SMTP")
- description: 2 sentences explaining the hypothesis
- confidence: high | medium | low
- supporting_evidence: list of 2-3 specific items from the summary that support it
- verification_plan: list of 2-3 specific tool calls or checks that would confirm or rule it out

Order by confidence descending. Only generate hypotheses the evidence supports.
If the capture looks benign, say so with one hypothesis: {name: "Benign traffic", confidence: "high"}.

Respond ONLY with a JSON array. No preamble. No markdown fences."""

VERIFICATION_SYSTEM_PROMPT = """You are verifying a specific hypothesis about network traffic.

Hypothesis: {hypothesis_name}
Description: {hypothesis_description}
Verification plan: {verification_plan}

Use the available tools to gather evidence that confirms or rules out this
hypothesis. Be systematic — follow the verification plan. After gathering
evidence, return a JSON object:
{{
  "verdict": "confirmed" | "weakened" | "ruled_out",
  "evidence_found": ["specific finding 1", "specific finding 2"],
  "confidence_after": "high" | "medium" | "low",
  "reasoning": "2-3 sentences explaining the verdict"
}}

Do not guess. If tools return no relevant data, verdict is "ruled_out"."""

CONCLUSION_SYSTEM_PROMPT = """You are a senior SOC analyst. You investigated a packet capture by
generating hypotheses, verifying each one with available tools, and collecting
verdicts. You will be given the original capture summary plus the verified
hypotheses.

Produce a final incident report. Output JSON only:
{
  "incident_narrative": "3-5 sentence narrative",
  "suspect_hosts": [
    {"ip": "x.x.x.x", "confidence": "high|medium|low",
     "evidence": ["item1", "item2"],
     "likely_role": "human-readable role"}
  ],
  "mitre_techniques": [
    {"technique": "Technique Name", "id": "TXXXX", "evidence": "..."}
  ],
  "iocs": ["indicator1", "indicator2"],
  "next_steps": ["step1", "step2", "step3"],
  "confidence_overall": "high|medium|low",
  "analyst_summary": "One-sentence ticket-title verdict"
}

Rules:
- Every claim must cite specific evidence from the summary or verification results.
- Use exact values from the capture (IPs, hashes, domains).
- If no verified hypotheses produced evidence, say so — do not manufacture incidents.
- Prefer "likely"/"possible" when confidence < 0.8, "confirmed" only when evidence is unambiguous.

Wrap in ```json ... ``` fences. No prose outside the JSON."""


# --------------------------------------------------------------------------- #
# JSON extraction helpers                                                     #
# --------------------------------------------------------------------------- #
_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\[.*?\]|\{.*?\})\s*```", re.DOTALL)


def _extract_json_obj(text: str) -> Optional[Dict[str, Any]]:
    if not text:
        return None
    m = _JSON_FENCE_RE.search(text)
    if m:
        try:
            obj = json.loads(m.group(1))
            if isinstance(obj, dict):
                return obj
        except Exception:
            pass
    # Fall back to first balanced object.
    start = text.find("{")
    while start != -1:
        depth = 0
        for end in range(start, len(text)):
            ch = text[end]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(text[start:end + 1])
                        if isinstance(obj, dict):
                            return obj
                    except Exception:
                        pass
                    break
        start = text.find("{", start + 1)
    return None


def _extract_json_array(text: str) -> Optional[List[Any]]:
    if not text:
        return None
    m = _JSON_FENCE_RE.search(text)
    if m:
        try:
            obj = json.loads(m.group(1))
            if isinstance(obj, list):
                return obj
        except Exception:
            pass
    start = text.find("[")
    while start != -1:
        depth = 0
        for end in range(start, len(text)):
            ch = text[end]
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(text[start:end + 1])
                        if isinstance(obj, list):
                            return obj
                    except Exception:
                        pass
                    break
        start = text.find("[", start + 1)
    return None


# --------------------------------------------------------------------------- #
# InvestigationReport dataclass                                              #
# --------------------------------------------------------------------------- #
@dataclass
class Hypothesis:
    name:               str
    description:        str = ""
    confidence:         str = "low"   # high | medium | low
    supporting_evidence:List[str] = field(default_factory=list)
    verification_plan:  List[str] = field(default_factory=list)
    # Populated after verification:
    verdict:            Optional[str] = None   # confirmed | weakened | ruled_out
    evidence_found:     List[str]     = field(default_factory=list)
    confidence_after:   Optional[str] = None
    reasoning:          str           = ""


@dataclass
class InvestigationReport:
    narrative:    str = ""
    hypotheses:   List[Hypothesis]   = field(default_factory=list)
    conclusion:   Dict[str, Any]     = field(default_factory=dict)
    elapsed_sec:  float              = 0.0
    llm_calls:    int                = 0

    def confirmed(self) -> List[Hypothesis]:
        return [h for h in self.hypotheses if h.verdict == "confirmed"]

    def weakened(self) -> List[Hypothesis]:
        return [h for h in self.hypotheses if h.verdict == "weakened"]

    def ruled_out(self) -> List[Hypothesis]:
        return [h for h in self.hypotheses if h.verdict == "ruled_out"]


# --------------------------------------------------------------------------- #
# LLM call helpers                                                            #
# --------------------------------------------------------------------------- #
def _single_completion(llm_client, system: str, user: str,
                       model_type: str = "explainer",
                       temperature: float = 0.2,
                       max_tokens: int = 1500,
                       timeout_sec: int = 600) -> Optional[str]:
    """Send one-shot completion. Raises RuntimeError on backend failure."""
    if llm_client is None or not getattr(llm_client, "is_available", lambda: False)():
        return None
    saved = getattr(llm_client, "ollama_timeout", None)
    try:
        if saved is not None:
            llm_client.ollama_timeout = max(saved, timeout_sec)
        response = llm_client._call_messages(
            messages=[{"role": "system", "content": system},
                      {"role": "user",   "content": user}],
            model_type=model_type,
            temperature=temperature,
            max_tokens=max_tokens,
        )
    finally:
        if saved is not None:
            llm_client.ollama_timeout = saved
    if response is None:
        return None
    try:
        return (response.choices[0].message.content or "").strip()
    except Exception:
        return None


def _make_fallback_hypotheses(anomalies) -> List[Hypothesis]:
    """Build one trivial hypothesis from the top anomaly (no LLM)."""
    if not anomalies:
        return [Hypothesis(
            name="Benign traffic",
            description="No anomalies detected by the deterministic pipeline.",
            confidence="high",
        )]
    a = max(anomalies, key=lambda x: x.score)
    return [Hypothesis(
        name=a.type.replace("_", " ").title(),
        description=a.evidence,
        confidence="medium" if a.score < 0.5 else "high",
        supporting_evidence=[a.evidence],
        verification_plan=[f"Inspect packets matching the {a.type} detector."],
    )]


# --------------------------------------------------------------------------- #
# Main entry point                                                            #
# --------------------------------------------------------------------------- #
def investigate(shell, on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> InvestigationReport:
    """Run the full hypothesis-verify-conclude loop.

    Args:
        shell: InteractiveShell instance (provides packets, flows, llm_client).
        on_event: optional callback invoked with (event_name, payload_dict)
            at each phase. Useful for the CLI to print progress without
            blocking on the analyst prompts.

    Returns:
        InvestigationReport with all intermediate state and the final
        conclusion dict.
    """
    report = InvestigationReport()
    t_start = time.monotonic()

    # ------------------------------------------------------------------ #
    # Step 1 — Build narrative + anomaly list (deterministic).           #
    # ------------------------------------------------------------------ #
    from core.detectors import run_all
    from core.narrative import build
    from ai.tool_registry import ToolContext

    packets = shell.get_packets()
    flows = shell.flow_engine.get_all_flows()
    alerts = []
    for r in shell.rules:
        alerts.extend(r.get_alerts())
    anomalies = run_all(packets, flows)
    narrative = build(packets, flows, alerts, anomalies)
    report.narrative = narrative
    report.llm_calls += 1  # call 1 is the hypothesis generation, counted below

    if on_event:
        on_event("narrative_ready", {
            "narrative_chars": len(narrative),
            "anomaly_count":   len(anomalies),
        })

    # ------------------------------------------------------------------ #
    # Step 2 — Hypothesis generation (LLM call 1).                        #
    # ------------------------------------------------------------------ #
    llm = getattr(shell, "llm_client", None)
    raw = _single_completion(
        llm, HYPOTHESIS_SYSTEM_PROMPT, narrative, max_tokens=1500,
    )
    if raw:
        parsed = _extract_json_array(raw) or []
        for item in parsed[:3]:
            if not isinstance(item, dict):
                continue
            report.hypotheses.append(Hypothesis(
                name=str(item.get("name", "?"))[:80],
                description=str(item.get("description", ""))[:500],
                confidence=str(item.get("confidence", "low")).lower(),
                supporting_evidence=[str(x)[:200] for x in (item.get("supporting_evidence") or [])][:5],
                verification_plan=[str(x)[:200] for x in (item.get("verification_plan") or [])][:5],
            ))

    if not report.hypotheses:
        # Fallback: derive from top anomaly (no LLM needed).
        report.hypotheses = _make_fallback_hypotheses(anomalies)

    if on_event:
        on_event("hypotheses_ready", {
            "count":  len(report.hypotheses),
            "names":  [h.name for h in report.hypotheses],
        })

    # ------------------------------------------------------------------ #
    # Step 3+4 — Verify each hypothesis with tool-calling loop (LLM 2).   #
    # ------------------------------------------------------------------ #
    ctx = ToolContext(packets=packets, flows=flows, alerts=alerts,
                      stats_engine=getattr(shell, "stats_engine", None),
                      flow_engine=getattr(shell, "flow_engine", None),
                      pcap_path=getattr(shell, "pcap_file", None))

    for h in report.hypotheses:
        if on_event:
            on_event("hypothesis_start", {
                "index":       report.hypotheses.index(h) + 1,
                "total":       len(report.hypotheses),
                "name":        h.name,
                "description": h.description,
                "confidence":  h.confidence,
                "supporting_evidence": h.supporting_evidence,
                "verification_plan":   h.verification_plan,
            })

        sys_prompt = VERIFICATION_SYSTEM_PROMPT.format(
            hypothesis_name=h.name,
            hypothesis_description=h.description,
            verification_plan=h.verification_plan,
        )
        user_prompt = (f"Verify this hypothesis using the available tools.\n"
                       f"Hypothesis: {h.description}")
        result_text = None
        if llm is not None:
            try:
                result_text = llm.query_with_tools(
                    question=user_prompt,
                    context=ctx,
                    model_type="explainer",
                    max_steps=8,
                    max_tokens=800,
                    temperature=0.2,
                )
            except Exception as exc:
                logger.warning("verification LLM failed: %s", exc)
                result_text = None
            report.llm_calls += 1

        if result_text:
            parsed = _extract_json_obj(result_text) or {}
            h.verdict = str(parsed.get("verdict", "ruled_out")).lower()
            h.evidence_found = [str(x)[:200] for x in (parsed.get("evidence_found") or [])][:5]
            h.confidence_after = str(parsed.get("confidence_after", "low")).lower()
            h.reasoning = str(parsed.get("reasoning", ""))[:500]
        else:
            # No LLM available: trust the narrative evidence, mark as
            # "weakened" so the analyst sees something rather than nothing.
            h.verdict = "weakened"
            h.confidence_after = h.confidence
            h.reasoning = "(verification skipped — LLM unavailable)"

        if on_event:
            on_event("hypothesis_verdict", {
                "name":             h.name,
                "verdict":          h.verdict,
                "confidence_after": h.confidence_after,
                "evidence_found":   h.evidence_found,
                "reasoning":        h.reasoning,
            })

    # ------------------------------------------------------------------ #
    # Step 5 — Final conclusion (LLM call 3).                            #
    # ------------------------------------------------------------------ #
    verdicts_text = "\n".join(
        f"- [{h.verdict or 'pending'}] {h.name} "
        f"(confidence: {h.confidence_after or h.confidence})\n"
        f"    Evidence: {'; '.join(h.evidence_found) if h.evidence_found else '(none)'}\n"
        f"    Reasoning: {h.reasoning}"
        for h in report.hypotheses
    )
    conclusion_user = (
        f"=== ORIGINAL CAPTURE SUMMARY ===\n{narrative}\n\n"
        f"=== VERIFIED HYPOTHESES ===\n{verdicts_text}\n\n"
        f"Produce the final incident report."
    )
    raw = _single_completion(
        llm, CONCLUSION_SYSTEM_PROMPT, conclusion_user, max_tokens=1500,
    )
    if raw:
        parsed = _extract_json_obj(raw)
        if parsed:
            report.conclusion = parsed
    report.llm_calls += 1

    if not report.conclusion:
        # Fallback: assemble from hypotheses + narrative directly.
        report.conclusion = _fallback_conclusion(report)

    if on_event:
        on_event("conclusion_ready", {
            "iocs":          report.conclusion.get("iocs") or [],
            "confidence":    report.conclusion.get("confidence_overall"),
            "mitre_count":   len(report.conclusion.get("mitre_techniques") or []),
        })

    report.elapsed_sec = time.monotonic() - t_start
    return report


# --------------------------------------------------------------------------- #
# Fallback conclusion — used when the LLM call 3 fails to parse.              #
# --------------------------------------------------------------------------- #
def _fallback_conclusion(report: InvestigationReport) -> Dict[str, Any]:
    confirmed = report.confirmed()
    if not confirmed:
        return {
            "incident_narrative": "No confirmed anomalies in this capture.",
            "suspect_hosts":      [],
            "mitre_techniques":   [],
            "iocs":               [],
            "next_steps":         ["Review `anomalies` for details."],
            "confidence_overall": "low",
            "analyst_summary":    "Benign or inconclusive capture.",
        }
    primary = confirmed[0]
    return {
        "incident_narrative": primary.description or primary.name,
        "suspect_hosts":      [],
        "mitre_techniques":   [],
        "iocs":               [],
        "next_steps":         ["Review the verified hypothesis for next steps."],
        "confidence_overall": primary.confidence_after or primary.confidence,
        "analyst_summary":    f"{primary.name} ({primary.confidence_after or primary.confidence} confidence).",
    }
