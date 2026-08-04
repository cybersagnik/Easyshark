"""
dag_runner.py — Phase 9 §9.2 executor DAG for the multi-agent investigate.

Replaces the linear for-each loop with a dependency-aware DAG:

  plan (HypothesisPlanner) -> topological waves -> per-hypothesis:
      executor tool loop (max 6 steps) -> verdict JSON
      critic (ai.critic.Critic)  -> approve / correct / issues
      if critic rejects -> executor retries ONCE with the feedback
      if confidence < 0.4 -> mark INCONCLUSIVE (does not block dependents)

Execution is strictly sequential (no threading — WSL2 RAM budget, and
≤5 hypotheses make it a non-issue). Every LLM call goes through
LLMClient so the OpenRouter→Ollama→Groq chain and the Phase 9 rate
limiter apply automatically.

Public API:
    DagRunner(shell).run(plan_items, ctx, on_event=None) -> DAGResult
"""
from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .critic import Critic

logger = logging.getLogger(__name__)

# Phase 10 §10.2 — cross-session memory hooks. Regexes used to extract
# IOC-like values from verdict evidence so approved verdicts feed the
# iocs / verdicts tables and prior-session knowledge is recalled.
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MD5_RE = re.compile(r"\b[0-9a-f]{32}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")

INCONCLUSIVE_CONFIDENCE = 0.4   # below this, a verdict is marked inconclusive
EXECUTOR_MAX_STEPS = 6          # tool round-trips per hypothesis
EXECUTOR_MAX_RETRIES = 1        # max re-runs after critic rejection


# --------------------------------------------------------------------------- #
# Phase 10 §10.2 — cross-session memory hooks.                                #
#                                                                             #
# Before the tool loop we recall IOCs for the IPs/domains present in this     #
# capture and inject them as "[prior session ...]" notes. After the critic    #
# approves a verdict we persist it (verdicts table) plus any IOC-like values  #
# found in the evidence (iocs table). Both hooks are best-effort and          #
# gated by EASYSHARK_MEMORY_ENABLED.                                          #
# --------------------------------------------------------------------------- #
def memory_enabled() -> bool:
    """EASYSHARK_MEMORY_ENABLED=0 disables the DAG memory hooks entirely."""
    return os.environ.get("EASYSHARK_MEMORY_ENABLED", "1") != "0"


def _pcap_hash_of(ctx) -> Optional[str]:
    pcap_path = getattr(ctx, "pcap_path", None)
    if not pcap_path:
        return None
    from core.memory import pcap_hash
    return pcap_hash(str(pcap_path))


def _recall_prior_iocs(ctx) -> List[str]:
    """Return "[prior session ...]" notes for IOCs seen in earlier runs.

    Candidates are the src/dst IPs of every flow plus any IP-looking
    metadata values in the alert list. Looked up against the iocs table;
    only rows with a recorded verdict produce a note.
    """
    if not memory_enabled():
        return []
    from core import memory
    candidates: set = set()
    for f in getattr(ctx, "flows", []) or []:
        for attr in ("src_ip", "dst_ip"):
            v = getattr(f, attr, None)
            if v:
                candidates.add(str(v))
    for a in getattr(ctx, "alerts", []) or []:
        md = getattr(a, "metadata", {}) or {}
        if isinstance(md, dict):
            for v in md.values():
                if isinstance(v, str) and _IPV4_RE.fullmatch(v.strip()):
                    candidates.add(v.strip())
    notes: List[str] = []
    for value in sorted(candidates):
        row = memory.recall_ioc(value)
        if row and row.get("verdict"):
            src = row.get("source_pcap") or "?"
            notes.append(f"[prior session: {value} — prior verdict "
                         f"'{row['verdict']}' from {src}]")
        if len(notes) >= 10:
            break
    return notes


def _persist_verdict(hyp: "DAGHypothesis", ctx) -> None:
    """Store an approved verdict and upsert any IOC-like values in its
    evidence / reasoning into the memory DB. Best-effort — never raises."""
    if not memory_enabled():
        return
    try:
        from core import memory
        ph = _pcap_hash_of(ctx) or ""
        src = os.path.basename(getattr(ctx, "pcap_path", None) or "")
        memory.store_verdict({
            "pcap_hash": ph,
            "hypothesis": hyp.hypothesis,
            "verdict": hyp.verdict,
            "confidence": hyp.confidence,
            "critic_approved": bool(hyp.critic_approved),
            "tools_used": hyp.tools_used,
        })
        blob = " ".join(hyp.evidence or []) + " " + (hyp.reasoning or "")
        for m in set(_IPV4_RE.findall(blob)):
            memory.upsert_ioc({"ip": m, "verdict": hyp.verdict,
                               "source_pcap": src})
        for m in set(_DOMAIN_RE.findall(blob)):
            memory.upsert_ioc({"domain": m, "verdict": hyp.verdict,
                               "source_pcap": src})
        for m in set(_MD5_RE.findall(blob)):
            memory.upsert_ioc({"md5": m, "verdict": hyp.verdict,
                               "source_pcap": src})
    except Exception as exc:
        logger.warning("dag memory persist failed: %s", exc)


EXECUTOR_SYSTEM_PROMPT = """You are verifying a specific hypothesis about network traffic in a packet
capture. Call the available forensic tools to gather real evidence. Be
systematic. After gathering evidence, return a single JSON object:

{
  "verdict": "confirmed" | "weakened" | "ruled_out",
  "evidence_found": ["specific finding 1", "specific finding 2"],
  "confidence": 0.0-1.0,
  "reasoning": "2-3 sentences explaining the verdict"
}

Rules:
- Every finding in evidence_found MUST come from an actual tool result —
  quote exact IPs, ports, hashes, usernames, filenames, and counts.
- confidence reflects how strongly the evidence supports the verdict:
  >=0.8 needs specific, unambiguous tool evidence; 0.4-0.8 for partial
  support; <0.4 for weak/ambiguous.
- If the tools return no relevant data, verdict is "ruled_out".
- Output ONLY the JSON object. No prose, no markdown fences."""


# --------------------------------------------------------------------------- #
# Data structures                                                              #
# --------------------------------------------------------------------------- #
@dataclass
class DAGHypothesis:
    id: str
    hypothesis: str
    depends_on: List[str] = field(default_factory=list)
    tools_hint: List[str] = field(default_factory=list)
    priority: int = 2
    # Results populated by the runner:
    verdict: str = "pending"                 # confirmed|weakened|ruled_out|inconclusive
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    reasoning: str = ""
    tools_used: List[str] = field(default_factory=list)
    critic_approved: Optional[bool] = None
    critic_issues: List[str] = field(default_factory=list)
    retries: int = 0

    def short_label(self) -> str:
        return f"{self.id}: {self.hypothesis[:48]}"


@dataclass
class DAGResult:
    hypotheses: List[DAGHypothesis] = field(default_factory=list)
    executor_calls: int = 0
    critic_calls: int = 0
    elapsed_sec: float = 0.0

    @property
    def llm_calls(self) -> int:
        return self.executor_calls + self.critic_calls

    def by_id(self) -> Dict[str, DAGHypothesis]:
        return {h.id: h for h in self.hypotheses}


# --------------------------------------------------------------------------- #
# Topological ordering                                                        #
# --------------------------------------------------------------------------- #
def _execution_waves(hypotheses: List[DAGHypothesis]) -> List[List[DAGHypothesis]]:
    """Split hypotheses into waves where every wave's dependencies have
    already been run. Cycles are broken by priority order (defensive)."""
    by_id = {h.id: h for h in hypotheses}
    remaining = {h.id: set(h.depends_on) & set(by_id) for h in hypotheses}
    waves: List[List[DAGHypothesis]] = []
    done: set = set()
    while remaining:
        ready = sorted(
            (h for h in hypotheses if h.id in remaining and remaining[h.id] <= done),
            key=lambda h: h.priority,
        )
        if not ready:
            # Cycle / dangling dependency — run the leftovers in priority order.
            ready = sorted(
                (h for h in hypotheses if h.id in remaining),
                key=lambda h: h.priority,
            )
        waves.append(ready)
        for h in ready:
            done.add(h.id)
            del remaining[h.id]
    return waves


# --------------------------------------------------------------------------- #
# Verdict parsing                                                             #
# --------------------------------------------------------------------------- #
def _parse_verdict(text: Optional[str]) -> Optional[Dict[str, Any]]:
    if not text:
        return None
    from ai.investigator import _extract_json_obj
    parsed = _extract_json_obj(text)
    if not parsed:
        return None
    verdict = str(parsed.get("verdict", "ruled_out")).lower()
    if verdict not in ("confirmed", "weakened", "ruled_out"):
        verdict = "ruled_out"
    try:
        confidence = float(parsed.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5
    confidence = max(0.0, min(1.0, confidence))
    return {
        "verdict": verdict,
        "evidence_found": [str(x)[:200] for x in (parsed.get("evidence_found") or [])][:5],
        "confidence": confidence,
        "reasoning": str(parsed.get("reasoning", ""))[:500],
    }


# --------------------------------------------------------------------------- #
# Runner                                                                      #
# --------------------------------------------------------------------------- #
class DagRunner:
    """Executes a hypothesis DAG: topo order -> executor -> critic -> retry."""

    def __init__(self, llm_client: Optional[Any] = None,
                 critic: Optional[Critic] = None):
        self.llm = llm_client
        self.critic = critic or Critic(llm_client)

    # ------------------------------------------------------------------ #
    # Public entry                                                        #
    # ------------------------------------------------------------------ #
    def run(self,
            plan_items: List[Dict[str, Any]],
            ctx,
            on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None,
            ) -> DAGResult:
        """Execute the plan against a ToolContext.

        Args:
            plan_items: validated hypothesis dicts from HypothesisPlanner.
            ctx: ai.tool_registry.ToolContext.
            on_event: (event_name, payload) callback for progress printing.
        """
        t_start = time.monotonic()
        hypotheses = [self._to_hypothesis(item) for item in plan_items]
        waves = _execution_waves(hypotheses)

        # Phase 10 §10.2 — recall prior-session knowledge once, before any
        # tool loop runs. The notes are injected into each executor prompt.
        prior_notes = _recall_prior_iocs(ctx)
        if on_event and prior_notes:
            on_event("prior_knowledge", {"notes": prior_notes})

        if on_event:
            on_event("dag_plan", {
                "count": len(hypotheses),
                "hypotheses": [
                    {"id": h.id, "name": h.hypothesis, "depends_on": h.depends_on,
                     "tools_hint": h.tools_hint, "priority": h.priority}
                    for h in hypotheses
                ],
                "waves": [[h.id for h in wave] for wave in waves],
            })

        executor_calls = 0
        critic_calls = 0
        for wave in waves:
            for hyp in wave:
                if on_event:
                    on_event("hypothesis_start", {
                        "id": hyp.id, "name": hyp.hypothesis,
                        "depends_on": hyp.depends_on, "tools_hint": hyp.tools_hint,
                    })

                verdict = None
                feedback = None
                for attempt in range(EXECUTOR_MAX_RETRIES + 1):
                    text, transcript = self._run_executor(hyp, ctx, feedback,
                                                          prior_notes)
                    executor_calls += 1
                    hyp.retries = attempt
                    hyp.tools_used = [t.get("tool", "?") for t in transcript]
                    if on_event and transcript:
                        on_event("tools_used", {
                            "id": hyp.id, "tools": hyp.tools_used,
                        })
                    verdict = _parse_verdict(text)
                    if verdict is None:
                        if attempt < EXECUTOR_MAX_RETRIES:
                            feedback = ("Your previous response was not a valid "
                                        "JSON verdict object. Output ONLY the "
                                        "JSON object.")
                            continue
                        break
                    if feedback is not None:
                        break  # this was the retry; accept it (no 2nd critic pass)
                    # Critic audit.
                    critic_calls += 1
                    review = self.critic.review(
                        hypothesis=hyp.hypothesis,
                        verdict={
                            "hypothesis": hyp.hypothesis,
                            "verdict": verdict["verdict"],
                            "evidence_found": verdict["evidence_found"],
                            "confidence": verdict["confidence"],
                            "reasoning": verdict["reasoning"],
                        },
                        tool_outputs=transcript,
                    )
                    hyp.critic_approved = review.get("approved", False)
                    hyp.critic_issues = review.get("issues") or []
                    if review.get("approved"):
                        break
                    # Phase 11 §11.3 — log critic rejections so the pattern
                    # learner can avoid the tool sequences that produced them.
                    try:
                        from ai.failure_library import log_critic_rejection
                        log_critic_rejection(
                            hypothesis=hyp.hypothesis,
                            bad_verdict={"verdict": verdict["verdict"],
                                         "confidence": verdict["confidence"],
                                         "evidence_found": verdict["evidence_found"]},
                            critic_issues=hyp.critic_issues,
                            tools_used=hyp.tools_used,
                            pcap_hash=_pcap_hash_of(ctx) or "",
                        )
                    except Exception as exc:
                        logger.debug("critic-rejection log failed: %s", exc)
                    corrected = review.get("corrected_verdict")
                    issues = "\n".join(hyp.critic_issues)
                    feedback = (issues + ("\n" + corrected if corrected else "")).strip()
                    if not feedback:
                        break  # nothing actionable from the critic

                self._finalize(hyp, verdict)
                # Phase 10 §10.2 — persist critic-approved verdicts + their
                # IOCs so a future session over this/related captures can
                # recall them.
                if hyp.critic_approved and hyp.verdict != "inconclusive":
                    _persist_verdict(hyp, ctx)
                if on_event:
                    on_event("hypothesis_verdict", {
                        "id": hyp.id,
                        "name": hyp.hypothesis,
                        "verdict": hyp.verdict,
                        "confidence": hyp.confidence,
                        "evidence": hyp.evidence,
                        "reasoning": hyp.reasoning,
                        "critic_approved": hyp.critic_approved,
                        "critic_issues": hyp.critic_issues,
                        "retries": hyp.retries,
                    })

        result = DAGResult(
            hypotheses=hypotheses,
            executor_calls=executor_calls,
            critic_calls=critic_calls,
            elapsed_sec=time.monotonic() - t_start,
        )
        if on_event:
            on_event("dag_done", {"llm_calls": result.llm_calls,
                                  "elapsed_sec": result.elapsed_sec})
        return result

    # ------------------------------------------------------------------ #
    # Executor                                                            #
    # ------------------------------------------------------------------ #
    def _run_executor(self, hyp: DAGHypothesis, ctx,
                      feedback: Optional[str],
                      prior_notes: Optional[List[str]] = None) -> tuple:
        """One executor tool loop. Returns (final_text, transcript)."""
        if self.llm is None or not getattr(self.llm, "query_with_tools", None):
            return None, []
        sys_prompt = EXECUTOR_SYSTEM_PROMPT
        # Phase 14 TASK 2 — compact prompt; base keeps the verdict JSON schema.
        try:
            from ai.prompt_optimizer import build_system_prompt, top_patterns
            sys_prompt = build_system_prompt(
                "explainer", patterns=top_patterns(2),
                base=EXECUTOR_SYSTEM_PROMPT)
        except Exception as exc:
            logger.warning("prompt_optimizer executor failed: %s", exc)
        if feedback:
            sys_prompt += (
                "\n\nA critic reviewed your previous verdict. Address these "
                "issues and produce a corrected verdict JSON object:\n" + feedback
            )
        user_prompt = (
            f"Hypothesis to verify: {hyp.hypothesis}\n"
            f"Suggested tools: {', '.join(hyp.tools_hint) or '(any)'}\n"
            "Gather evidence and return the verdict JSON object."
        )
        if prior_notes:
            notes = "\n".join(f"- {n}" for n in prior_notes)
            user_prompt = (
                "Prior-session knowledge (from earlier investigations):\n"
                f"{notes}\n\n"
                "You MAY use this as a hint, but verify against the current "
                "capture's tools before citing it.\n\n"
                f"{user_prompt}"
            )
        try:
            result = self.llm.query_with_tools(
                question=user_prompt,
                context=ctx,
                model_type="explainer",
                max_steps=EXECUTOR_MAX_STEPS,
                max_tokens=2500,
                temperature=0.2,
                return_transcript=True,
                system_prompt=sys_prompt,
            )
        except Exception as exc:
            logger.warning("DAG executor failed for %s: %s", hyp.id, exc)
            return None, []
        if isinstance(result, tuple) and len(result) == 2:
            return result
        return result, []

    # ------------------------------------------------------------------ #
    # Finalization                                                        #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _finalize(hyp: DAGHypothesis, verdict: Optional[Dict[str, Any]]) -> None:
        if verdict is None:
            hyp.verdict = "inconclusive"
            hyp.confidence = 0.0
            hyp.reasoning = "(executor unavailable — no verdict produced)"
            return
        hyp.evidence = verdict["evidence_found"]
        hyp.reasoning = verdict["reasoning"]
        if verdict["confidence"] < INCONCLUSIVE_CONFIDENCE:
            hyp.verdict = "inconclusive"
            hyp.confidence = verdict["confidence"]
            return
        hyp.verdict = verdict["verdict"]
        hyp.confidence = verdict["confidence"]

    @staticmethod
    def _to_hypothesis(item: Dict[str, Any]) -> DAGHypothesis:
        return DAGHypothesis(
            id=str(item.get("id", "H?")),
            hypothesis=str(item.get("hypothesis", "?")),
            depends_on=[str(d) for d in item.get("depends_on", [])],
            tools_hint=[str(t) for t in item.get("tools_hint", [])][:5],
            priority=max(1, min(3, int(item.get("priority", 2)))),
        )
