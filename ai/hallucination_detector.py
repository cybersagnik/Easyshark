"""
ai/hallucination_detector.py — Phase 7

A small, second-pass audit of the LLM's final answer. Runs ASYNC so it
never delays the analyst's interactive flow.

The detector asks qwen2.5:7b one focused question:

    "Given this answer and these extracted facts, which claims in the
    answer are NOT supported by the facts?"

Returns a HallucinationResult with:
    score        — 0.0 (high confidence) to 1.0 (likely hallucinated)
    flagged_claims — list of claim strings the model marked as unsupported

Design constraints:
- Single LLM call, max_tokens=300, temperature=0.0 — cheap and stable.
- Falls back to deterministic-only scoring when the LLM is unavailable:
  re-runs _verify_claims and treats every "unverified" claim as a flag.
- Non-blocking: launched in a daemon thread. Caller supplies on_result
  callback; result is delivered on the next main-loop tick.
- Never raises into the caller. Logs and returns silently on any error.
"""
from __future__ import annotations

import logging
import re
import threading
from dataclasses import dataclass, field
from typing import Callable, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public dataclass
# ---------------------------------------------------------------------------
@dataclass
class HallucinationResult:
    score: float = 0.0
    flagged_claims: List[str] = field(default_factory=list)
    source: str = ""        # "llm" | "deterministic" | "skipped"
    latency_ms: int = 0


# ---------------------------------------------------------------------------
# Deterministic fallback — pure Python, no LLM.
# ---------------------------------------------------------------------------
def _deterministic_score(answer: str, packets, flows) -> HallucinationResult:
    """When the LLM is unavailable, score using only the claim-grounding
    pass. Every unverified claim is treated as a potential hallucination;
    contradicted claims are weighted 2x. Returns a score in [0, 1]."""
    from cli.ai_commands import _extract_claims, _verify_claims
    try:
        claims = _extract_claims(answer or "")
        if not claims:
            return HallucinationResult(score=0.0, source="deterministic")
        tags = _verify_claims(claims, packets, flows)
        n_total = max(len(tags), 1)
        n_unver = sum(1 for v in tags.values() if v == "unverified")
        n_contra = sum(1 for v in tags.values() if v == "contradicted")
        flagged = [k for k, v in tags.items() if v != "verified"]
        # Weight contradicted 2x. Cap at 1.0.
        score = min(1.0, (n_unver + 2 * n_contra) / n_total)
        return HallucinationResult(
            score=score, flagged_claims=flagged, source="deterministic")
    except Exception as exc:
        logger.debug("deterministic scoring failed: %s", exc)
        return HallucinationResult(score=0.0, source="deterministic")


# ---------------------------------------------------------------------------
# LLM scoring — one focused call to qwen2.5:7b.
# ---------------------------------------------------------------------------
_LLM_PROMPT = """You are auditing a forensic answer for unsupported claims.

QUESTION:
{question}

ANSWER TO AUDIT:
{answer}

VERIFIABLE FACTS EXTRACTED FROM THE CAPTURE:
{evidence}

For each concrete claim in the ANSWER (IP addresses, ports, usernames,
filenames, MD5 hashes, packet counts), look it up in the VERIFIABLE
FACTS above. If the value appears literally in the facts, the claim is
SUPPORTED. If the value cannot be found anywhere in the facts, flag it.

IMPORTANT:
- IP addresses appear in "Top destinations: ip=count, ip=count".
- Ports appear in "Top dst_ports: port=count".
- Usernames (email addresses) appear in "SMTP creds: user/pass" lines.
- Filenames + MD5s appear in "Attachments: filename@md5" or
  "Carved: filename@md5" lines.
- A username like "sneakyg33k@aol.com" IS supported when "SMTP creds:
  sneakyg33k@aol.com/..." is present.
- A password IS supported when it appears in the "SMTP creds" line.
- A filename + MD5 IS supported when "filename@md5" appears in the
  attachments or carved list.

Reply with ONLY this JSON (no prose, no markdown):
{{"flagged_claims": ["ip:1.2.3.4", "md5:abc...", ...],
  "score": 0.0_to_1.0}}

`score` is your overall confidence that the ANSWER contains at least one
unsupported concrete claim:
  0.0 = every concrete claim is supported
  0.3 = one claim unsupported
  0.7 = many claims unsupported
  1.0 = the answer is fabricated

Be PRECISE: only flag values that genuinely do not appear in the
VERIFIABLE FACTS. If you cannot tell, leave it out of flagged_claims.
"""


def _score_with_llm(answer: str, question: str,
                    packets, flows, llm_client) -> HallucinationResult:
    from cli.ai_commands import _grounding_evidence_text
    evidence = _grounding_evidence_text(packets, flows)
    prompt = _LLM_PROMPT.format(
        question=question or "(unknown)",
        answer=answer or "(empty)",
        evidence=evidence,
    )
    try:
        raw = llm_client.query(prompt, model_type="explainer",
                               temperature=0.0)
    except Exception as exc:
        logger.debug("hallucination LLM call failed: %s", exc)
        return _deterministic_score(answer, packets, flows)
    if not raw or not raw.strip():
        return _deterministic_score(answer, packets, flows)

    # Parse the JSON. Tolerate trailing prose and markdown fences.
    text = raw.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    m = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if not m:
        return _deterministic_score(answer, packets, flows)
    try:
        import json
        obj = json.loads(m.group(0))
    except Exception:
        return _deterministic_score(answer, packets, flows)
    flagged = obj.get("flagged_claims") or []
    try:
        score = float(obj.get("score", 0.0))
        score = max(0.0, min(1.0, score))
    except Exception:
        score = 0.0
    return HallucinationResult(
        score=score,
        flagged_claims=[str(x) for x in flagged if x],
        source="llm")


# ---------------------------------------------------------------------------
# Public entry point — runs sync; the async wrapper is below.
# ---------------------------------------------------------------------------
def score_answer(answer: str, question: str,
                 packets, flows, llm_client=None) -> HallucinationResult:
    """Compute the hallucination score for an answer. Returns a
    HallucinationResult. Never raises."""
    import time
    t0 = time.monotonic()
    if not answer or not answer.strip():
        return HallucinationResult(score=0.0, source="skipped",
                                   latency_ms=0)
    if llm_client is not None and llm_client.is_available():
        try:
            res = _score_with_llm(answer, question, packets, flows,
                                  llm_client)
        except Exception as exc:
            logger.debug("LLM scoring crashed, using deterministic: %s", exc)
            res = _deterministic_score(answer, packets, flows)
    else:
        res = _deterministic_score(answer, packets, flows)
    res.latency_ms = int((time.monotonic() - t0) * 1000)
    return res


# ---------------------------------------------------------------------------
# Async wrapper — non-blocking. Runs in a daemon thread.
# ---------------------------------------------------------------------------
def run_async_score(answer: str,
                    question: str,
                    packets,
                    flows,
                    shell=None,
                    on_result: Optional[Callable[[HallucinationResult], None]] = None
                    ) -> threading.Thread:
    """Spawn a daemon thread that scores `answer` and (optionally)
    invokes `on_result(result)` on completion. The thread is daemon=True
    so it cannot keep the shell alive on shutdown."""
    llm_client = None
    if shell is not None:
        # InteractiveShell stores the client as ``llm_client`` (not ``llm``).
        llm_client = getattr(shell, "llm", None) \
                    or getattr(shell, "llm_client", None)
        if llm_client is None:
            ai_handler = getattr(shell, "ai_handler", None)
            llm_client = getattr(ai_handler, "llm", None) if ai_handler else None

    def _runner():
        try:
            result = score_answer(answer, question, packets, flows,
                                  llm_client=llm_client)
            if on_result is not None:
                try:
                    on_result(result)
                except BaseException:
                    pass  # never cascade; the answer is already on screen
        except BaseException:
            pass  # never cascade; logging itself can OOM under pressure

    t = threading.Thread(target=_runner, name="hallucination-detector",
                         daemon=True)
    try:
        t.start()
    except Exception as exc:
        # Thread creation/start can fail under memory pressure (OOM) or
        # when the runtime cannot allocate a new thread stack. This must
        # NEVER propagate into the shell — a scoring thread is optional
        # and the answer is already on screen.
        logger.warning("hallucination-detector thread start failed: %s", exc)
    return t


__all__ = ["HallucinationResult", "score_answer", "run_async_score"]
