"""
prompt_distiller.py — Phase 11 §11.2 weekly reasoning-pattern distillation.

Periodically (weekly gate) reads the last ~50 critic-approved verdicts,
asks the "coder" role to compress them into 3-5 reusable JSON reasoning
patterns, and stores them so the planner/explainer can use them as
few-shot examples (~300 tokens).

Storage: ``~/.easyshark/distilled_prompts.jsonl`` (env override
``EASYSHARK_DISTILLED_PATH``). Each row:

    {
      "ts": "2026-08-02T...",
      "patterns": [
        {
          "family": "smtp_credentials",
          "question_keywords": ["smtp", "username", "password"],
          "tool_sequence": ["get_smtp_credentials", "follow_stream"],
          "reasoning": "AUTH LOGIN user/password pairs live in the SMTP
                        session; follow the stream then extract creds."
        }
      ]
    }

API:
    maybe_distill(llm_client, force=False)  — weekly gate + budget gate,
                                              distill & append
    load_distilled(limit=3)                  — top-N patterns (few-shot)
    top_few_shot(limit=3, max_tokens=300)    — compact few-shot block
    last_distilled_ts()                      — for the weekly gate
    distill(approved_verdicts, llm_client)   — raw distill step (testable)

Budget protection: distillation is skipped entirely when the OpenRouter
session counter exceeds 40 calls today (spec §11.2) — learning must never
compete with analyst Q&A.
"""
from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DISTILLED_PATH = Path(os.environ.get(
    "EASYSHARK_DISTILLED_PATH",
    str(Path.home() / ".easyshark" / "distilled_prompts.jsonl")))

_ENABLED = os.environ.get("EASYSHARK_DISTILLER_ENABLED", "1") != "0"

# Weekly gate: only distill if the last distill is older than this.
WEEK_SEC = 7 * 24 * 60 * 60

# Budget gate: never distill when OpenRouter has already burned this many
# calls today (spec §11.2 — learning must not compete with analyst Q&A).
BUDGET_GATE_CALLS = 40

# How many verdicts to consider and how many patterns to request.
DISTILL_VERDICT_LIMIT = 50
MIN_PATTERNS = 3
MAX_PATTERNS = 5

DISTILL_SYSTEM_PROMPT = """You are a forensic-analysis pattern distiller. Given a list of
critic-approved investigation verdicts (hypothesis, verdict, evidence,
tools used), compress them into 3-5 reusable reasoning patterns.

Return a JSON object ONLY:
{
  "patterns": [
    {
      "family": "short family name",
      "question_keywords": ["k1", "k2", ...],
      "tool_sequence": ["tool_a", "tool_b"],
      "reasoning": "one or two sentences: when this question family
                    appears, this tool sequence finds the evidence and
                    why (e.g. AUTH LOGIN creds live in the SMTP stream)."
    }
  ]
}

Rules:
- 3 to 5 patterns. Each pattern must be grounded in the verdicts given —
  never invent tool sequences not present in the data.
- question_keywords should be the question words that predict the family
  (max 8).
- tool_sequence max 5 tools, ordered by actual usage.
- Output ONLY the JSON. No fences, no prose."""


def distilled_path() -> Path:
    return DISTILLED_PATH


def last_distilled_ts() -> Optional[float]:
    """Unix timestamp of the most recent distill row, or None."""
    if not DISTILLED_PATH.exists():
        return None
    try:
        last = None
        for line in DISTILLED_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            ts = obj.get("ts")
            if ts:
                try:
                    val = float(ts)
                except (TypeError, ValueError):
                    continue
                last = max(last or 0.0, val)
        return last
    except Exception as exc:
        logger.warning("last_distilled_ts failed: %s", exc)
        return None


def _append_distilled(payload: Dict[str, Any]) -> None:
    try:
        DISTILLED_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(DISTILLED_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload) + "\n")
    except Exception as exc:
        logger.warning("distilled append failed: %s", exc)


def load_distilled(limit: int = 3) -> List[Dict[str, Any]]:
    """Most recent distilled patterns (across batches), newest first."""
    if not DISTILLED_PATH.exists():
        return []
    patterns: List[Dict[str, Any]] = []
    try:
        for line in DISTILLED_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            for p in obj.get("patterns") or []:
                if isinstance(p, dict):
                    patterns.append(p)
    except Exception as exc:
        logger.warning("load_distilled failed: %s", exc)
        return []
    return patterns[-max(1, limit):]


def top_few_shot(limit: int = 3, max_tokens: int = 300) -> str:
    """Compact few-shot block for the planner prompt (≤ ~300 tokens)."""
    pats = load_distilled(limit=limit)
    if not pats:
        return ""
    lines = ["## Learned reasoning patterns (from prior approved investigations)"]
    budget = max_tokens
    for p in pats:
        block = (
            f"- family: {p.get('family', '?')}\n"
            f"  triggers: {', '.join(p.get('question_keywords') or [])[:80]}\n"
            f"  tools:    {', '.join(p.get('tool_sequence') or [])[:80]}\n"
            f"  why:      {(p.get('reasoning') or '')[:140]}\n"
        )
        if budget - len(block.split()) < 0:
            break
        lines.append(block)
        budget -= len(block.split())
    return "\n".join(lines)


def distill(verdicts: List[Dict[str, Any]],
            llm_client) -> Optional[List[Dict[str, Any]]]:
    """One distillation pass over approved verdicts (testable, no gate).
    Returns a list of patterns or None on failure."""
    if not verdicts:
        return None
    verdict_lines = [
        (f"- question: {v.get('question') or ''}\n"
         f"  oracle: {v.get('oracle_kind') or ''} "
         f"expected={bool(v.get('expected'))} predicted={bool(v.get('predicted'))} "
         f"(confidence {v.get('confidence') or 0.0})\n"
         f"  tools: {', '.join(v.get('tools') or [])}\n"
         f"  evidence: {str(v.get('evidence') or '')[:200]}")
        for v in verdicts
    ]
    user = ("Independent oracle outcomes to distill:\n"
            + "\n".join(verdict_lines)
            + "\n\nProduce the JSON pattern object.")
    from ai.investigator import _single_completion, _extract_json_obj
    raw = _single_completion(
        llm_client, DISTILL_SYSTEM_PROMPT, user,
        model_type="coder", temperature=0.1, max_tokens=800,
    )
    if not raw:
        logger.warning("distill: LLM returned nothing")
        return None
    obj = _extract_json_obj(raw)
    if not obj:
        logger.warning("distill: unparseable response %.200s", raw)
        return None
    pats = [p for p in (obj.get("patterns") or []) if isinstance(p, dict)]
    if not (MIN_PATTERNS <= len(pats) <= MAX_PATTERNS):
        logger.warning("distill: bad pattern count %d", len(pats))
        return None
    # Normalise fields so consumers can rely on the schema.
    out = []
    for p in pats:
        out.append({
            "family": str(p.get("family") or "unknown")[:60],
            "question_keywords": [str(k) for k in (p.get("question_keywords") or [])][:8],
            "tool_sequence": [str(t) for t in (p.get("tool_sequence") or [])][:5],
            "reasoning": str(p.get("reasoning") or "")[:300],
        })
    return out


def maybe_distill(llm_client, force: bool = False,
                  db_path: Optional[Path] = None) -> Optional[List[Dict[str, Any]]]:
    """Weekly-gated distillation. Returns the new patterns, or None when
    skipped (gate / budget / LLM failure). ``force`` bypasses the weekly
    gate but NOT the budget gate. ``db_path`` is passed to memory for
    hermetic tests."""
    if not _ENABLED:
        return None
    # Budget gate — never compete with analyst Q&A.
    try:
        calls_today = int(getattr(llm_client, "openrouter_calls_today", 0) or 0)
        if calls_today > BUDGET_GATE_CALLS:
            logger.info("distiller: budget gate (%d/%d calls) — skipped",
                        calls_today, BUDGET_GATE_CALLS)
            return None
    except Exception:
        pass
    # Weekly gate.
    if not force:
        last = last_distilled_ts()
        if last is not None and (time.time() - last) < WEEK_SEC:
            logger.debug("distiller: weekly gate — skipped (last %s)",
                         time.strftime("%Y-%m-%d", time.gmtime(last)))
            return None
    try:
        from ai.oracle import OracleStore
        verdicts = OracleStore(str(db_path) if db_path else None).training_examples(
            DISTILL_VERDICT_LIMIT)
    except Exception as exc:
        logger.warning("distiller: oracle read failed: %s", exc)
        return None
    if not verdicts:
        logger.debug("distiller: no independent oracle outcomes to learn from")
        return None
    pats = distill(verdicts, llm_client)
    if not pats:
        return None
    _append_distilled({
        "ts": time.time(),
        "patterns": pats,
    })
    logger.info("distiller: stored %d patterns", len(pats))
    return pats
