"""
pattern_learner.py — Phase 11 §11.1 cross-session tool-sequence learning.

Learns *"which tool sequences work for which question families"* from the
verdicts table (Phase 10 §10.1) and serves suggestions to the
HypothesisPlanner as a ``tools_hint`` override so the planner stops
guessing which forensic tools to reach for.

Storage: ``~/.easyshark/patterns.jsonl`` (env override
``EASYSHARK_PATTERNS_PATH``). Each row:

    {
      "question_keywords": ["smtp", "username", "credential"],
      "tool_sequence":     ["get_smtp_credentials"],
      "success_rate":      0.8,      # 0.0-1.0
      "sample_count":      4
    }

API:
    learn_from_verdicts(n=50)  — pull critic-approved verdicts, merge
    update_patterns(question, tools_used, success)  — merge one datapoint
    suggest_tools(question)    — top-3 tool hints (or None) when a pattern
                                 is confident (success_rate > 0.7)
    read_patterns(limit=20)    — for diagnostics
    learn_in_background()      — fire-and-forget daemon thread (non-blocking)

Honesty rules:
    - Learning only consumes critic-APPROVED verdicts.
    - Suggestions require success_rate > 0.7 AND a keyword overlap — a
      pattern with one lucky sample never overrides the LLM planner.
    - All file I/O is guarded by a module lock and wrapped in
      try/except; this module must never crash the investigation.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

PATTERNS_PATH = Path(os.environ.get(
    "EASYSHARK_PATTERNS_PATH", str(Path.home() / ".easyshark" / "patterns.jsonl")))

_ENABLED = os.environ.get("EASYSHARK_PATTERNS_ENABLED", "1") != "0"
_RSI_REQUIRE_FEEDBACK = os.environ.get("EASYSHARK_RSI_REQUIRE_FEEDBACK", "1") != "0"

# Confidence gate: only patterns whose success_rate clears this bar are
# allowed to override the LLM planner's own tool hints.
SUGGEST_CONFIDENCE = 0.7
SUGGEST_MIN_SAMPLES = 2
MAX_TOOL_HINTS = 3

_STOPWORDS = {
    "what", "which", "when", "where", "who", "how", "many", "much",
    "the", "a", "an", "and", "or", "of", "in", "on", "to", "from",
    "with", "was", "were", "did", "does", "this", "that", "for", "is",
    "are", "do", "it", "its", "has", "have", "by", "at", "as", "be",
    "any", "all", "can", "could", "should", "please", "capture",
}
_KEYWORD_RE = re.compile(r"[a-z0-9_]+")

_lock = threading.Lock()


# --------------------------------------------------------------------------- #
# Storage                                                                      #
# --------------------------------------------------------------------------- #
def patterns_path() -> Path:
    return PATTERNS_PATH


def read_patterns(limit: int = 20) -> List[Dict[str, Any]]:
    """Load the most recent patterns (newest last in file -> reversed)."""
    if not PATTERNS_PATH.exists():
        return []
    rows: List[Dict[str, Any]] = []
    try:
        for line in PATTERNS_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                rows.append(obj)
    except Exception as exc:
        logger.warning("read_patterns failed: %s", exc)
        return []
    return rows[-max(1, limit):]


def _write_rows(rows: List[Dict[str, Any]]) -> None:
    try:
        PATTERNS_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = PATTERNS_PATH.with_suffix(".jsonl.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        tmp.replace(PATTERNS_PATH)
    except Exception as exc:
        logger.warning("pattern persist failed: %s", exc)


# --------------------------------------------------------------------------- #
# Keyword helpers                                                              #
# --------------------------------------------------------------------------- #
def _keywords(text: str) -> List[str]:
    """Lowercased alnum tokens, stopwords removed."""
    if not text:
        return []
    return [t for t in _KEYWORD_RE.findall(text.lower())
            if len(t) >= 3 and t not in _STOPWORDS]


# --------------------------------------------------------------------------- #
# Learning                                                                     #
# --------------------------------------------------------------------------- #
def update_patterns(question: str,
                    tools_used: List[str],
                    success: float,
                    confidence: Optional[float] = None) -> None:
    """Merge one datapoint into the pattern store.

    Args:
        question: the analyst question the tools were used on.
        tools_used: tool names actually invoked (from the executor).
        success: 0.0-1.0 — how well the sequence performed (see
            _verdict_success). Only critic-approved verdicts should be
            passed here.
        confidence: 0.0-1.0 — the executor verdict's numeric confidence
            (Gap 4). Rolling mean is stored so suggest_tools can weight
            hints by how certain the evidence was, not just success.
    """
    if not _ENABLED:
        return
    tools = [t for t in (tools_used or []) if t][:10]
    if not tools:
        return
    kws = _keywords(question)
    if not kws:
        return
    try:
        with _lock:
            rows = read_patterns(limit=10_000)
            # Find an existing pattern for the same question family
            # (overlapping keywords) AND same tool sequence.
            best = None
            for row in rows:
                existing = set(row.get("question_keywords") or [])
                if set(kws) & existing and row.get("tool_sequence") == tools:
                    best = row
                    break
            if best is None:
                rows.append({
                    "question_keywords": kws,
                    "tool_sequence": tools,
                    "success_rate": success,
                    "sample_count": 1,
                    "mean_confidence": round(confidence or success, 4),
                    "status": "candidate",
                    "feedback_total": 0,
                    "feedback_pass": 0,
                })
            else:
                n = int(best.get("sample_count", 1))
                rate = float(best.get("success_rate", success))
                best["success_rate"] = round(
                    (rate * n + success) / (n + 1), 4)
                best["sample_count"] = n + 1
                # Gap 4 — rolling mean of the numeric verdict confidence.
                prev_conf = float(best.get("mean_confidence", rate))
                best["mean_confidence"] = round(
                    (prev_conf * n + (confidence if confidence is not None else success))
                    / (n + 1), 4)
                # Grow the keyword set with new family terms.
                merged = list(dict.fromkeys(
                    list(best.get("question_keywords") or []) + kws))[:20]
                best["question_keywords"] = merged
            _write_rows(rows)
    except Exception as exc:
        logger.warning("update_patterns failed: %s", exc)


def _verdict_success(verdict: str, critic_approved: bool) -> float:
    """Map a verdict to a learning signal. Approved 'confirmed' is a clean
    hit; approved 'weakened' is partial; an approved rule-out is still
    informative but not a strong hit. Anything critic-rejected scores 0."""
    if not critic_approved:
        return 0.0
    v = (verdict or "").lower()
    if v == "confirmed":
        return 1.0
    if v == "weakened":
        return 0.5
    if v == "ruled_out":
        return 0.25
    return 0.0


def learn_from_verdicts(n: int = 50,
                        db_path: Optional[Path] = None) -> int:
    """Pull the latest critic-approved verdicts from the memory DB and merge
    them into the pattern store. Returns how many were merged (best-effort).
    ``db_path`` is passed through to the memory layer for hermetic tests.
    """
    if not _ENABLED:
        return 0
    try:
        from core import memory
        verdicts = memory.approved_verdicts(n=n, db_path=db_path)
    except Exception as exc:
        logger.warning("learn_from_verdicts: memory read failed: %s", exc)
        return 0
    merged = 0
    for v in verdicts:
        tools = [t.strip() for t in str(v.get("tools_used") or "").split(",")
                 if t.strip()]
        if not tools:
            continue
        success = _verdict_success(v.get("verdict", ""),
                                   bool(v.get("critic_approved")))
        update_patterns(
            question=v.get("hypothesis") or "",
            tools_used=tools,
            success=success,
            confidence=float(v.get("confidence") or 0.0),
        )
        merged += 1
    return merged


# --------------------------------------------------------------------------- #
# Suggestion                                                                   #
# --------------------------------------------------------------------------- #
def suggest_tools(question: str) -> Optional[List[str]]:
    """Return up to 3 tool hints for a question, or None when no learned
    pattern is confident (success_rate > 0.7) AND overlaps the question.

    The planner should treat the result as an *override* hint: these tools
    worked for this question family in prior critic-approved runs.
    """
    if not _ENABLED:
        return None
    qkws = set(_keywords(question))
    if not qkws:
        return None
    try:
        rows = read_patterns(limit=10_000)
    except Exception:
        return None
    scored: List[tuple] = []
    for row in rows:
        pkws = set(row.get("question_keywords") or [])
        overlap = len(qkws & pkws)
        if overlap == 0:
            continue
        rate = float(row.get("success_rate", 0.0))
        n = int(row.get("sample_count", 0))
        min_samples = 1 if _RSI_REQUIRE_FEEDBACK else SUGGEST_MIN_SAMPLES
        if rate < SUGGEST_CONFIDENCE or n < min_samples:
            continue
        tools = row.get("tool_sequence") or []
        # Gap 4 — weight by the rolling mean of the numeric verdict
        # confidence so high-certainty evidence outranks barely-confident
        # successes when both clear the success-rate gate.
        conf = float(row.get("mean_confidence", rate))
        if _RSI_REQUIRE_FEEDBACK:
            from ai.rsi import validate_pattern
            if not validate_pattern(row):
                continue
        scored.append((overlap * rate * conf, n, tools))
    if not scored:
        return None
    scored.sort(key=lambda x: (x[0], x[1]), reverse=True)
    hints: List[str] = []
    for _, _, tools in scored:
        for t in tools:
            if t not in hints:
                hints.append(t)
            if len(hints) >= MAX_TOOL_HINTS:
                return hints
    return hints or None


# --------------------------------------------------------------------------- #
# Background learning                                                          #
# --------------------------------------------------------------------------- #
def learn_in_background(n: int = 50) -> None:
    """Fire-and-forget: merge recent approved verdicts into patterns on a
    daemon thread so an investigation is never blocked by learning."""
    if not _ENABLED:
        return
    try:
        t = threading.Thread(target=learn_from_verdicts, args=(n,),
                             name="pattern-learner", daemon=True)
        t.start()
    except Exception as exc:
        logger.warning("pattern learner thread failed to start: %s", exc)
