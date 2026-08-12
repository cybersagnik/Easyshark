"""Measured recursive self-improvement controls.

Patterns are candidates until an analyst independently labels their usefulness.
This prevents the executor and critic from silently training the planner on
their own possibly-wrong conclusions.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

MIN_FEEDBACK = 3
PROMOTE_RATE = 0.75
RETIRE_RATE = 0.40


def _enabled() -> bool:
    import os
    return os.environ.get("EASYSHARK_RSI_ENABLED", "1") != "0"


def record_oracle_feedback(question: str, accepted: bool, *,
                           oracle_kind: str, oracle_run_id: str = "") -> int:
    """Apply an independent analyst label to matching learned patterns.

    Returns the number of patterns updated. Labels are deliberately explicit;
    an LLM verdict is not treated as independent feedback.
    """
    if oracle_kind not in {"corpus", "synthetic", "rederive", "delayed_intel", "cross_path", "analyst_override"}:
        raise ValueError("feedback source is not an independent oracle")
    if not _enabled() or not question.strip():
        return 0
    from ai import pattern_learner as learner
    query = set(learner._keywords(question))
    if not query:
        return 0
    rows = learner.read_patterns(limit=10_000)
    changed = 0
    for row in rows:
        overlap = query & set(row.get("question_keywords") or [])
        if not overlap:
            continue
        total = int(row.get("feedback_total", 0)) + 1
        passed = int(row.get("feedback_pass", 0)) + (1 if accepted else 0)
        row["feedback_total"] = total
        row["feedback_pass"] = passed
        row["feedback_rate"] = round(passed / total, 4)
        row["last_oracle_kind"] = oracle_kind
        row["last_oracle_run_id"] = oracle_run_id
        if total >= MIN_FEEDBACK:
            row["status"] = "active" if row["feedback_rate"] >= PROMOTE_RATE else "retired"
        changed += 1
    if changed:
        learner._write_rows(rows)
    return changed


def record_feedback(question: str, accepted: bool) -> int:
    """Compatibility entrypoint: an explicit analyst label is a manual oracle.

    Automatic learning paths never call this function.
    """
    return record_oracle_feedback(question, accepted,
                                  oracle_kind="analyst_override")


def status() -> Dict[str, int]:
    """Return candidate/active/retired counts for operator visibility."""
    from ai import pattern_learner as learner
    out = {"candidate": 0, "active": 0, "retired": 0}
    for row in learner.read_patterns(limit=10_000):
        state = row.get("status", "candidate")
        out[state] = out.get(state, 0) + 1
    return out


def validate_pattern(row: Dict[str, Any]) -> bool:
    """Whether a pattern has passed the independent promotion gate."""
    return (row.get("status") == "active"
            and int(row.get("feedback_total", 0)) >= MIN_FEEDBACK
            and float(row.get("feedback_rate", 0.0)) >= PROMOTE_RATE)
