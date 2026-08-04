"""
failure_library.py — Phase 11 §11.3 failure logging.

Appends structured failure rows to ~/.easyshark/failures.jsonl so the
analyst (and the pattern learner) can see what the heuristic / DAG got
wrong, and learn which tool sequences to avoid.

Two writers:
    log_critic_rejection(...)  — a DAG critic rejected a verdict
    log_heuristic_miss(...)    — the heuristic returned None for a question

Both are best-effort (never raise) and gated by EASYSHARK_FAILURES_ENABLED.

Public API:
    log_critic_rejection(hypothesis, bad_verdict, critic_issues, ...)
    log_heuristic_miss(question, triage_flags, ...)
    read_failures(limit=20) -> List[Dict]
"""
from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

FAILURES_PATH = Path(os.environ.get(
    "EASYSHARK_FAILURES_PATH", str(Path.home() / ".easyshark" / "failures.jsonl")))


def failures_enabled() -> bool:
    return os.environ.get("EASYSHARK_FAILURES_ENABLED", "1") != "0"


def _append(row: Dict[str, Any]) -> None:
    if not failures_enabled():
        return
    try:
        FAILURES_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(FAILURES_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
    except Exception as exc:
        logger.warning("failure_library append failed: %s", exc)


def log_critic_rejection(hypothesis: str,
                         bad_verdict: Optional[Dict[str, Any]] = None,
                         critic_issues: Optional[List[str]] = None,
                         pcap_hash: str = "",
                         question: str = "",
                         tools_used: Optional[List[str]] = None) -> None:
    _append({
        "kind": "critic_rejection",
        "question": question,
        "hypothesis": hypothesis,
        "bad_verdict": bad_verdict or {},
        "critic_issues": [str(i)[:300] for i in (critic_issues or [])][:5],
        "tools_used": [str(t) for t in (tools_used or [])],
        "pcap_hash": pcap_hash,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })


def log_heuristic_miss(question: str,
                       triage_flags: Optional[Dict[str, Any]] = None,
                       pcap_hash: str = "",
                       patterns_tried: Optional[List[str]] = None) -> None:
    _append({
        "kind": "heuristic_miss",
        "question": question,
        "triage_flags": {str(k): bool(v) for k, v in (triage_flags or {}).items()},
        "patterns_tried": [str(p) for p in (patterns_tried or [])],
        "pcap_hash": pcap_hash,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })


def read_failures(limit: int = 20) -> List[Dict[str, Any]]:
    """Read the most recent N failure rows (newest first)."""
    if not FAILURES_PATH.exists():
        return []
    rows: List[Dict[str, Any]] = []
    try:
        for line in FAILURES_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    except Exception as exc:
        logger.warning("read_failures failed: %s", exc)
        return []
    return list(reversed(rows))[:max(1, limit)]
