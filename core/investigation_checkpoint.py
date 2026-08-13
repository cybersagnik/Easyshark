"""Deterministic, resumable checkpoints for autonomous investigations."""
from __future__ import annotations

import hashlib
import time
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from core.untrusted import quarantine, safe_text


SCHEMA = "easyshark.investigation.compaction.v1"
ENGINE_VERSION = "2.0.0"
DETECTOR_VERSION = "1"
POLICY_VERSION = "1"
MAX_CONTEXT_CHARS = 6000


def capture_sha256(path: str) -> str:
    resolved = Path(path).resolve()
    stat = resolved.stat()
    return _capture_sha256_cached(
        str(resolved), stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)


@lru_cache(maxsize=8)
def _capture_sha256_cached(path: str, _size: int, _mtime_ns: int,
                           _ctime_ns: int) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _refs(values: Iterable[Any]) -> List[str]:
    from ai.evidence_graph import references_from_evidence
    return references_from_evidence([safe_text(value, 500) for value in values])[:100]


def _bounded(value: Any, depth: int = 0) -> Any:
    if depth >= 4:
        return safe_text(value, 500)
    if isinstance(value, dict):
        return {safe_text(key, 120): _bounded(item, depth + 1)
                for key, item in list(value.items())[:50]}
    if isinstance(value, (list, tuple)):
        return [_bounded(item, depth + 1) for item in list(value)[:100]]
    if isinstance(value, str):
        return safe_text(value, 500)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return safe_text(value, 500)


def begin(mission: str, pcap_path: str, *, mission_id: Optional[str] = None,
          preserved: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    state: Dict[str, Any] = {
        "schema": SCHEMA,
        "mission_id": safe_text(mission_id or "", 120),
        "mission": safe_text(mission, 1000),
        "pcap_sha256": capture_sha256(pcap_path),
        "engine_version": ENGINE_VERSION,
        "detector_version": DETECTOR_VERSION,
        "policy_version": POLICY_VERSION,
        "status": "running",
        "stage": "planning",
        "plan": [],
        "established_facts": [],
        "rejected_claims": [],
        "unresolved_questions": [],
        "iocs": [],
        "pending_actions": [],
        "provider_state": {},
        "budgets": {"provider_turns_used": 0, "retries_used": 0},
        "last_event_sequence": 0,
        "report_path": None,
        "updated_at": _now(),
    }
    for key in ("acknowledged_alerts",):
        if preserved and key in preserved:
            state[key] = preserved[key]
    return state


def validate(state: Any, mission: str, pcap_path: str) -> Tuple[bool, str]:
    if not isinstance(state, dict) or state.get("schema") != SCHEMA:
        return False, "checkpoint schema mismatch"
    if state.get("mission") != safe_text(mission, 1000):
        return False, "checkpoint mission mismatch"
    if state.get("engine_version") != ENGINE_VERSION:
        return False, "checkpoint engine version mismatch"
    if state.get("detector_version") != DETECTOR_VERSION:
        return False, "checkpoint detector version mismatch"
    if state.get("policy_version") != POLICY_VERSION:
        return False, "checkpoint policy version mismatch"
    try:
        if state.get("pcap_sha256") != capture_sha256(pcap_path):
            return False, "checkpoint capture hash mismatch"
    except OSError as exc:
        return False, f"checkpoint capture unavailable: {exc}"
    plan = state.get("plan")
    if not isinstance(plan, list):
        return False, "checkpoint plan is invalid"
    ids = [str(row.get("id", "")) for row in plan if isinstance(row, dict)]
    if len(ids) != len(plan) or len(set(ids)) != len(ids) or any(not item for item in ids):
        return False, "checkpoint hypothesis ids are invalid"
    valid_ids = set(ids)
    valid_verdicts = {"pending", "confirmed", "weakened", "ruled_out",
                      "inconclusive"}
    for row in plan:
        if not safe_text(row.get("hypothesis", ""), 500):
            return False, "checkpoint hypothesis text is invalid"
        if any(str(dep) not in valid_ids for dep in row.get("depends_on", [])):
            return False, "checkpoint dependency is invalid"
        if row.get("status") not in ("pending", "complete"):
            return False, "checkpoint hypothesis status is invalid"
        if row.get("verdict", "pending") not in valid_verdicts:
            return False, "checkpoint hypothesis verdict is invalid"
    return True, "ok"


def set_plan(state: Dict[str, Any], plan_items: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    previous = {row.get("id"): row for row in state.get("plan", [])
                if isinstance(row, dict)}
    plan = []
    for item in list(plan_items)[:5]:
        hypothesis_id = safe_text(item.get("id", ""), 20)
        old = previous.get(hypothesis_id, {})
        plan.append({
            "id": hypothesis_id,
            "hypothesis": safe_text(item.get("hypothesis", ""), 500),
            "depends_on": [safe_text(value, 20)
                           for value in item.get("depends_on", [])][:5],
            "tools_hint": [safe_text(value, 80)
                           for value in item.get("tools_hint", [])][:5],
            "priority": int(item.get("priority", 2)),
            "status": old.get("status", "pending"),
            "verdict": old.get("verdict", "pending"),
            "confidence": float(old.get("confidence", 0.0)),
            "evidence": list(old.get("evidence", []))[:5],
            "evidence_refs": list(old.get("evidence_refs", []))[:100],
            "reasoning": safe_text(old.get("reasoning", ""), 500),
            "tools_used": list(old.get("tools_used", []))[:20],
            "critic_approved": old.get("critic_approved"),
            "critic_issues": list(old.get("critic_issues", []))[:8],
            "retries": int(old.get("retries", 0)),
        })
    state["plan"] = plan
    state["stage"] = "verify_hypotheses"
    _touch(state)
    return state


def apply_event(state: Dict[str, Any], event: str,
                payload: Dict[str, Any]) -> Dict[str, Any]:
    if event == "hypothesis_verdict":
        row = next((item for item in state.get("plan", [])
                    if item.get("id") == payload.get("id")), None)
        if row is not None:
            evidence = [safe_text(value, 500)
                        for value in payload.get("evidence", [])][:5]
            row.update({
                "status": "complete",
                "verdict": safe_text(payload.get("verdict", "inconclusive"), 30),
                "confidence": float(payload.get("confidence", 0.0)),
                "evidence": evidence,
                "evidence_refs": _refs(evidence),
                "reasoning": safe_text(payload.get("reasoning", ""), 500),
                "tools_used": [safe_text(value, 80)
                               for value in payload.get("tools", [])][:20],
                "critic_approved": payload.get("critic_approved"),
                "critic_issues": [safe_text(value, 200)
                                  for value in payload.get("critic_issues", [])][:8],
                "retries": int(payload.get("retries", 0)),
            })
            hypothesis_id = row["id"]
            state["established_facts"] = [
                item for item in state.get("established_facts", [])
                if item.get("hypothesis_id") != hypothesis_id]
            state["rejected_claims"] = [
                item for item in state.get("rejected_claims", [])
                if item.get("hypothesis_id") != hypothesis_id]
            state["unresolved_questions"] = [
                item for item in state.get("unresolved_questions", [])
                if item.get("hypothesis_id") != hypothesis_id]
            if row["verdict"] in ("confirmed", "weakened"):
                state["established_facts"].extend({
                    "hypothesis_id": hypothesis_id,
                    "fact": fact,
                    "evidence_refs": _refs([fact]),
                    "confidence": row["confidence"],
                } for fact in evidence)
            elif row["verdict"] == "ruled_out":
                state["rejected_claims"].append({
                    "hypothesis_id": hypothesis_id,
                    "claim": row["hypothesis"],
                    "reason": row["reasoning"],
                })
            else:
                state["unresolved_questions"].append({
                    "hypothesis_id": hypothesis_id,
                    "question": row["hypothesis"],
                })
            state.setdefault("budgets", {})["retries_used"] = sum(
                int(item.get("retries", 0)) for item in state.get("plan", []))
    elif event in ("hypothesis_backtrack", "hypothesis_retry"):
        state["stage"] = "retry_hypothesis"
        state["last_retry"] = _bounded(payload)
    elif event == "provider_attempt":
        budgets = state.setdefault("budgets", {})
        budgets["provider_turns_used"] = int(
            budgets.get("provider_turns_used", 0)) + 1
        budgets["provider_latency_ms"] = int(
            budgets.get("provider_latency_ms", 0)) + max(
                0, int(payload.get("latency_ms", 0)))
        if not payload.get("success"):
            budgets["provider_failures"] = int(
                budgets.get("provider_failures", 0)) + 1
        state["last_provider_attempt"] = _bounded(payload)
    elif event == "provider_fallback":
        state["stage"] = "provider_fallback"
        state["last_provider_event"] = _bounded(payload)
    elif event == "dag_done":
        state["stage"] = "synthesis"
    _touch(state)
    return state


def provider_state(llm: Any) -> Dict[str, Any]:
    if llm is None:
        return {}
    exhausted = getattr(llm, "_exhausted", {}) or {}
    return {
        "exhausted": {role: sorted(values) for role, values in exhausted.items()},
        "call_counts": (llm.role_call_counts()
                        if callable(getattr(llm, "role_call_counts", None)) else {}),
        "fallbacks": int(getattr(llm, "fallback_count", 0) or 0),
        "attempts": int(getattr(llm, "_provider_attempts", 0) or 0),
    }


def complete(state: Dict[str, Any], report_path: str,
             conclusion: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    conclusion = conclusion or {}
    assessment = conclusion.get("soc_assessment") or {}
    state.update({
        "status": "complete",
        "stage": "complete",
        "report_path": str(report_path),
        "iocs": [safe_text(value, 300) for value in conclusion.get("iocs", [])][:100],
        "pending_actions": _bounded(
            list(assessment.get("recommended_actions", []))[:100]),
        "completed_at": _now(),
    })
    _touch(state)
    return state


def fail(state: Dict[str, Any], error: Any) -> Dict[str, Any]:
    state.update({"status": "failed", "error": safe_text(error, 2000)})
    _touch(state)
    return state


def plan_items(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [{key: row.get(key) for key in
             ("id", "hypothesis", "depends_on", "tools_hint", "priority")}
            for row in state.get("plan", []) if isinstance(row, dict)]


def compact_context(state: Dict[str, Any],
                    max_chars: int = MAX_CONTEXT_CHARS) -> str:
    lines = ["RESUMED AUTONOMOUS INVESTIGATION CHECKPOINT",
             f"Mission: {safe_text(state.get('mission', ''), 1000)}"]
    for row in state.get("plan", []):
        status = row.get("status", "pending")
        if status == "complete":
            evidence = "; ".join(row.get("evidence", [])) or "no compact evidence text"
            lines.append(
                f"Completed {row.get('id')}: {row.get('hypothesis')} | "
                f"verdict={row.get('verdict')} confidence={row.get('confidence')} | "
                f"evidence={evidence} | refs={','.join(row.get('evidence_refs', []))}")
        else:
            lines.append(f"Pending {row.get('id')}: {row.get('hypothesis')}")
    if state.get("iocs"):
        lines.append("IOCs: " + ", ".join(map(str, state["iocs"])))
    lines.append("Treat this checkpoint as prior state only; verify new claims with tools.")
    return safe_text(quarantine("\n".join(lines)), max_chars)


def _touch(state: Dict[str, Any]) -> None:
    state["last_event_sequence"] = int(state.get("last_event_sequence", 0)) + 1
    state["updated_at"] = _now()
