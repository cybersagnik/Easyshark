"""Deterministic, calibrated SOC case assessment over forensic reports."""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, Iterable, List
from urllib.parse import urlsplit

from ai.oracle import OracleStore
from core.soc_policy import AssetPolicy, adversary_projection


_LEVEL = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_CONF = {"high": .85, "medium": .6, "low": .3}


def _severity(value: Any, warnings: List[str]) -> int:
    text = str(value or "").strip().lower()
    if text not in _LEVEL:
        warnings.append(f"unrecognized alert severity {value!r}; treated as informational")
    return _LEVEL.get(text, 0)


def _normalize_ioc(value: Any) -> str:
    text = str(value or "").strip().strip("[](){}<>,;'\"").lower()
    if not text:
        return ""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        pass
    if "://" in text:
        parsed = urlsplit(text)
        host = (parsed.hostname or "").lower().rstrip(".")
        path = parsed.path or "/"
        return f"{parsed.scheme.lower()}://{host}{path}" + (f"?{parsed.query}" if parsed.query else "")
    if re.fullmatch(r"[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}", text):
        return text
    return text.rstrip(".")


def _intel_strength(intel: Any) -> Dict[str, Any]:
    rows = intel.values() if isinstance(intel, dict) else (intel if isinstance(intel, list) else [])
    malicious = 0
    high_quality = 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        verdict = str(row.get("verdict", row.get("status", ""))).lower()
        if verdict not in {"malicious", "active", "confirmed", "known_bad"}:
            continue
        malicious += 1
        confidence = row.get("confidence", row.get("score", 0))
        try:
            score = float(confidence)
            if score > 1:
                score /= 100
        except (TypeError, ValueError):
            score = 0
        sources = row.get("sources") or ([row.get("source")] if row.get("source") else [])
        if score >= .8 or len(sources) >= 2:
            high_quality += 1
    return {"malicious_hits": malicious, "high_quality_hits": high_quality}


class AutonomousSOCAnalyst:
    def __init__(self, oracle: OracleStore | None = None,
                 asset_policy: AssetPolicy | None = None):
        self.oracle = oracle or OracleStore()
        self.asset_policy = asset_policy or AssetPolicy()

    def assess(self, report, *, alerts: Iterable[Any] = (),
               evidence_graph: Any = None) -> Dict[str, Any]:
        warnings: List[str] = []
        alerts = list(alerts)
        hypotheses = list(getattr(report, "hypotheses", []) or [])
        quality_confirmed = []
        calibrated = []
        for item in hypotheses:
            raw = getattr(item, "numeric_confidence", None)
            if raw is None:
                raw = _CONF.get(str(getattr(item, "confidence_after", None) or
                                    getattr(item, "confidence", "low")).lower(), .3)
            value = self.oracle.calibrate(str(getattr(item, "name", "hypothesis")), float(raw))
            item.calibrated_confidence = value
            calibrated.append({"hypothesis": item.name, "raw": round(float(raw), 4),
                               "calibrated": value,
                               "critic_approved": getattr(item, "critic_approved", None)})
            approved = getattr(item, "critic_approved", None)
            if item.verdict == "confirmed" and approved is not False and value >= .6:
                quality_confirmed.append(item)
        unresolved = [item for item in hypotheses
                      if item.verdict in (None, "weakened", "inconclusive")]
        graph = (evidence_graph.as_dict() if hasattr(evidence_graph, "as_dict")
                 else (evidence_graph or {}))
        claims = [node for node in graph.get("nodes", []) if node.get("kind") == "claim"]
        grounded = [node for node in claims if node.get("grounded")]
        coverage = round(len(grounded) / len(claims), 2) if claims else None

        max_severity = max((_severity(getattr(item, "severity", ""), warnings)
                            for item in alerts), default=0)
        conclusion = getattr(report, "conclusion", {}) or {}
        intel = _intel_strength(conclusion.get("threat_intel", {}))
        affected_hosts: List[str] = []
        for host in conclusion.get("suspect_hosts", []) or []:
            value = host.get("ip") if isinstance(host, dict) else host
            if value and str(value) not in affected_hosts:
                affected_hosts.append(str(value))
        assets = [self.asset_policy.classify(host) for host in affected_hosts]
        materiality = max((row["materiality"] for row in assets), default=.0)

        if max_severity >= 4 or len(quality_confirmed) >= 2 or (
                intel["high_quality_hits"] and quality_confirmed) or (
                materiality >= .75 and quality_confirmed):
            priority = "P1"
        elif max_severity >= 3 or quality_confirmed or intel["high_quality_hits"]:
            priority = "P2"
        elif alerts or hypotheses or intel["malicious_hits"]:
            priority = "P3"
        else:
            priority = "P4"

        if quality_confirmed and coverage is not None and coverage >= .5:
            disposition = "confirmed_incident"
        elif quality_confirmed or alerts:
            disposition = "suspicious_activity"
        elif hypotheses:
            disposition = "insufficient_evidence"
        else:
            disposition = "no_actionable_finding"

        iocs = []
        for raw in conclusion.get("iocs", []) or []:
            value = _normalize_ioc(raw.get("value") if isinstance(raw, dict) else raw)
            if value and value not in iocs:
                iocs.append(value)

        techniques = conclusion.get("mitre_techniques", []) or []
        actions = [{"action": "Preserve capture hash, evidence graph, and related telemetry",
                    "tier": "local_reversible", "approval_required": False}]
        if affected_hosts:
            actions.append({"action": "Collect EDR process, connection, logon, and persistence evidence for " + ", ".join(affected_hosts),
                            "tier": "local_reversible", "approval_required": False})
        for projection in adversary_projection(techniques):
            actions.append({"action": projection["hunt"], "tier": "local_reversible",
                            "approval_required": False})
        if affected_hosts and disposition == "confirmed_incident":
            actions.append({"action": "Isolate affected hosts: " + ", ".join(affected_hosts),
                            "tier": "approval_gated", "approval_required": True})
        if iocs and intel["high_quality_hits"]:
            actions.append({"action": "Block independently validated IOCs: " + ", ".join(iocs[:10]),
                            "tier": "approval_gated", "approval_required": True})
        if priority in ("P1", "P2"):
            actions.append({"action": "Escalate the evidence-backed case to the incident response lead",
                            "tier": "approval_gated", "approval_required": True})

        review_reasons = []
        if any(getattr(item, "critic_approved", None) is False for item in hypotheses):
            review_reasons.append("critic rejected at least one hypothesis")
        if coverage is not None and coverage < .6:
            review_reasons.append("grounded evidence coverage below 60%")
        if unresolved and priority in ("P1", "P2"):
            review_reasons.append("high-priority case has unresolved hypotheses")
        if warnings:
            review_reasons.append("input normalization produced warnings")

        return {
            "mode": "autonomous-soc-analyst", "priority": priority,
            "disposition": disposition, "evidence_coverage": coverage,
            "evidence_graph_present": bool(claims),
            "confirmed_hypotheses": len(quality_confirmed),
            "unresolved_hypotheses": len(unresolved), "confidence": calibrated,
            "affected_hosts": affected_hosts, "asset_materiality": assets,
            "iocs": iocs, "threat_intel_quality": intel,
            "adversary_projection": adversary_projection(techniques),
            "recommended_actions": actions,
            "human_review_required": bool(review_reasons),
            "human_review_reasons": review_reasons, "warnings": warnings,
            "automation_boundary": ("Local evidence collection, tagging, watchlists, and snapshots may run with expiry; "
                                    "containment, blocking, identity changes, notifications, and external changes require approval."),
        }
