"""
report_commands.py — `report` / `anomalies` / `timeline` shell verbs.

The USP (CONTEXT.md §14): turn a raw PCAP into a narrative the way a
senior SOC analyst would after 10 minutes with it.

    anomalies            — ranked anomaly list (deterministic, no LLM)
    timeline             — compressed behavioral timeline (deterministic)
    report [--json] [--mitre] [--force] — detectors → narrative → LLM synthesis

`report` runs the confidence gate (§15.4): when max anomaly score < 0.4 AND
fewer than 2 anomalies, the LLM call is skipped and a structured skip message
is printed instead. `--force` overrides the gate. Every invocation (including
gate skips) is logged to ~/.easyshark/llm_calls.jsonl.
"""
from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from main import RESET, DIM, YELLOW, WHITE, BRIGHT_GREEN, BRIGHT_CYAN, _box
from .formatter import OutputFormatter

logger = logging.getLogger(__name__)

LOG_PATH = Path.home() / ".easyshark" / "llm_calls.jsonl"

MAX_SCORE_THRESHOLD = 0.4      # §15.4 confidence gate
ANOMALY_COUNT_THRESHOLD = 2

BAR = "═" * 67


def _log_call(row: Dict[str, Any]) -> None:
    """Append one JSONL row per report invocation (schema §15.6)."""
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, default=str) + "\n")
    except Exception as exc:
        logger.debug("llm_calls log failed: %s", exc)


class ReportCommandHandler:
    """Mirrors cli.commands.CommandHandler interface."""

    def __init__(self, shell):
        self.shell = shell
        self.fmt = OutputFormatter()

    # ------------------------------------------------------------------ #
    # Entry                                                              #
    # ------------------------------------------------------------------ #
    def handle(self, line: str) -> Optional[str]:
        line = line.strip()
        if not line:
            return None
        parts = line.split(None, 1)
        verb = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""
        if verb == "anomalies":
            return self.cmd_anomalies(arg)
        if verb == "timeline":
            return self.cmd_timeline(arg)
        if verb in ("report", "analyze-auto"):
            return self.cmd_report(arg)
        return self.fmt.error(f"unknown command: {verb}")

    # ------------------------------------------------------------------ #
    # Shared facts                                                        #
    # ------------------------------------------------------------------ #
    def _facts(self):
        packets = self.shell.get_packets()
        flows = self.shell.flow_engine.get_all_flows()
        alerts: List[Any] = []
        for rule in self.shell.rules:
            alerts.extend(rule.get_alerts())
        from core.detectors import run_all
        anomalies = run_all(packets, flows)
        return packets, flows, alerts, anomalies

    def _basename(self) -> str:
        name = getattr(self.shell, "pcap_file", "") or ""
        return Path(name).name

    # ------------------------------------------------------------------ #
    # anomalies — deterministic, no LLM                                  #
    # ------------------------------------------------------------------ #
    def cmd_anomalies(self, arg: str) -> str:
        packets, flows, alerts, anomalies = self._facts()
        lines = [
            f"ANOMALY REPORT — {self._basename()}",
            BAR,
        ]
        if not anomalies:
            lines += ["", "  (no anomalies detected)", "",
                      f"{BAR}",
                      f"0 anomalies | run `report` for LLM synthesis"]
            return "\n".join(lines)
        for i, a in enumerate(anomalies[:10], 1):
            lines += [
                f"{i}. [{a.score:.2f}] {a.type}  {a.hosts[0] if a.hosts else '?'} -> {a.remote}",
                f"   evidence: {a.evidence}",
                f"   threshold: max_score >= {MAX_SCORE_THRESHOLD:.2f}",
                f"   hosts:     {', '.join(a.hosts) if a.hosts else '(none)'}",
            ]
            if a.packets:
                shown = a.packets[:5]
                lines.append(f"   packets:   {len(a.packets)} matched (showing first 5)")
                lines.append(f"   indices:   {', '.join(map(str, shown))}")
                wf = " or ".join(f"frame.number=={p + 1}" for p in shown)
                lines.append(f"   Wireshark: {wf}")
            else:
                lines.append("   packets:   (not recorded)")
            lines.append("─" * 67)
        lines += [
            f"{len(anomalies)} anomalies | highest score: "
            f"{anomalies[0].score:.2f} | run `report` for LLM synthesis",
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    # timeline — deterministic, no LLM                                    #
    # ------------------------------------------------------------------ #
    def cmd_timeline(self, arg: str) -> str:
        packets, flows, alerts, anomalies = self._facts()
        from core.narrative import build
        narrative = build(packets, flows, alerts, anomalies, max_chars=14_000)
        # Extract only the BEHAVIORAL EVENTS section.
        try:
            start = narrative.index("BEHAVIORAL EVENTS")
            stop = narrative.index("ANOMALIES RANKED")
            section = narrative[start:stop].rstrip()
        except ValueError:
            section = "BEHAVIORAL EVENTS\n  (none)\n"
        return "\n".join([
            f"TIMELINE — {self._basename()}",
            BAR,
            "",
            section,
            "",
            BAR,
            f"run `anomalies` for ranked findings, `report` for LLM synthesis",
        ])

    # ------------------------------------------------------------------ #
    # report — full USP pipeline (detectors → narrative → LLM)            #
    # ------------------------------------------------------------------ #
    def cmd_report(self, arg: str) -> str:
        as_json = "--json" in arg
        as_mitre = "--mitre" in arg
        force = "--force" in arg
        packets, flows, alerts, anomalies = self._facts()

        from core.narrative import build
        narrative = build(packets, flows, alerts, anomalies, max_chars=14_000)

        max_score = anomalies[0].score if anomalies else 0.0
        count = len(anomalies)
        gate_skipped = not force and max_score < MAX_SCORE_THRESHOLD and count < ANOMALY_COUNT_THRESHOLD

        start_ms = time.time()
        payload: Dict[str, Any] = {}
        llm_model = None
        parse_error = False

        if gate_skipped:
            body = self._gate_skip_message(anomalies, max_score)
            # Anomaly count needs packet/duration context; keep it simple.
            _log_call({
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "pcap": self._basename(),
                "anomaly_count": count,
                "max_score": round(max_score, 3),
                "narrative_chars": len(narrative),
                "llm_model": None,
                "response_ms": 0,
                "parse_error": False,
                "ioc_count": 0,
                "confidence": None,
                "gate_skipped": True,
            })
            return body

        # ---- LLM synthesis (single completion, no tool loop) ---------- #
        if getattr(self.shell, "llm_client", None) is None or \
                not self.shell.llm_client.is_available():
            payload = self._fallback_report(anomalies)
            _log_call({
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "pcap": self._basename(),
                "anomaly_count": count,
                "max_score": round(max_score, 3),
                "narrative_chars": len(narrative),
                "llm_model": None,
                "response_ms": 0,
                "parse_error": True,
                "ioc_count": len(payload.get("iocs") or []),
                "confidence": payload.get("confidence_overall"),
                "gate_skipped": False,
            })
            if as_json:
                return json.dumps(payload, indent=2, default=str)
            return self._render_report(payload, anomalies, 0, True, as_mitre)

        from ai.investigator import _single_completion, _extract_json_obj, CONCLUSION_SYSTEM_PROMPT
        user = (f"=== CAPTURE SUMMARY ===\n{narrative}\n\n"
                f"Produce the final incident report.")
        raw = _single_completion(
            self.shell.llm_client, CONCLUSION_SYSTEM_PROMPT, user,
            model_type="explainer", max_tokens=1500,
        )
        response_ms = int((time.time() - start_ms) * 1000)
        if raw:
            payload = _extract_json_obj(raw) or {}
            if not payload:
                parse_error = True
            llm_model = getattr(self.shell.llm_client, "model_name", None)
            if llm_model is None:
                llm_model = getattr(self.shell.llm_client, "explainer_model", None)

        if not payload:
            payload = self._fallback_report(anomalies)

        if as_json:
            return json.dumps(payload, indent=2, default=str)

        iocs = payload.get("iocs") or []
        self.shell.last_iocs = list(iocs)
        _log_call({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "pcap": self._basename(),
            "anomaly_count": count,
            "max_score": round(max_score, 3),
            "narrative_chars": len(narrative),
            "llm_model": llm_model,
            "response_ms": response_ms,
            "parse_error": parse_error,
            "ioc_count": len(iocs),
            "confidence": payload.get("confidence_overall"),
            "gate_skipped": False,
        })
        return self._render_report(payload, anomalies, response_ms, parse_error, as_mitre)

    # ------------------------------------------------------------------ #
    # Render                                                              #
    # ------------------------------------------------------------------ #
    def _gate_skip_message(self, anomalies, max_score) -> str:
        count = len(anomalies)
        lines = [
            BAR,
            "LLM SKIPPED — confidence gate not met",
            BAR,
            "",
            f"  Anomalies        : {count}",
            f"  Highest score    : {max_score:.2f}" if anomalies else "  Highest score    : (no anomalies)",
            f"  Threshold        : max_score >= {MAX_SCORE_THRESHOLD:.2f} OR count >= {ANOMALY_COUNT_THRESHOLD}",
            "",
            "  No LLM call was made — the capture does not meet the threshold",
            "  for an interesting narrative. Use `anomalies` to inspect",
            "  detector output, or run `report --force` to override the gate.",
            "",
            BAR,
        ]
        return "\n".join(lines)

    def _fallback_report(self, anomalies) -> Dict[str, Any]:
        iocs: List[str] = []
        for a in anomalies:
            if a.hosts:
                for h in a.hosts[:1]:
                    if h not in iocs:
                        iocs.append(h)
            if a.remote and "->" not in a.remote:
                host = a.remote.split(":")[0]
                if host and host not in iocs:
                    iocs.append(host)
        return {
            "incident_narrative": (
                "Deterministic fallback (LLM synthesis failed). "
                f"{len(anomalies)} anomalies detected; see `anomalies` for "
                "ranked evidence and packet drill-down."
            ),
            "suspect_hosts": [
                {"ip": h, "confidence": "medium",
                 "evidence": [a.type for a in anomalies if h in a.hosts],
                 "likely_role": "suspect"}
                for h in dict.fromkeys(h for a in anomalies for h in a.hosts)
            ],
            "mitre_techniques": [],
            "iocs": iocs,
            "next_steps": ["Inspect `anomalies` drill-down (packet indices + Wireshark filters)."],
            "confidence_overall": "low",
            "analyst_summary": "Deterministic fallback — LLM synthesis failed.",
        }

    def _render_report(self, payload, anomalies, response_ms, parse_error, as_mitre=False) -> str:
        lines = [
            BAR,
            "INCIDENT REPORT",
            BAR,
            "",
            "INCIDENT SUMMARY",
            "─" * 67,
            "",
            payload.get("incident_narrative") or "(no narrative)",
            "",
        ]
        if as_mitre:
            mitre = payload.get("mitre_techniques") or []
            if not mitre:
                lines += [
                    "MITRE ATT&CK",
                    "─" * 67,
                    "",
                    "  (none mapped — LLM synthesis unavailable)",
                    "",
                ]
            else:
                lines += ["MITRE ATT&CK", "─" * 67, ""]
                for m in mitre:
                    tid = m.get("id", "?")
                    tname = m.get("technique", "?")
                    ev = m.get("evidence", "")
                    lines.append(f"  {tid}  {tname}")
                    if ev:
                        lines.append(f"          evidence: {ev}")
                lines.append("")
        else:
            suspects = payload.get("suspect_hosts") or []
            if suspects:
                lines += ["SUSPECT HOSTS", "─" * 67, ""]
                for s in suspects:
                    conf = (s.get("confidence") or "?").upper()
                    role = s.get("likely_role") or ""
                    lines.append(f"  [{conf:>4}]  {s.get('ip', '?')}"
                                 + (f"  — {role}" if role else ""))
                    for ev in (s.get("evidence") or [])[:4]:
                        lines.append(f"           - {ev}")
                lines.append("")
            mitre = payload.get("mitre_techniques") or []
            if mitre:
                lines += ["MITRE ATT&CK", "─" * 67, ""]
                for m in mitre:
                    tid = m.get("id", "?")
                    tname = m.get("technique", "?")
                    ev = m.get("evidence", "")
                    lines.append(f"  {tid}  {tname}")
                    if ev:
                        lines.append(f"          evidence: {ev}")
                lines.append("")
            iocs = payload.get("iocs") or []
            if iocs:
                lines += ["IOCs", "─" * 67, ""]
                for i in iocs:
                    lines.append(f"  {i}")
                lines.append("")
            steps = payload.get("next_steps") or []
            if steps:
                lines += ["NEXT STEPS", "─" * 67, ""]
                for i, st in enumerate(steps, 1):
                    lines.append(f"  {i}. {st}")
                lines.append("")
        lines += [
            f"Confidence: {(payload.get('confidence_overall') or '?').upper()}",
            f"Anomalies: {len(anomalies)} (max {anomalies[0].score:.2f})"
            if anomalies else "Anomalies: 0",
            f"LLM response: {response_ms} ms" + (" (parse failed — fallback shown)" if parse_error else ""),
            BAR,
        ]
        return "\n".join(lines)
