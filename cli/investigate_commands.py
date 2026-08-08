"""
investigate_commands.py — `investigate` shell verb (CONTEXT.md §16, Task 2;
Phase 9 §9.4 multi-agent DAG).

Two investigation engines:
    investigate [question] [--auto]   — planner → executor → critic DAG
    investigate --linear [--auto]     — old linear investigator.py (debug)

Flags:
    --auto      skip all interactive prompts (scripted runs)
    --linear    bypass the DAG and use ai.investigator.investigate

The final report reuses the auto_analyst conclusion schema + renderer.
"""
from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from main import RESET, BOLD, DIM, CYAN, BRIGHT_CYAN, BRIGHT_GREEN, YELLOW, WHITE, _box
from .formatter import OutputFormatter
from ai.investigator import (
    investigate,
    InvestigationReport,
    Hypothesis,
    CONCLUSION_SYSTEM_PROMPT,
    _single_completion,
    _extract_json_obj,
    _fallback_conclusion,
)

logger = logging.getLogger(__name__)


REPORTS_DIR = Path.home() / ".easyshark" / "reports"


# --------------------------------------------------------------------------- #
# Handler                                                                      #
# --------------------------------------------------------------------------- #
class InvestigateCommandHandler:
    """Mirrors cli.commands.CommandHandler interface."""

    def __init__(self, shell):
        self.shell = shell
        self.fmt = OutputFormatter()

    def handle(self, line: str) -> Optional[str]:
        line = line.strip()
        if not line:
            return None
        parts = line.split(None, 1)
        verb = parts[0].lower()
        if verb != "investigate":
            return self.fmt.error(f"unknown command: {verb}")
        arg = (parts[1] if len(parts) > 1 else "").strip()
        auto = "--auto" in arg
        linear = "--linear" in arg
        question = " ".join(
            tok for tok in arg.split() if tok not in ("--auto", "--linear")
        )
        if not question:
            question = "Analyze the suspicious activity in this capture."
        try:
            self.shell._ensure_llm_client()
        except Exception:
            pass
        if getattr(self.shell, "llm_client", None) is None or \
                not self.shell.llm_client.is_available():
            return ("LLM client unavailable. Cannot run investigation.\n"
                    "  Start Ollama:  ollama serve")

        # ---- Live activity status on stderr (cli/status.py) ----------- #
        from cli.status import status, status_finish
        if hasattr(self.shell.llm_client, "set_status_callback"):
            self.shell.llm_client.set_status_callback(status)

        if linear:
            try:
                return self._run_linear(auto=auto, header_line=(
                    "INVESTIGATION  (linear hypothesis → verify → conclude)  [--linear]"))
            finally:
                status_finish("investigation complete")
        try:
            return self._run_dag(auto=auto, question=question)
        finally:
            status_finish("investigation complete")

    # ------------------------------------------------------------------ #
    # Linear path (debug / regression) — Phase 9 §9.4 --linear flag       #
    # ------------------------------------------------------------------ #
    def _run_linear(self, auto: bool,
                    header_line: str = "INVESTIGATION  (agentic hypothesis → verify → conclude)") -> str:
        out: List[str] = []
        out.append("═" * 67)
        out.append(header_line)
        out.append("═" * 67)
        out.append("")

        def emit(event: str, payload: Dict[str, Any]):
            """Print progress to stdout during the loop."""
            if event == "narrative_ready":
                from cli.status import status
                status("investigate", f"narrative ({payload['narrative_chars']} chars)")
                out.append(f"  narrative built ({payload['narrative_chars']} chars, "
                           f"{payload['anomaly_count']} anomalies)")
            elif event == "hypotheses_ready":
                out.append(f"  generated {payload['count']} hypotheses:")
                for n in payload["names"]:
                    out.append(f"    - {n}")
                out.append("")
            elif event == "hypothesis_start":
                from cli.status import status
                status("investigate",
                       f"hypothesis {payload['index']}/{payload['total']} · "
                       f"{payload['name'][:40]}")
                idx, total = payload["index"], payload["total"]
                out.append("─" * 67)
                out.append(f"HYPOTHESIS {idx}/{total}  [confidence: {payload['confidence'].upper()}]")
                out.append(f"{payload['name']}")
                out.append(f"{payload['description']}")
                out.append("")
                out.append("Supporting evidence:")
                for ev in payload["supporting_evidence"][:3]:
                    out.append(f"  → {ev}")
                if payload["verification_plan"]:
                    out.append("")
                    out.append("Verification plan:")
                    for plan in payload["verification_plan"][:3]:
                        out.append(f"  → {plan}")
                out.append("")
                # Interactive prompt unless --auto.
                if not auto:
                    out.append("Verify this hypothesis? [y/n/skip all]:")
                    response = input("> ").strip().lower()
                    out.append(f"> {response}")
                    if response in ("skip all", "skip", "s"):
                        # Cascade-skip remaining.
                        payload["_skip_remaining"] = True
                    elif response not in ("y", "yes"):
                        # User declined — mark as pending/ruled_out.
                        payload["_skip_this"] = True
                    out.append("")
            elif event == "hypothesis_verdict":
                from cli.status import status
                verdict = (payload.get("verdict") or "?").upper()
                conf = (payload.get("confidence_after") or "?").upper()
                status("investigate",
                       f"verdict {verdict} · {payload.get('name','')[:40]}")
                out.append("─" * 67)
                out.append(f"VERDICT: {verdict}  [confidence: {conf}]")
                if payload.get("evidence_found"):
                    out.append("Evidence found:")
                    for ev in payload["evidence_found"][:4]:
                        out.append(f"  → {ev}")
                if payload.get("reasoning"):
                    out.append(f"Reasoning: {payload['reasoning']}")
                out.append("")
                if not auto:
                    out.append("Continue to next hypothesis? [y/n]:")
                    response = input("> ").strip().lower()
                    out.append(f"> {response}")
                    if response not in ("y", "yes"):
                        payload["_halt_loop"] = True
                    out.append("")

        # Wrap emit() to short-circuit on skip/halt flags during run.
        state = {"skip_remaining": False, "halt": False}

        def emit_wrapped(event: str, payload: Dict[str, Any]):
            if state["skip_remaining"] or state["halt"]:
                return
            emit(event, payload)
            if payload.get("_skip_remaining"):
                state["skip_remaining"] = True
                return
            if payload.get("_skip_this"):
                # Inject synthetic verdict.
                # We can't modify payload here — just append a marker
                # that the post-loop emitter can act on. Since the
                # investigator runs synchronously, we instead mark the
                # current hypothesis as ruled_out via a small monkey-patch:
                # we set a sentinel on the most-recent hypothesis.
                pass
            if payload.get("_halt_loop"):
                state["halt"] = True

        report = investigate(self.shell, on_event=emit_wrapped)

        # In interactive skip-this path, post-process: convert declines
        # into ruled_out entries. (Best-effort: mark the most recent
        # pending hypothesis as ruled_out if its verdict is None.)
        for h in report.hypotheses:
            if h.verdict is None:
                h.verdict = "ruled_out"
                h.confidence_after = "low"
                h.reasoning = "(analyst declined to verify)"

        out.append("═" * 67)
        out.append("INVESTIGATION COMPLETE")
        out.append("═" * 67)
        out.append("")
        for h in report.hypotheses:
            verdict = (h.verdict or "?").upper()
            conf = (h.confidence_after or h.confidence).upper()
            tag = f"[{verdict}]"
            out.append(f"  {tag:<14}  {h.name:<32}  confidence: {conf}")
        out.append("")
        out.append(f"  elapsed: {report.elapsed_sec:.1f}s, "
                   f"LLM calls: {report.llm_calls}")

        # ---- Final report (reuse auto_analyst schema + renderer) ----- #
        out.append("")
        out.append("─" * 67)
        out.append("FINAL INCIDENT REPORT")
        out.append("─" * 67)
        out.append("")
        out.append(_render_conclusion(report.conclusion))

        # Save prompt.
        if not auto:
            out.append("")
            out.append("─" * 67)
            out.append("Save this report? [y/n]:")
            try:
                response = input("> ").strip().lower()
            except EOFError:
                response = "n"
            out.append(f"> {response}")
            if response in ("y", "yes"):
                try:
                    path = _save_report(report, self.shell.pcap_file)
                    out.append(f"Report saved to {path}")
                except Exception as exc:
                    out.append(f"Save failed: {exc}")

        return "\n".join(out)

    # ------------------------------------------------------------------ #
    # DAG path — Phase 9 §9.4                                             #
    # planner -> dag_runner (executor + critic) -> synthesis -> annotate  #
    # ------------------------------------------------------------------ #
    def _run_dag(self, auto: bool, question: str) -> str:
        from ai.planner import HypothesisPlanner
        from ai.dag_runner import DagRunner
        from ai.tool_registry import ToolContext

        out: List[str] = []
        out.append("═" * 67)
        out.append("INVESTIGATION  (planner → executor → critic DAG)")
        out.append("═" * 67)
        out.append("")

        llm = self.shell.llm_client
        packets = self.shell.get_packets()
        flows = self.shell.flow_engine.get_all_flows()
        alerts: List[Any] = []
        for r in self.shell.rules:
            alerts.extend(r.get_alerts())
        from core.detectors import run_all
        from core.narrative import build
        anomalies = run_all(packets, flows)
        narrative = build(packets, flows, alerts, anomalies)

        out.append(f"  narrative built ({len(narrative)} chars, "
                   f"{len(anomalies)} anomalies)")
        out.append("")

        # -------------------------------------------------------------- #
        # Planner (small/fast role). Planner failure -> linear fallback.  #
        # -------------------------------------------------------------- #
        planner_calls = 0
        planner = HypothesisPlanner(llm)
        try:
            # Phase 11 §11.1 — suggest tools learned from prior
            # critic-approved investigations (best-effort, never blocks).
            learned_hint = None
            try:
                from ai.pattern_learner import suggest_tools
                learned_hint = suggest_tools(question)
            except Exception as exc:
                logger.debug("pattern_learner.suggest_tools failed: %s", exc)
            plan_items = planner.plan(
                question=question, triage=self.shell.triage,
                alerts=alerts, anomalies=anomalies, narrative=narrative,
                tools_hint=learned_hint,
            )
            planner_calls = 1 if (llm is not None
                                  and llm.is_available()) else 0
        except Exception as exc:
            logger.warning("Planner failed: %s", exc)
            plan_items = None
        if not plan_items:
            out.append("  planner produced no usable plan — "
                       "falling back to linear investigation")
            linear_out = self._run_linear(auto=auto, header_line=(
                "INVESTIGATION  (linear fallback — planner failed)"))
            return "\n".join(out) + "\n" + linear_out

        out.append(f"Planning investigation... [{len(plan_items)} hypotheses]")
        for item in plan_items:
            deps = (f"  (after {', '.join(item['depends_on'])})"
                    if item.get("depends_on") else "")
            out.append(f"    {item['id']}: {item['hypothesis']}{deps}")
        out.append("")

        # -------------------------------------------------------------- #
        # DAG execution                                                   #
        # -------------------------------------------------------------- #
        ctx = ToolContext(packets=packets, flows=flows, alerts=alerts,
                          stats_engine=getattr(self.shell, "stats_engine", None),
                          flow_engine=getattr(self.shell, "flow_engine", None),
                          pcap_path=getattr(self.shell, "pcap_file", None),
                          triage=getattr(self.shell, "triage", None),
                          dissection=getattr(self.shell, "dissection", None))
        runner = DagRunner(llm_client=llm)
        status_line: Dict[str, str] = {}

        def emit(event: str, payload: Dict[str, Any]):
            if event == "hypothesis_start":
                from cli.status import status
                status("investigate",
                       f"hypothesis {payload['id']} · {payload['name'][:40]}")
                line = (CYAN + f"  {payload['id']}: "
                        f"{payload['name'][:58]} ..." + RESET)
                status_line[payload["id"]] = line
                out.append(line)
            elif event == "tools_used":
                out.append(DIM + f"      tools: {', '.join(payload['tools'])}" + RESET)
            elif event == "hypothesis_verdict":
                colour_map = {"confirmed": BRIGHT_GREEN, "weakened": DIM,
                              "ruled_out": YELLOW, "inconclusive": DIM}
                c = colour_map.get(payload["verdict"], WHITE)
                mark_map = {"confirmed": "✓", "weakened": "~",
                            "ruled_out": "✗", "inconclusive": "?"}
                mark = mark_map.get(payload["verdict"], "?")
                line = (c + f"      {mark} {payload['verdict'].upper():<12} "
                        f"confidence={payload['confidence']:.2f}" + RESET)
                if payload.get("critic_issues"):
                    line += (DIM + "  [critic: "
                             + "; ".join(payload["critic_issues"][:2]) + "]" + RESET)
                out.append(line)
                prev = status_line.get(payload["id"])
                if prev is not None:
                    try:
                        i = out.index(prev)
                        out[i] = prev + c + f"  {mark}" + RESET
                    except ValueError:
                        pass
            elif event == "hypothesis_backtrack":
                # Gap 3 — the DAG is retrying an inconclusive hypothesis with
                # a narrowed-evidence prompt. Surface it so the analyst knows
                # the "?" is being re-investigated, not dropped.
                out.append(DIM +
                           f"      ⟲ inconclusive (conf={payload['confidence']:.2f}) "
                           f"— retrying with narrowed evidence..." + RESET)

        dag = runner.run(plan_items, ctx, on_event=emit)

        # Phase 11 §11.1 — merge the just-persisted critic-approved verdicts
        # into the pattern store on a background thread (non-blocking).
        try:
            from ai.pattern_learner import learn_in_background
            learn_in_background()
        except Exception as exc:
            logger.debug("pattern_learner background failed: %s", exc)

        # Phase 11 §11.2 — weekly reasoning-pattern distillation (gated by
        # the weekly timestamp + the OpenRouter budget). Best-effort; never
        # blocks or fails the investigation.
        try:
            from ai.prompt_distiller import maybe_distill
            if llm is not None:
                maybe_distill(llm, force=False)
        except Exception as exc:
            logger.debug("prompt_distiller skipped: %s", exc)

        out.append("")
        out.append("─" * 67)
        out.append("DAG RESULTS")
        out.append("─" * 67)
        for h in dag.hypotheses:
            mark = {"confirmed": "✓", "weakened": "~",
                    "ruled_out": "✗", "inconclusive": "?"}.get(h.verdict, "?")
            tag = (f"[{h.verdict.upper()}]" if h.verdict != "inconclusive"
                   else "[?]")
            out.append(f"  {tag:<10}  {h.short_label():<52} "
                       f"conf={h.confidence:.2f} {mark}")
        out.append("")

        # -------------------------------------------------------------- #
        # Synthesis (conclusion) — reuse the auto_analyst schema.         #
        # -------------------------------------------------------------- #
        verdicts_text = "\n".join(
            f"- [{h.verdict}] {h.hypothesis} (confidence: {h.confidence:.2f})\n"
            f"    Evidence: {'; '.join(h.evidence) if h.evidence else '(none)'}\n"
            f"    Reasoning: {h.reasoning or '(none)'}"
            for h in dag.hypotheses
        )
        conclusion_user = (
            f"=== ORIGINAL CAPTURE SUMMARY ===\n{narrative}\n\n"
            f"=== VERIFIED HYPOTHESES (DAG) ===\n{verdicts_text}\n\n"
            f"Produce the final incident report."
        )
        synthesis_calls = 0
        conclusion: Dict[str, Any] = {}
        raw = _single_completion(
            llm, CONCLUSION_SYSTEM_PROMPT, conclusion_user, max_tokens=1500,
        )
        if raw:
            synthesis_calls = 1
            conclusion = _extract_json_obj(raw) or {}

        report = InvestigationReport(
            narrative=narrative,
            hypotheses=[
                Hypothesis(
                    name=h.hypothesis,
                    description="",
                    confidence=_conf_label(h.confidence),
                    verdict=None if h.verdict == "inconclusive" else h.verdict,
                    evidence_found=h.evidence,
                    confidence_after=_conf_label(h.confidence),
                    reasoning=h.reasoning,
                )
                for h in dag.hypotheses
            ],
            conclusion=conclusion,
            elapsed_sec=dag.elapsed_sec,
            llm_calls=planner_calls + dag.llm_calls + synthesis_calls,
        )
        if not report.conclusion:
            report.conclusion = _fallback_conclusion(report)

        out.append("─" * 67)
        out.append("INVESTIGATION COMPLETE")
        out.append("─" * 67)
        out.append("")
        for h in report.hypotheses:
            verdict = (h.verdict or "?").upper()
            conf = (h.confidence_after or h.confidence).upper()
            out.append(f"  [{verdict:<11}]  {h.name:<40}  confidence: {conf}")
        out.append("")
        out.append(f"  elapsed: {dag.elapsed_sec:.1f}s, "
                   f"LLM calls: {report.llm_calls} "
                   f"(planner {planner_calls} + exec {dag.executor_calls} "
                   f"+ critic {dag.critic_calls} + synthesis {synthesis_calls})")

        # ---- Final report (reuse auto_analyst schema + renderer) ----- #
        out.append("")
        out.append("─" * 67)
        out.append("FINAL INCIDENT REPORT")
        out.append("─" * 67)
        out.append("")
        out.append(_render_conclusion(report.conclusion))

        # Save prompt.
        if not auto:
            out.append("")
            out.append("─" * 67)
            out.append("Save this report? [y/n]:")
            try:
                response = input("> ").strip().lower()
            except EOFError:
                response = "n"
            out.append(f"> {response}")
            if response in ("y", "yes"):
                try:
                    path = _save_report(report, self.shell.pcap_file)
                    out.append(f"Report saved to {path}")
                except Exception as exc:
                    out.append(f"Save failed: {exc}")

        return "\n".join(out)


def _conf_label(confidence: float) -> str:
    if confidence >= 0.8:
        return "high"
    if confidence >= 0.5:
        return "medium"
    return "low"


# --------------------------------------------------------------------------- #
# Render conclusion.                                                           #
# --------------------------------------------------------------------------- #
def _render_conclusion(payload: Dict[str, Any]) -> str:
    bar = "═" * 67
    lines: List[str] = [bar]
    lines.append("INCIDENT SUMMARY")
    lines.append(bar)
    lines.append("")
    lines.append(payload.get("incident_narrative") or "(no narrative)")
    lines.append("")

    suspects = payload.get("suspect_hosts") or []
    if suspects:
        lines.append(bar)
        lines.append("SUSPECT HOSTS")
        lines.append(bar)
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
        lines.append(bar)
        lines.append("MITRE ATT&CK")
        lines.append(bar)
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
        lines.append(bar)
        lines.append("IOCs")
        lines.append(bar)
        for i in iocs:
            lines.append(f"  {i}")
        lines.append("")

    steps = payload.get("next_steps") or []
    if steps:
        lines.append(bar)
        lines.append("NEXT STEPS")
        lines.append(bar)
        for i, st in enumerate(steps, 1):
            lines.append(f"  {i}. {st}")
        lines.append("")

    lines.append(bar)
    lines.append(f"Confidence: {(payload.get('confidence_overall') or '?').upper()}    "
                 f"Verdict: {payload.get('analyst_summary') or '(none)'}")
    lines.append(bar)
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Report save                                                                 #
# --------------------------------------------------------------------------- #
def _save_report(report: InvestigationReport, pcap_path: str) -> str:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    base = os.path.basename(pcap_path)
    name = f"{base}_{ts}.json"
    out_path = REPORTS_DIR / name
    blob: Dict[str, Any] = {
        "pcap":           pcap_path,
        "timestamp":      ts,
        "elapsed_sec":    report.elapsed_sec,
        "llm_calls":      report.llm_calls,
        "hypotheses": [
            {
                "name":              h.name,
                "description":       h.description,
                "confidence":        h.confidence,
                "supporting_evidence": h.supporting_evidence,
                "verification_plan":   h.verification_plan,
                "verdict":           h.verdict,
                "evidence_found":    h.evidence_found,
                "confidence_after":  h.confidence_after,
                "reasoning":         h.reasoning,
            }
            for h in report.hypotheses
        ],
        "conclusion": report.conclusion,
    }
    out_path.write_text(json.dumps(blob, indent=2, default=str))
    return str(out_path)
