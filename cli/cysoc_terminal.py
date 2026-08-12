"""Nested SOC workspace over the existing EasyShark command handlers."""
from __future__ import annotations

import json
from typing import Callable, Optional


class CYSOCTerminal:
    """SOC-focused REPL. It delegates all real work to InteractiveShell."""

    def __init__(self, shell, input_fn: Optional[Callable[[str], str]] = None,
                 output_fn: Optional[Callable[[str], None]] = None,
                 store=None):
        self.shell = shell
        self.input = input_fn or input
        self.output = output_fn or print
        from .cysoc_commands import CYSOCCommandHandler
        self.operations = CYSOCCommandHandler(store)

    def run(self) -> None:
        from core.event_sink import event_bus
        payload = {
            "session": getattr(getattr(self.shell, "session", None), "key", None),
            "pcap": getattr(self.shell, "pcap_file", None),
        }
        event_bus.publish("cysoc_terminal_opened", payload)
        self.output("\nCYSOC TERMINAL  |  SOC investigation workspace")
        self.output("Type `help` for commands; `exit`, `back`, or `quit` returns to EasyShark.\n")
        try:
            while True:
                try:
                    line = self.input("cysoc > ").strip()
                except EOFError:
                    break
                except KeyboardInterrupt:
                    self.output("\nUse `exit` or `back` to return to EasyShark.")
                    continue
                if not line:
                    continue
                low = line.lower()
                if low in ("exit", "back", "quit", "main"):
                    break
                if low in ("help", "?"):
                    self.output(self.help_text())
                elif low in ("overview", "status", "dashboard"):
                    self.output(self.overview())
                elif low == "triage" or low.startswith("triage "):
                    mission = line[6:].strip() or "Triage and scope suspicious activity."
                    from cli.commands import CommandHandler
                    previous = set(CommandHandler._report_files())
                    self.shell._execute_command("soc-analyst " + mission)
                    current = CommandHandler._report_files()
                    report = next((path for path in current if path not in previous),
                                  current[0] if current else None)
                    if report is not None:
                        case_id = self.operations.store.ingest_easyshark_report(str(report))
                        self.output(f"SOC investigation registered as case {case_id}.")
                elif self.operations.owns(line):
                    self.output(self.operations.handle(line))
                else:
                    # Reuse the normal shell's routing, output, safety policy,
                    # session storage, and approval boundaries.
                    self.shell._execute_command(line)
        finally:
            event_bus.publish("cysoc_terminal_closed", payload)
            self.output("Returning to EasyShark shell.")

    def overview(self) -> str:
        packets = list(self.shell.get_packets())
        flows = list(self.shell.flow_engine.get_all_flows())
        alerts = []
        for rule in getattr(self.shell, "rules", []) or []:
            alerts.extend(rule.get_alerts())
        from cli.commands import CommandHandler
        from core.event_sink import event_bus
        reports = CommandHandler._report_files()
        pulse = self.operations.store.pulse()
        active_alerts = sum(pulse["alerts"].values())
        open_cases = sum(value for key, value in pulse["cases"].items()
                         if key not in ("closed", "resolved"))
        session = getattr(getattr(self.shell, "session", None), "key", "-")
        backend = "offline"
        llm = getattr(self.shell, "llm_client", None)
        if llm is not None and hasattr(llm, "backend"):
            backend = llm.backend()
        return "\n".join([
            "CYSOC OVERVIEW",
            f"  session: {session}",
            f"  capture: {getattr(self.shell, 'pcap_file', '-')}",
            f"  packets: {len(packets)}  flows: {len(flows)}  alerts: {len(alerts)}",
            f"  reports: {len(reports)}  events: {len(event_bus.history())}",
            f"  SOC store: active alerts={active_alerts}  open cases={open_cases}",
            f"  model backend: {backend}",
            "  response policy: containment and external changes require approval",
        ])

    def case_status(self) -> str:
        from cli.commands import CommandHandler
        reports = CommandHandler._report_files()
        if not reports:
            return "No SOC case report yet. Run `triage <mission>`."
        try:
            report = json.loads(reports[0].read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return f"Latest report could not be read: {exc}"
        assessment = (report.get("conclusion") or {}).get("soc_assessment")
        if not assessment:
            return (f"Latest report: {reports[0].name}\n"
                    "No SOC assessment present. Run `triage <mission>`.")
        return "\n".join([
            f"CASE  {reports[0].name}",
            f"  priority: {assessment.get('priority', '?')}",
            f"  disposition: {assessment.get('disposition', '?')}",
            (f"  evidence coverage: {assessment.get('evidence_coverage'):.0%}"
             if assessment.get('evidence_coverage') is not None
             else "  evidence coverage: not measured (no evidence graph claims)"),
            f"  affected hosts: {', '.join(assessment.get('affected_hosts') or []) or '(none)' }",
            f"  human review: {'required' if assessment.get('human_review_required') else 'not required'}",
            f"  recommended actions: {len(assessment.get('recommended_actions') or [])}",
        ])

    @staticmethod
    def help_text() -> str:
        return """CYSOC commands
  overview | pulse             Environment and security-operations status
  queue [p1,p2] [status=new]   Prioritized alert queue
  alert ack|close|false-positive|reopen <id>  Manage alert workflow
  ingest <json|jsonl> [source] Import SIEM, EDR, identity, DNS, or firewall data
  triage [mission]             Run autonomous SOC triage and save the case
  cases [status]               List SOC cases
  case <id>                    Case details, alerts, and response actions
  case create <P1-P4> <title>  Open a case
  case assign|status <id> ...  Manage ownership and workflow
  case note <id> <text>        Add an analyst note
  case link <id> <alert-id>    Link an alert to a case
  case timeline <id>           Complete case activity trace
  hunt <entity|text>           Global search across security data and cases
  correlate <entity>           Cross-source entity timeline
  fuse [entity]                Multi-sensor agreement in the active window
  detections                   Detection volume and false-positive health
  action request <case> <text> Create an approval-gated response request
  action approve|deny <id>     Record the response decision; never auto-executes
  connectors                   Data-source readiness and ingestion status
  connector pull <src> <url>   Pull an allow-listed HTTPS JSON endpoint
  autotriage [limit] [window]  Group unlinked alerts into cases
  benchmark generate <dir>     Generate labelled synthetic PCAP cases
  benchmark corpus <manifest>  Run deterministic corpus oracle and calibration
  oracle                       Precision, recall, Brier, and ECE status
  oracle rederive <report>     Deterministically re-check persisted claims
  rescore-intel <feed.json>    Apply delayed threat-intel oracle labels
  baseline observe|check ...   Learn/check per-entity time-bucket behavior
  similar <case|text>          Retrieve similar historical cases locally
  campaign list|build <case>   Link related cases into a campaign
  response local <case> <tag|watchlist|snapshot> <target> [ttl]
  response status [case]       Inspect active/reverted local response state
  anomalies | timeline        Fast deterministic findings
  analyze <question>           Natural-language forensic question
  investigate <question>      Multi-hypothesis investigation
  report                       Generate an incident report
  alerts | packets | flows     Network evidence and detections
  protocols | ips | dns       Protocol and host intelligence
  filter <expr> | search <re>  Locate packets and payload evidence
  dissect <n> | hex <n>       Inspect packet details
  follow tcp|udp <n>           Reassemble a conversation
  update-feeds [provider]      Refresh threat intelligence
  ioc-check <value>            Check an IOC
  events [limit]               Investigation and SOC audit events
  reports | evidence [index]   Saved cases and evidence graphs
  sessions | memory            Investigation continuity and learned knowledge
  capture ...                  Live-capture controls
  exit | back | quit           Return to the EasyShark shell"""
