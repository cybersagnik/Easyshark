"""Operational commands for the CYSOC analyst workspace."""
from __future__ import annotations

import json
import shlex
import time
from datetime import datetime
from typing import Any, Dict, Iterable, Optional

from core.soc_store import SOCStore


def _when(value: Any) -> str:
    try:
        return datetime.fromtimestamp(float(value)).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError):
        return "?"


class CYSOCCommandHandler:
    def __init__(self, store: Optional[SOCStore] = None):
        self.store = store or SOCStore()

    @staticmethod
    def owns(line: str) -> bool:
        verb = (line.strip().split(None, 1) or [""])[0].lower()
        return verb in {"pulse", "queue", "ingest", "cases", "case", "hunt",
                        "alert", "correlate", "detections", "action", "connector", "connectors",
                        "benchmark", "oracle", "baseline", "similar", "campaign", "response",
                        "rescore-intel", "fuse", "autotriage"}

    def handle(self, line: str) -> str:
        try:
            parts = shlex.split(line)
        except ValueError as exc:
            return f"Error: {exc}"
        if not parts:
            return ""
        verb, args = parts[0].lower(), parts[1:]
        try:
            if verb == "pulse":
                return self._pulse()
            if verb == "queue":
                return self._queue(args)
            if verb == "alert":
                return self._alert(args)
            if verb == "ingest":
                return self._ingest(args)
            if verb == "autotriage":
                return self._autotriage(args)
            if verb == "cases":
                return self._cases(args)
            if verb == "case":
                return self._case(args)
            if verb == "hunt":
                return self._hunt(args)
            if verb == "correlate":
                return self._correlate(args)
            if verb == "detections":
                return self._detections()
            if verb == "action":
                return self._action(args)
            if verb == "connectors":
                return self._connectors()
            if verb == "connector":
                return self._connector(args)
            if verb == "benchmark":
                return self._benchmark(args)
            if verb == "oracle":
                return self._oracle(args)
            if verb == "baseline":
                return self._baseline(args)
            if verb == "similar":
                return self._similar(args)
            if verb == "campaign":
                return self._campaign(args)
            if verb == "response":
                return self._response(args)
            if verb == "rescore-intel":
                return self._rescore_intel(args)
            if verb == "fuse":
                return self._fuse(args)
        except (OSError, ValueError) as exc:
            return f"Error: {exc}"
        return f"Unknown CYSOC command: {verb}"

    def _pulse(self) -> str:
        data = self.store.pulse()
        alerts = data["alerts"]
        cases = data["cases"]
        lines = ["CYSOC PULSE",
                 "  active alerts: " + ", ".join(
                     f"{name}={alerts.get(name, 0)}"
                     for name in ("critical", "high", "medium", "low")),
                 "  cases: " + (", ".join(f"{key}={value}" for key, value in cases.items())
                                or "none")]
        if data["hot_assets"]:
            lines.append("  hot assets: " + ", ".join(
                f"{row['asset']}({row['n']})" for row in data["hot_assets"]))
        lines.append("\nRECENT ALERTS")
        lines.extend(f"  [{row['severity'].upper():8}] {row['id']}  {row['title'][:70]}"
                     for row in data["recent_alerts"])
        if not data["recent_alerts"]:
            lines.append("  (none; use `ingest <json|jsonl> <source>`)")
        return "\n".join(lines)

    def _queue(self, args) -> str:
        priorities = []
        status = "new"
        for arg in args:
            if arg.lower().startswith("status="):
                status = arg.split("=", 1)[1]
            else:
                priorities.extend(item for item in arg.split(",") if item)
        rows = self.store.alert_queue(priorities, status=status)
        if not rows:
            return f"No {status} alerts in the selected queue."
        lines = [f"ALERT QUEUE  status={status}  count={len(rows)}"]
        lines.extend(
            f"  [{row['severity'].upper():8}] {row['id']:<30} "
            f"{row['asset'] or '-':<18} {row['title'][:65]}"
            for row in rows)
        return "\n".join(lines)

    def _alert(self, args) -> str:
        if len(args) != 2:
            return "Usage: alert ack|close|false-positive|reopen <alert-id>"
        statuses = {"ack": "acknowledged", "close": "closed",
                    "false-positive": "false_positive", "reopen": "new"}
        status = statuses.get(args[0].lower())
        if not status:
            return "Usage: alert ack|close|false-positive|reopen <alert-id>"
        self.store.update_alert(args[1], status)
        return f"Alert {args[1]} status changed to {status}."

    def _ingest(self, args) -> str:
        if not args:
            return "Usage: ingest <file.json|file.jsonl> [source]"
        result = self.store.ingest_file(
            args[0], source=args[1] if len(args) > 1 else "import",
            auto_triage=True)
        triage = result.get("triage") or {"created": 0, "linked": 0}
        return (f"Ingested {result['events']} new events and {result['alerts']} new alerts "
                f"from {args[1] if len(args) > 1 else 'import'}. "
                f"Auto-triage created {triage['created']} case(s) and linked "
                f"{triage['linked']} alert(s).")

    def _autotriage(self, args) -> str:
        if len(args) > 2:
            return "Usage: autotriage [limit] [window-seconds]"
        result = self.store.triage_alerts(
            int(args[0]) if args else 500,
            int(args[1]) if len(args) > 1 else 3600)
        return (f"AUTO-TRIAGE processed={result['processed']} linked={result['linked']} "
                f"created={result['created']} promoted={result['promoted']} "
                f"cases={len(result['cases'])}")

    def _cases(self, args) -> str:
        rows = self.store.cases(args[0] if args else None)
        if not rows:
            return "No SOC cases. Use `case create P2 <title>` or run `triage`."
        lines = [f"SOC CASES  count={len(rows)}"]
        lines.extend(f"  [{row['priority']}] {row['id']}  {row['status']:<10} "
                     f"{row['assignee'] or '-':<16} {row['title'][:70]}"
                     for row in rows)
        return "\n".join(lines)

    def _case(self, args) -> str:
        if not args:
            return self._cases([])
        action = args[0].lower()
        if action == "create":
            if len(args) < 3:
                return "Usage: case create <P1|P2|P3|P4> <title>"
            case_id = self.store.create_case(" ".join(args[2:]), args[1])
            return f"Created case {case_id}."
        if action in ("assign", "status", "priority", "disposition"):
            if len(args) < 3:
                return f"Usage: case {action} <case-id> <value>"
            field = "assignee" if action == "assign" else action
            self.store.update_case(args[1], field, " ".join(args[2:]))
            return f"Updated {args[1]}: {field}={ ' '.join(args[2:]) }."
        if action == "note":
            if len(args) < 3:
                return "Usage: case note <case-id> <note>"
            self.store.add_note(args[1], " ".join(args[2:]))
            return f"Note added to {args[1]}."
        if action == "link":
            if len(args) != 3:
                return "Usage: case link <case-id> <alert-id>"
            self.store.link_alert(args[1], args[2])
            return f"Linked {args[2]} to {args[1]}."
        if action == "timeline":
            if len(args) != 2:
                return "Usage: case timeline <case-id>"
            rows = self.store.timeline(args[1])
            if not rows:
                return "No timeline entries or case not found."
            return "\n".join([f"CASE TIMELINE  {args[1]}"] + [
                f"  {_when(row['event_ts'])}  {row['kind']:<18} "
                f"{row['actor']:<12} {row['message']}" for row in rows])
        row = self.store.case(args[0])
        if not row:
            return f"Case not found: {args[0]}"
        lines = [f"CASE {row['id']}  [{row['priority']}] {row['status']}",
                 f"  title: {row['title']}",
                 f"  disposition: {row['disposition'] or '(pending)'}",
                 f"  assignee: {row['assignee'] or '(unassigned)'}",
                 f"  linked alerts: {len(row['alerts'])}",
                 f"  response actions: {len(row['actions'])}"]
        if row["summary"]:
            lines.append(f"  summary: {row['summary'][:500]}")
        for item in row["actions"]:
            lines.append(f"  action #{item['id']} [{item['status']}] {item['action']}")
        return "\n".join(lines)

    def _hunt(self, args) -> str:
        if not args:
            return "Usage: hunt <IP|host|identity|IOC|text>"
        term = " ".join(args)
        result = self.store.hunt(term)
        lines = [f"GLOBAL HUNT  {term!r}",
                 f"  alerts={len(result['alerts'])} events={len(result['events'])} cases={len(result['cases'])}"]
        lines.extend(f"  alert {row['id']} [{row['severity']}] {row['title'][:80]}"
                     for row in result["alerts"][:20])
        lines.extend(f"  event {_when(row['event_ts'])} {row['source']} {row['summary'][:80]}"
                     for row in result["events"][:20])
        lines.extend(f"  case {row['id']} [{row['priority']}] {row['title'][:80]}"
                     for row in result["cases"][:20])
        return "\n".join(lines)

    def _correlate(self, args) -> str:
        if not args:
            return "Usage: correlate <asset|identity|IP|IOC>"
        entity = " ".join(args)
        rows = self.store.correlate(entity)
        if not rows:
            return f"No observations found for {entity}."
        lines = [f"CORRELATION  {entity}  observations={len(rows)}"]
        lines.extend(f"  {_when(row['event_ts'])} {row['source']:<14} "
                     f"{row['event_type']:<12} {row['summary'][:85]}" for row in rows)
        return "\n".join(lines)

    def _detections(self) -> str:
        rows = self.store.detection_health()
        if not rows:
            return "No detection telemetry."
        lines = ["DETECTION HEALTH"]
        for row in rows:
            rate = row["false_positives"] / row["alerts"] if row["alerts"] else 0
            lines.append(f"  {row['source']:<14} {row['rule_name'][:38]:<38} "
                         f"alerts={row['alerts']:<5} fp={rate:.0%} last={_when(row['last_seen'])}")
        return "\n".join(lines)

    def _action(self, args) -> str:
        if not args:
            return "Usage: action request <case-id> <action> | action approve|deny <id> [actor]"
        operation = args[0].lower()
        if operation == "request":
            if len(args) < 3:
                return "Usage: action request <case-id> <action>"
            action_id = self.store.request_action(args[1], " ".join(args[2:]))
            return (f"Response action #{action_id} is pending approval. "
                    "No external change was executed.")
        if operation in ("approve", "deny"):
            if len(args) < 2:
                return f"Usage: action {operation} <action-id> [approver]"
            decision = "approved" if operation == "approve" else "denied"
            self.store.decide_action(int(args[1]), decision,
                                     args[2] if len(args) > 2 else "approver")
            return (f"Action #{args[1]} {decision}. Approval is recorded; "
                    "execution still requires a configured response connector.")
        return "Usage: action request <case-id> <action> | action approve|deny <id> [actor]"

    def _connectors(self) -> str:
        rows = self.store.source_counts()
        lines = ["CONNECTORS",
                 "  file-import  ready  JSON/JSONL exports from SIEM, EDR, identity, DNS, firewall",
                 "  easyshark    ready  autonomous SOC reports",
                 "  https-json   ready  allow-listed read-only API ingestion"]
        lines.append("\nINGESTED SOURCES")
        lines.extend(f"  {row['source']:<20} events={row['events']:<7} last={_when(row['last_seen'])}"
                     for row in rows)
        if not rows:
            lines.append("  (none)")
        return "\n".join(lines)

    def _connector(self, args) -> str:
        if len(args) < 3 or args[0].lower() != "pull":
            return "Usage: connector pull <source> <https-url> [TOKEN_ENV]"
        from core.soc_connectors import HTTPSJSONConnector
        result = HTTPSJSONConnector(self.store).pull(
            args[1], args[2], args[3] if len(args) > 3 else None)
        return (f"Connector imported {result['events']} new events and "
                f"{result['alerts']} new alerts from {args[1]}.")

    def _benchmark(self, args) -> str:
        if len(args) != 2 or args[0].lower() not in ("corpus", "generate"):
            return "Usage: benchmark corpus <manifest.json> | benchmark generate <directory>"
        if args[0].lower() == "generate":
            from ai.oracle import generate_synthetic_corpus
            result = generate_synthetic_corpus(args[1])
            return f"Generated {result['cases']} labelled synthetic cases. Manifest: {result['manifest']}"
        from ai.oracle import run_corpus
        result = run_corpus(args[1])
        detector_errors = sum(
            row.get("false_positives", 0) + row.get("false_negatives", 0)
            for row in result.get("by_subject", {}).values())
        return (f"ORACLE RUN {result['run_id']} cases={result['cases']} failed={len(result['failed'])} "
                f"precision={result['precision']} recall={result['recall']} "
                f"Brier={result['brier']} ECE={result['ece']} "
                f"detectors={len(result.get('by_subject', {}))} errors={detector_errors}")

    def _oracle(self, args) -> str:
        from ai.oracle import OracleStore, rederive_report
        if len(args) == 2 and args[0].lower() == "rederive":
            result = rederive_report(args[1])
            return (f"RE-DERIVATION {result['run_id']} samples={result['samples']} "
                    f"precision={result['precision']} recall={result['recall']} ECE={result['ece']}")
        if args:
            return "Usage: oracle | oracle rederive <report.json>"
        metrics = OracleStore().metrics()
        return ("ORACLE CALIBRATION\n"
                f"  samples={metrics['samples']} precision={metrics['precision']} recall={metrics['recall']}\n"
                f"  Brier={metrics['brier']} ECE={metrics['ece']}\n"
                "  learning source: independent corpus/synthetic/rederive/delayed-intel/cross-path outcomes")

    def _learning(self):
        from core.soc_learning import SOCLearningStore
        return SOCLearningStore(str(self.store.path))

    def _baseline(self, args) -> str:
        learning = self._learning()
        if not args or args[0].lower() == "status":
            rows = learning.baseline_status()
            if not rows:
                return "No behavioral baseline samples. Use `baseline observe <entity> <feature> <value>`."
            return "\n".join(["BEHAVIORAL BASELINES"] + [
                f"  {r['entity']:<24} {r['feature']:<22} hour={r['time_bucket']:02} n={r['n']} mean={r['mean']:.3f}"
                for r in rows])
        if len(args) != 4 or args[0].lower() not in ("observe", "check"):
            return "Usage: baseline observe|check <entity> <feature> <numeric-value>"
        value = float(args[3])
        if args[0].lower() == "observe":
            row = learning.observe(args[1], args[2], value)
        else:
            row = learning.deviation(args[1], args[2], value)
        return json.dumps(row, sort_keys=True)

    def _similar(self, args) -> str:
        if not args:
            return "Usage: similar <case-id|case description>"
        rows = self._learning().similar(" ".join(args))
        if not rows:
            return "No similar historical cases found."
        return "\n".join(["SIMILAR CASES"] + [
            f"  {r['similarity']:.0%}  [{r['priority']}] {r['case_id']}  {r['title'][:75]}" for r in rows])

    def _campaign(self, args) -> str:
        learning = self._learning()
        if not args or args[0].lower() == "list":
            rows = learning.campaigns()
            return "\n".join(["CAMPAIGNS"] + [f"  {r['id']} cases={r['cases']} {r['title']}" for r in rows])
        if len(args) != 2 or args[0].lower() != "build":
            return "Usage: campaign list | campaign build <case-id>"
        result = learning.build_campaign(args[1])
        return f"Built {result['campaign_id']} with {result['cases']} linked case(s)."

    def _response(self, args) -> str:
        if not args or args[0].lower() == "status":
            rows = self._learning().responses(args[1] if len(args) > 1 else "")
            if not rows:
                return "No local response state."
            return "\n".join(["LOCAL RESPONSE STATE"] + [
                f"  #{r['id']} [{r['state']}] {r['case_id']} {r['action']} {r['target']} expires={_when(r['expires'])}"
                for r in rows])
        if args[0].lower() == "expire":
            count = self._learning().expire_responses()
            return f"Reverted {count} expired local response action(s)."
        if len(args) < 4 or args[0].lower() != "local":
            return ("Usage: response local <case-id> <tag|watchlist|snapshot> <target> [ttl-seconds] "
                    "| response status [case-id] | response expire")
        ttl = int(args[4]) if len(args) > 4 else 3600
        result = self._learning().execute_local(args[1], args[2], args[3], ttl)
        return (f"Local reversible response #{result['id']} active until {_when(result['expires'])}. "
                "It will auto-revert; no external control was changed.")

    def _rescore_intel(self, args) -> str:
        if len(args) != 1:
            return "Usage: rescore-intel <threat-intel.json>"
        from ai.oracle import OracleStore
        from core.threat_intel import ThreatIntel
        intel = ThreatIntel(args[0])
        oracle = OracleStore()
        run_id = oracle.start("delayed_intel")
        with self.store._connect() as db:
            rows = db.execute("SELECT DISTINCT ioc,severity,id FROM alerts WHERE ioc<>''").fetchall()
        hits = 0
        for row in rows:
            match = intel.lookup(row["ioc"])
            malicious = bool(match and str(match.get("verdict", "")).lower() == "malicious")
            predicted = row["severity"] in ("critical", "high")
            oracle.record(run_id, kind="delayed_intel", subject="ioc_risk",
                          expected=malicious, predicted=predicted,
                          confidence={"critical": .95, "high": .8, "medium": .5, "low": .2}.get(row["severity"], .1),
                          evidence={"alert_id": row["id"], "ioc": row["ioc"], "match": match or {}})
            hits += int(malicious)
        metrics = oracle.finish(run_id, len(rows))
        return (f"Delayed-intel oracle {run_id}: rescored={len(rows)} malicious_hits={hits} "
                f"precision={metrics['precision']} recall={metrics['recall']} ECE={metrics['ece']}")

    def _fuse(self, args) -> str:
        entity = " ".join(args)
        rows = self.store.fusion(entity)
        if not rows:
            return "No multi-sensor agreements in the active 15-minute window."
        return "\n".join(["MULTI-SENSOR FUSION"] + [
            f"  {r['confidence']:.0%} {r['entity']:<28} sources={','.join(r['sources'])} events={r['events']}"
            for r in rows[:50]])
