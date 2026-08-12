"""Durable, vendor-neutral SOC alerts, cases, evidence, and response state."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


def _value(row: Dict[str, Any], *names: str, default=None):
    for name in names:
        current: Any = row
        for part in name.split("."):
            if not isinstance(current, dict) or part not in current:
                current = None
                break
            current = current[part]
        if current not in (None, ""):
            return current
    return default


def _timestamp(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value) / 1000 if float(value) > 10_000_000_000 else float(value)
    if value:
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
        except ValueError:
            pass
    return time.time()


def _severity(value: Any) -> str:
    if isinstance(value, (int, float)):
        score = float(value)
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 30:
            return "medium"
        return "low"
    text = str(value or "medium").lower()
    numeric = {"1": "low", "2": "medium", "3": "high", "4": "critical"}
    text = numeric.get(text, text)
    return text if text in ("critical", "high", "medium", "low", "info") else "medium"


class SOCStore:
    """SQLite boundary shared by CYSOC commands and future SIEM/EDR connectors."""

    def __init__(self, path: Optional[str] = None):
        state = Path(os.environ.get("EASYSHARK_STATE_DIR",
                                    str(Path.home() / ".easyshark")))
        self.path = Path(path or os.environ.get("EASYSHARK_SOC_DB",
                                                str(state / "cysoc.db")))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(str(self.path), timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA foreign_keys=ON")
            yield connection
            connection.commit()
        finally:
            connection.close()

    def _init(self) -> None:
        with self._connect() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS alerts (
              id TEXT PRIMARY KEY, source TEXT NOT NULL, external_id TEXT NOT NULL,
              title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
              severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'new',
              rule_name TEXT NOT NULL DEFAULT '', asset TEXT NOT NULL DEFAULT '',
              identity TEXT NOT NULL DEFAULT '', src_ip TEXT NOT NULL DEFAULT '',
              dst_ip TEXT NOT NULL DEFAULT '', ioc TEXT NOT NULL DEFAULT '',
              event_ts REAL NOT NULL, raw TEXT NOT NULL, created REAL NOT NULL,
              updated REAL NOT NULL, UNIQUE(source, external_id)
            );
            CREATE INDEX IF NOT EXISTS idx_soc_alert_queue
              ON alerts(status, severity, event_ts DESC);
            CREATE TABLE IF NOT EXISTS observations (
              id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT UNIQUE NOT NULL,
              source TEXT NOT NULL, event_type TEXT NOT NULL, summary TEXT NOT NULL,
              asset TEXT NOT NULL DEFAULT '', identity TEXT NOT NULL DEFAULT '',
              src_ip TEXT NOT NULL DEFAULT '', dst_ip TEXT NOT NULL DEFAULT '',
              ioc TEXT NOT NULL DEFAULT '', event_ts REAL NOT NULL, raw TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_soc_observation_ts
              ON observations(event_ts DESC);
            CREATE TABLE IF NOT EXISTS cases (
              id TEXT PRIMARY KEY, source_ref TEXT UNIQUE,
              title TEXT NOT NULL, priority TEXT NOT NULL, status TEXT NOT NULL,
              disposition TEXT NOT NULL DEFAULT '', assignee TEXT NOT NULL DEFAULT '',
              summary TEXT NOT NULL DEFAULT '', created REAL NOT NULL, updated REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_soc_case_queue
              ON cases(status, priority, updated DESC);
            CREATE TABLE IF NOT EXISTS case_alerts (
              case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
              alert_id TEXT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
              PRIMARY KEY(case_id, alert_id)
            );
            CREATE TABLE IF NOT EXISTS triage_groups (
              correlation_key TEXT PRIMARY KEY,
              case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
              last_event REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS case_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
              event_ts REAL NOT NULL, kind TEXT NOT NULL, actor TEXT NOT NULL,
              message TEXT NOT NULL, data TEXT NOT NULL DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS idx_soc_case_timeline
              ON case_events(case_id, event_ts);
            CREATE TABLE IF NOT EXISTS actions (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
              action TEXT NOT NULL, status TEXT NOT NULL,
              requested_by TEXT NOT NULL, decided_by TEXT NOT NULL DEFAULT '',
              created REAL NOT NULL, updated REAL NOT NULL
            );
            """)

    @staticmethod
    def _rows(rows) -> List[Dict[str, Any]]:
        return [dict(row) for row in rows]

    def ingest_file(self, path: str, source: str = "import",
                    auto_triage: bool = False) -> Dict[str, Any]:
        target = Path(path).resolve()
        if not target.is_file():
            raise FileNotFoundError(path)
        if target.stat().st_size > 50 * 1024 * 1024:
            raise ValueError("telemetry import exceeds 50 MB")
        text = target.read_text(encoding="utf-8-sig")
        if target.suffix.lower() in (".jsonl", ".ndjson"):
            rows = [json.loads(line) for line in text.splitlines() if line.strip()]
        else:
            payload = json.loads(text)
            if isinstance(payload, list):
                rows = payload
            elif isinstance(payload, dict):
                rows = (_value(payload, "events", "alerts", "data") or [payload])
            else:
                raise ValueError("telemetry file must contain JSON objects")
        if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
            raise ValueError("telemetry records must be JSON objects")
        return self.ingest(rows, source=source, auto_triage=auto_triage)

    def ingest(self, rows: Iterable[Dict[str, Any]], source: str = "import",
               auto_triage: bool = False) -> Dict[str, Any]:
        source = str(source or "import").strip().lower()[:80]
        added_alerts = added_events = 0
        baseline_samples = []
        with self._connect() as db:
            for row in rows:
                if not isinstance(row, dict):
                    continue
                raw = json.dumps(row, sort_keys=True, default=str)
                ts = _timestamp(_value(row, "@timestamp", "timestamp", "ts", "time"))
                external = str(_value(row, "id", "alert_id", "event_id",
                                      "_id", default="")).strip()
                if not external:
                    external = hashlib.sha256(raw.encode()).hexdigest()[:20]
                title = str(_value(row, "title", "name", "rule.name", "message",
                                   default="Security event"))[:500]
                description = str(_value(row, "description", "details", "message",
                                         default=""))[:4000]
                rule_name = str(_value(row, "rule_name", "rule.name", "signature",
                                       "detection", default=""))[:300]
                asset = str(_value(row, "asset", "host.name", "hostname", "device_name",
                                   "computer", default=""))[:300]
                identity = str(_value(row, "identity", "user.name", "username", "user",
                                      "account", default=""))[:300]
                src_ip = str(_value(row, "src_ip", "source.ip", "source_ip",
                                    "client_ip", default=""))[:128]
                dst_ip = str(_value(row, "dst_ip", "destination.ip", "destination_ip",
                                    "server_ip", default=""))[:128]
                ioc = str(_value(row, "ioc", "indicator", "domain", "url", "hash",
                                 default=""))[:1000]
                event_type = str(_value(row, "event_type", "event.kind", "type",
                                        "category", default="event"))[:100]
                entity = asset or src_ip or identity
                for feature_name in ("bytes", "bytes_out", "duration", "risk_score"):
                    raw_value = _value(row, feature_name, f"network.{feature_name}")
                    if entity and isinstance(raw_value, (int, float)):
                        baseline_samples.append((entity, feature_name, float(raw_value), ts))
                fingerprint = hashlib.sha256(
                    f"{source}|{external}|{raw}".encode()).hexdigest()
                cur = db.execute(
                    "INSERT OR IGNORE INTO observations(fingerprint,source,event_type,summary,asset,identity,src_ip,dst_ip,ioc,event_ts,raw) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (fingerprint, source, event_type, title, asset, identity,
                     src_ip, dst_ip, ioc, ts, raw))
                added_events += max(0, cur.rowcount)

                is_alert = (event_type.lower() in ("alert", "signal", "detection") or
                            bool(rule_name) or _value(row, "severity") is not None)
                if not is_alert:
                    continue
                alert_id = f"{source}:{external}"
                severity = _severity(_value(row, "severity", "risk_score", "priority"))
                now = time.time()
                cur = db.execute(
                    "INSERT OR IGNORE INTO alerts(id,source,external_id,title,description,severity,status,rule_name,asset,identity,src_ip,dst_ip,ioc,event_ts,raw,created,updated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (alert_id, source, external, title, description, severity, "new",
                     rule_name, asset, identity, src_ip, dst_ip, ioc, ts, raw, now, now))
                added_alerts += max(0, cur.rowcount)
        if baseline_samples:
            from core.soc_learning import SOCLearningStore
            learning = SOCLearningStore(str(self.path))
            for entity, feature, value, ts in baseline_samples:
                learning.observe(entity, feature, value, ts)
        result: Dict[str, Any] = {"alerts": added_alerts, "events": added_events}
        if auto_triage and added_alerts:
            result["triage"] = self.triage_alerts()
        return result

    @staticmethod
    def _correlation_key(alert: Dict[str, Any]) -> str:
        """Stable entity key; unstructured attacker text never controls grouping."""
        for field in ("asset", "identity", "ioc", "src_ip", "dst_ip"):
            value = str(alert.get(field) or "").strip().lower()
            if value:
                return f"{field}:{value}"
        return "alert:" + str(alert["id"])

    def triage_alerts(self, limit: int = 500,
                      window_seconds: int = 3600) -> Dict[str, Any]:
        """Link untriaged alerts into deterministic, time-bounded SOC cases."""
        limit = max(1, min(5000, int(limit)))
        window = max(60, min(7 * 86400, int(window_seconds)))
        priority_for = {"critical": "P1", "high": "P2",
                        "medium": "P3", "low": "P4", "info": "P4"}
        rank = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}
        created = promoted = linked = 0
        case_ids: List[str] = []
        from core.untrusted import injection_signals, quarantine

        with self._connect() as db:
            alerts = self._rows(db.execute("""
              SELECT a.* FROM alerts a
              LEFT JOIN case_alerts ca ON ca.alert_id=a.id
              WHERE ca.alert_id IS NULL AND a.status IN ('new','acknowledged')
              ORDER BY a.event_ts,a.id LIMIT ?
            """, (limit,)))
            for alert in alerts:
                correlation_key = self._correlation_key(alert)
                event_ts = float(alert["event_ts"])
                group = db.execute("""
                  SELECT tg.case_id,tg.last_event,c.priority,c.status
                  FROM triage_groups tg JOIN cases c ON c.id=tg.case_id
                  WHERE tg.correlation_key=?
                """, (correlation_key,)).fetchone()
                reuse = bool(group and group["status"] not in ("closed", "resolved") and
                             abs(event_ts - float(group["last_event"])) <= window)
                priority = priority_for.get(str(alert["severity"]).lower(), "P3")
                suspicious_text = " ".join(str(alert.get(field) or "") for field in
                                           ("title", "description", "rule_name", "raw"))
                injection = bool(injection_signals(suspicious_text))

                if reuse:
                    case_id = str(group["case_id"])
                    if rank[priority] < rank.get(str(group["priority"]), 4):
                        db.execute("UPDATE cases SET priority=?,updated=? WHERE id=?",
                                   (priority, time.time(), case_id))
                        db.execute("""INSERT INTO case_events
                          (case_id,event_ts,kind,actor,message,data) VALUES(?,?,?,?,?,?)""",
                          (case_id, time.time(), "priority_promoted", "easyshark",
                           f"Priority promoted to {priority} by alert {alert['id']}",
                           json.dumps({"alert_id": alert["id"], "priority": priority})))
                        promoted += 1
                else:
                    case_id = f"CYSOC-{time.strftime('%Y%m%d')}-{secrets.token_hex(2).upper()}"
                    title = quarantine(str(alert["title"]))
                    if not isinstance(title, str) or not title.strip():
                        title = "Automatically triaged security alert"
                    summary = (f"Automatically grouped from {alert['source']} alert "
                               f"{alert['id']} using a structured entity key.")
                    if injection:
                        summary += " Connector text contained quarantined prompt-injection-like content."
                    now = time.time()
                    db.execute("""INSERT INTO cases
                      (id,source_ref,title,priority,status,disposition,summary,created,updated)
                      VALUES(?,?,?,?,?,?,?,?,?)""",
                      (case_id, "auto-triage:" + hashlib.sha256(
                          f"{correlation_key}|{event_ts}|{alert['id']}".encode()).hexdigest(),
                       title[:500], priority, "review" if injection else "open", "",
                       summary, now, now))
                    db.execute("""INSERT INTO case_events
                      (case_id,event_ts,kind,actor,message,data) VALUES(?,?,?,?,?,?)""",
                      (case_id, now, "auto_triaged", "easyshark",
                       "Case created by deterministic alert triage",
                       json.dumps({"correlation_field": correlation_key.split(":", 1)[0],
                                   "prompt_injection_suspected": injection})))
                    created += 1

                db.execute("INSERT OR IGNORE INTO case_alerts(case_id,alert_id) VALUES(?,?)",
                           (case_id, alert["id"]))
                db.execute("UPDATE alerts SET status='linked',updated=? WHERE id=?",
                           (time.time(), alert["id"]))
                db.execute("UPDATE cases SET updated=? WHERE id=?", (time.time(), case_id))
                db.execute("""INSERT INTO case_events
                  (case_id,event_ts,kind,actor,message,data) VALUES(?,?,?,?,?,?)""",
                  (case_id, time.time(), "alert_auto_linked", "easyshark",
                   f"Alert linked: {alert['id']}",
                   json.dumps({"alert_id": alert["id"], "source": alert["source"]})))
                db.execute("""INSERT INTO triage_groups(correlation_key,case_id,last_event)
                  VALUES(?,?,?) ON CONFLICT(correlation_key) DO UPDATE SET
                  case_id=excluded.case_id,
                  last_event=MAX(triage_groups.last_event,excluded.last_event)""",
                  (correlation_key, case_id, event_ts))
                linked += 1
                if case_id not in case_ids:
                    case_ids.append(case_id)
        return {"processed": len(alerts), "created": created, "promoted": promoted,
                "linked": linked, "cases": case_ids}

    def pulse(self) -> Dict[str, Any]:
        with self._connect() as db:
            alert_counts = {row["severity"]: row["n"] for row in db.execute(
                "SELECT severity,COUNT(*) n FROM alerts WHERE status NOT IN ('closed','false_positive') GROUP BY severity")}
            case_counts = {row["status"]: row["n"] for row in db.execute(
                "SELECT status,COUNT(*) n FROM cases GROUP BY status")}
            recent = self._rows(db.execute(
                "SELECT id,severity,title,source,asset,event_ts FROM alerts ORDER BY event_ts DESC LIMIT 5"))
            hot = self._rows(db.execute(
                "SELECT asset,COUNT(*) n FROM alerts WHERE asset<>'' GROUP BY asset ORDER BY n DESC LIMIT 5"))
        return {"alerts": alert_counts, "cases": case_counts,
                "recent_alerts": recent, "hot_assets": hot}

    def alert_queue(self, priorities: Optional[Iterable[str]] = None,
                    status: str = "new", limit: int = 50) -> List[Dict[str, Any]]:
        severities = [str(item).lower().replace("p1", "critical").replace(
            "p2", "high").replace("p3", "medium").replace("p4", "low")
                      for item in (priorities or [])]
        sql = "SELECT * FROM alerts WHERE status=?"
        params: List[Any] = [status]
        if severities:
            sql += " AND severity IN (" + ",".join("?" for _ in severities) + ")"
            params.extend(severities)
        sql += (" ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 "
                "WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,event_ts DESC LIMIT ?")
        params.append(max(1, min(500, int(limit))))
        with self._connect() as db:
            return self._rows(db.execute(sql, params))

    def update_alert(self, alert_id: str, status: str) -> None:
        status = status.lower().replace("-", "_")
        if status not in ("new", "acknowledged", "linked", "closed", "false_positive"):
            raise ValueError("alert status must be new, acknowledged, linked, closed, or false_positive")
        with self._connect() as db:
            cur = db.execute("UPDATE alerts SET status=?,updated=? WHERE id=?",
                             (status, time.time(), alert_id))
            if not cur.rowcount:
                raise ValueError("alert not found")

    def create_case(self, title: str, priority: str = "P3", actor: str = "analyst",
                    summary: str = "", source_ref: Optional[str] = None,
                    disposition: str = "") -> str:
        priority = priority.upper()
        if priority not in ("P1", "P2", "P3", "P4"):
            raise ValueError("priority must be P1, P2, P3, or P4")
        if not title.strip():
            raise ValueError("case title is required")
        if source_ref:
            with self._connect() as db:
                row = db.execute("SELECT id FROM cases WHERE source_ref=?",
                                 (source_ref,)).fetchone()
                if row:
                    return str(row["id"])
        case_id = f"CYSOC-{time.strftime('%Y%m%d')}-{secrets.token_hex(2).upper()}"
        now = time.time()
        with self._connect() as db:
            db.execute("INSERT INTO cases(id,source_ref,title,priority,status,disposition,summary,created,updated) VALUES(?,?,?,?,?,?,?,?,?)",
                       (case_id, source_ref, title.strip()[:500], priority, "open",
                        disposition, summary[:8000], now, now))
            db.execute("INSERT INTO case_events(case_id,event_ts,kind,actor,message) VALUES(?,?,?,?,?)",
                       (case_id, now, "created", actor, "Case created"))
        return case_id

    def cases(self, status: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM cases"
        params: List[Any] = []
        if status:
            sql += " WHERE status=?"
            params.append(status)
        sql += (" ORDER BY CASE priority WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 "
                "WHEN 'P3' THEN 3 ELSE 4 END,updated DESC LIMIT ?")
        params.append(max(1, min(500, int(limit))))
        with self._connect() as db:
            return self._rows(db.execute(sql, params))

    def case(self, case_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as db:
            row = db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
            if not row:
                return None
            result = dict(row)
            result["alerts"] = self._rows(db.execute(
                "SELECT a.* FROM alerts a JOIN case_alerts ca ON ca.alert_id=a.id WHERE ca.case_id=? ORDER BY a.event_ts",
                (case_id,)))
            result["actions"] = self._rows(db.execute(
                "SELECT * FROM actions WHERE case_id=? ORDER BY id", (case_id,)))
            return result

    def link_alert(self, case_id: str, alert_id: str, actor: str = "analyst") -> None:
        with self._connect() as db:
            if not db.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
                raise ValueError("case not found")
            if not db.execute("SELECT 1 FROM alerts WHERE id=?", (alert_id,)).fetchone():
                raise ValueError("alert not found")
            db.execute("INSERT OR IGNORE INTO case_alerts(case_id,alert_id) VALUES(?,?)",
                       (case_id, alert_id))
            db.execute("UPDATE alerts SET status='linked',updated=? WHERE id=?",
                       (time.time(), alert_id))
            db.execute("INSERT INTO case_events(case_id,event_ts,kind,actor,message,data) VALUES(?,?,?,?,?,?)",
                       (case_id, time.time(), "alert_linked", actor,
                        f"Alert linked: {alert_id}", json.dumps({"alert_id": alert_id})))

    def update_case(self, case_id: str, field: str, value: str,
                    actor: str = "analyst") -> None:
        allowed = {"status", "priority", "disposition", "assignee", "summary", "title"}
        if field not in allowed:
            raise ValueError("unsupported case field")
        if field == "priority" and value.upper() not in ("P1", "P2", "P3", "P4"):
            raise ValueError("priority must be P1, P2, P3, or P4")
        value = value.upper() if field == "priority" else value
        with self._connect() as db:
            cur = db.execute(f"UPDATE cases SET {field}=?,updated=? WHERE id=?",
                             (value[:8000], time.time(), case_id))
            if not cur.rowcount:
                raise ValueError("case not found")
            db.execute("INSERT INTO case_events(case_id,event_ts,kind,actor,message,data) VALUES(?,?,?,?,?,?)",
                       (case_id, time.time(), "case_updated", actor,
                        f"{field} changed to {value}", json.dumps({"field": field, "value": value})))

    def add_note(self, case_id: str, message: str, actor: str = "analyst") -> None:
        if not message.strip():
            raise ValueError("note is required")
        with self._connect() as db:
            if not db.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
                raise ValueError("case not found")
            db.execute("INSERT INTO case_events(case_id,event_ts,kind,actor,message) VALUES(?,?,?,?,?)",
                       (case_id, time.time(), "note", actor, message[:8000]))

    def timeline(self, case_id: str) -> List[Dict[str, Any]]:
        with self._connect() as db:
            return self._rows(db.execute(
                "SELECT event_ts,kind,actor,message,data FROM case_events WHERE case_id=? ORDER BY event_ts,id",
                (case_id,)))

    def request_action(self, case_id: str, action: str,
                       actor: str = "analyst") -> int:
        if not action.strip():
            raise ValueError("action is required")
        now = time.time()
        with self._connect() as db:
            if not db.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
                raise ValueError("case not found")
            cur = db.execute("INSERT INTO actions(case_id,action,status,requested_by,created,updated) VALUES(?,?,?,?,?,?)",
                             (case_id, action[:2000], "pending_approval", actor, now, now))
            action_id = int(cur.lastrowid)
            db.execute("INSERT INTO case_events(case_id,event_ts,kind,actor,message,data) VALUES(?,?,?,?,?,?)",
                       (case_id, now, "action_requested", actor, action[:2000],
                        json.dumps({"action_id": action_id})))
            return action_id

    def decide_action(self, action_id: int, decision: str,
                      actor: str = "approver") -> None:
        if decision not in ("approved", "denied"):
            raise ValueError("decision must be approved or denied")
        with self._connect() as db:
            row = db.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
            if not row:
                raise ValueError("action not found")
            if row["status"] != "pending_approval":
                raise ValueError("action has already been decided")
            db.execute("UPDATE actions SET status=?,decided_by=?,updated=? WHERE id=?",
                       (decision, actor, time.time(), action_id))
            db.execute("INSERT INTO case_events(case_id,event_ts,kind,actor,message,data) VALUES(?,?,?,?,?,?)",
                       (row["case_id"], time.time(), "action_decided", actor,
                        f"Action {decision}: {row['action']}",
                        json.dumps({"action_id": action_id, "decision": decision})))

    def hunt(self, term: str, limit: int = 50) -> Dict[str, List[Dict[str, Any]]]:
        if not term.strip():
            raise ValueError("hunt term is required")
        pattern = f"%{term.strip()}%"
        with self._connect() as db:
            alerts = self._rows(db.execute(
                "SELECT id,event_ts,severity,title,asset,identity,src_ip,dst_ip,ioc,source FROM alerts WHERE title LIKE ? OR description LIKE ? OR asset LIKE ? OR identity LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR ioc LIKE ? OR raw LIKE ? ORDER BY event_ts DESC LIMIT ?",
                (pattern,) * 8 + (limit,)))
            events = self._rows(db.execute(
                "SELECT event_ts,source,event_type,summary,asset,identity,src_ip,dst_ip,ioc FROM observations WHERE summary LIKE ? OR asset LIKE ? OR identity LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR ioc LIKE ? OR raw LIKE ? ORDER BY event_ts DESC LIMIT ?",
                (pattern,) * 7 + (limit,)))
            cases = self._rows(db.execute(
                "SELECT id,priority,status,title,assignee,disposition FROM cases WHERE id LIKE ? OR title LIKE ? OR summary LIKE ? ORDER BY updated DESC LIMIT ?",
                (pattern, pattern, pattern, limit)))
        return {"alerts": alerts, "events": events, "cases": cases}

    def correlate(self, entity: str, limit: int = 100) -> List[Dict[str, Any]]:
        if not entity.strip():
            raise ValueError("entity is required")
        value = entity.strip()
        with self._connect() as db:
            return self._rows(db.execute(
                "SELECT event_ts,source,event_type,summary,asset,identity,src_ip,dst_ip,ioc FROM observations WHERE asset=? OR identity=? OR src_ip=? OR dst_ip=? OR ioc=? ORDER BY event_ts DESC LIMIT ?",
                (value, value, value, value, value, max(1, min(500, limit)))))

    def fusion(self, entity: str = "", window_seconds: int = 900,
               limit: int = 1000) -> List[Dict[str, Any]]:
        """Find entities independently observed by multiple sensors in a time window."""
        cutoff = time.time() - max(60, min(int(window_seconds), 30 * 86400))
        with self._connect() as db:
            rows = self._rows(db.execute(
                "SELECT event_ts,source,event_type,summary,asset,identity,src_ip,dst_ip,ioc FROM observations WHERE event_ts>=? ORDER BY event_ts",
                (cutoff,)))
        grouped: Dict[str, Dict[str, Any]] = {}
        wanted = entity.strip().lower()
        for row in rows[-limit:]:
            values = {str(row.get(key) or "") for key in
                      ("asset", "identity", "src_ip", "dst_ip", "ioc")}
            values.discard("")
            for value in values:
                if wanted and value.lower() != wanted:
                    continue
                item = grouped.setdefault(value, {"entity": value, "sources": set(),
                                                   "event_types": set(), "events": 0,
                                                   "first_seen": row["event_ts"],
                                                   "last_seen": row["event_ts"]})
                item["sources"].add(row["source"])
                item["event_types"].add(row["event_type"])
                item["events"] += 1
                item["last_seen"] = row["event_ts"]
        fused = []
        for item in grouped.values():
            if len(item["sources"]) < 2:
                continue
            item["sources"] = sorted(item["sources"])
            item["event_types"] = sorted(item["event_types"])
            item["confidence"] = round(min(.95, .45 + .15 * len(item["sources"])), 2)
            fused.append(item)
        return sorted(fused, key=lambda row: (len(row["sources"]), row["events"]), reverse=True)

    def detection_health(self) -> List[Dict[str, Any]]:
        with self._connect() as db:
            return self._rows(db.execute("""
              SELECT COALESCE(NULLIF(rule_name,''),'(unmapped)') rule_name,source,
                     COUNT(*) alerts,
                     SUM(CASE WHEN status='false_positive' THEN 1 ELSE 0 END) false_positives,
                     MAX(event_ts) last_seen
              FROM alerts GROUP BY source,rule_name ORDER BY alerts DESC LIMIT 100
            """))

    def source_counts(self) -> List[Dict[str, Any]]:
        with self._connect() as db:
            return self._rows(db.execute(
                "SELECT source,COUNT(*) events,MAX(event_ts) last_seen FROM observations GROUP BY source ORDER BY events DESC"))

    def ingest_easyshark_report(self, path: str) -> str:
        target = Path(path).resolve()
        report = json.loads(target.read_text(encoding="utf-8"))
        conclusion = report.get("conclusion") or {}
        assessment = conclusion.get("soc_assessment") or {}
        title = (conclusion.get("analyst_summary") or
                 conclusion.get("incident_narrative") or target.name)
        case_id = self.create_case(
            str(title)[:500], assessment.get("priority", "P3"), actor="easyshark",
            summary=str(conclusion.get("incident_narrative") or "")[:8000],
            source_ref="easyshark-report:" + str(target),
            disposition=assessment.get("disposition", ""))
        with self._connect() as db:
            existing = db.execute(
                "SELECT 1 FROM case_events WHERE case_id=? AND kind='report_imported'",
                (case_id,)).fetchone()
            if not existing:
                db.execute("UPDATE cases SET status=?,updated=? WHERE id=?",
                           ("review" if assessment.get("human_review_required") else "open",
                            time.time(), case_id))
                db.execute("INSERT INTO case_events(case_id,event_ts,kind,actor,message,data) VALUES(?,?,?,?,?,?)",
                           (case_id, time.time(), "report_imported", "easyshark",
                            f"SOC report imported: {target.name}",
                            json.dumps({"report": str(target),
                                        "evidence_graph": report.get("evidence_graph", {})})))
                for action in assessment.get("recommended_actions", []) or []:
                    if isinstance(action, dict) and action.get("action"):
                        status = ("pending_approval" if action.get("approval_required")
                                  else "recommended")
                        now = time.time()
                        db.execute("INSERT INTO actions(case_id,action,status,requested_by,created,updated) VALUES(?,?,?,?,?,?)",
                                   (case_id, str(action["action"]), status,
                                    "easyshark", now, now))
        return case_id
