"""Durable SQLite queue for autonomous PCAP missions."""
from __future__ import annotations

import hashlib
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Optional

QUEUE_PATH = Path(os.environ.get(
    "EASYSHARK_QUEUE_DB", str(Path.home() / ".easyshark" / "jobs.db")))


class JobQueue:
    def __init__(self, path: Optional[str] = None, lease_seconds: float = 900.0):
        self.path = Path(path or QUEUE_PATH)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                mission TEXT NOT NULL,
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                error TEXT,
                session_key TEXT,
                checkpoint_stage TEXT,
                checkpoint_updated REAL,
                report_path TEXT,
                last_event_sequence INTEGER NOT NULL DEFAULT 0,
                idempotency_key TEXT,
                created REAL NOT NULL,
                updated REAL NOT NULL,
                UNIQUE(path, fingerprint, mission)
            )""")
            columns = {row[1] for row in conn.execute("PRAGMA table_info(jobs)")}
            migrations = {
                "session_key": "TEXT",
                "checkpoint_stage": "TEXT",
                "checkpoint_updated": "REAL",
                "report_path": "TEXT",
                "last_event_sequence": "INTEGER NOT NULL DEFAULT 0",
                "idempotency_key": "TEXT",
            }
            for name, declaration in migrations.items():
                if name not in columns:
                    conn.execute(f"ALTER TABLE jobs ADD COLUMN {name} {declaration}")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status)")
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_idempotency "
                         "ON jobs(idempotency_key) WHERE idempotency_key IS NOT NULL")
            conn.execute("UPDATE jobs SET status='queued', updated=? "
                         "WHERE status='running' AND updated < ?",
                         (time.time(), time.time() - max(1.0, lease_seconds)))

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(str(self.path), timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def enqueue(self, path: str, fingerprint: str, mission: str) -> int:
        now = time.time()
        idempotency_key = hashlib.sha256(
            f"{fingerprint}\0{mission}".encode("utf-8")).hexdigest()
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT OR IGNORE INTO jobs(path,fingerprint,mission,status,"
                "idempotency_key,created,updated) VALUES(?,?,?,?,?,?,?)",
                (path, fingerprint, mission, "queued", idempotency_key, now, now))
            row = conn.execute(
                "SELECT id FROM jobs WHERE idempotency_key=?",
                (idempotency_key,)).fetchone()
            return int(row["id"] if row else cur.lastrowid)

    def claim(self) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM jobs WHERE status='queued' ORDER BY id LIMIT 1").fetchone()
            if not row:
                return None
            now = time.time()
            conn.execute("UPDATE jobs SET status='running', attempts=attempts+1, updated=? WHERE id=?",
                         (now, row["id"]))
            out = dict(row)
            out["attempts"] = int(row["attempts"]) + 1
            out["status"] = "running"
            return out

    def bind_session(self, job_id: int, session_key: str) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE jobs SET session_key=?, updated=? WHERE id=?",
                         (str(session_key)[:100], time.time(), job_id))

    def checkpoint(self, job_id: int, state: Dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE jobs SET checkpoint_stage=?, checkpoint_updated=?, "
                "report_path=?, last_event_sequence=?, updated=? WHERE id=?",
                (str(state.get("stage", ""))[:100], time.time(),
                 str(state.get("report_path") or "")[:2000] or None,
                 int(state.get("last_event_sequence", 0)), time.time(), job_id))

    def complete(self, job_id: int, report_path: Optional[str] = None) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE jobs SET status='done', report_path=COALESCE(?, report_path), "
                "checkpoint_stage='complete', updated=? WHERE id=?",
                (report_path, time.time(), job_id))

    def fail(self, job_id: int, error: str, retry: bool = True) -> None:
        with self._connect() as conn:
            row = conn.execute("SELECT attempts FROM jobs WHERE id=?", (job_id,)).fetchone()
            status = "queued" if retry and row and row["attempts"] < 3 else "failed"
            conn.execute("UPDATE jobs SET status=?, error=?, updated=? WHERE id=?",
                         (status, str(error)[:2000], time.time(), job_id))

    def stats(self) -> Dict[str, int]:
        with self._connect() as conn:
            rows = conn.execute("SELECT status, COUNT(*) n FROM jobs GROUP BY status").fetchall()
        return {str(row["status"]): int(row["n"]) for row in rows}
