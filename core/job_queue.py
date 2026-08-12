"""Durable SQLite queue for autonomous PCAP missions."""
from __future__ import annotations

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
                created REAL NOT NULL,
                updated REAL NOT NULL,
                UNIQUE(path, fingerprint, mission)
            )""")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status)")
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
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT OR IGNORE INTO jobs(path,fingerprint,mission,status,created,updated) "
                "VALUES(?,?,?,?,?,?)", (path, fingerprint, mission, "queued", now, now))
            row = conn.execute(
                "SELECT id FROM jobs WHERE path=? AND fingerprint=? AND mission=?",
                (path, fingerprint, mission)).fetchone()
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

    def complete(self, job_id: int) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE jobs SET status='done', updated=? WHERE id=?",
                         (time.time(), job_id))

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
