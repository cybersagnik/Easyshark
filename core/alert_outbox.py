"""Durable alert outbox for webhook delivery after restarts."""
from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional


class AlertOutbox:
    def __init__(self, path: Optional[str] = None):
        self.path = Path(path or (Path.home() / ".easyshark" / "alerts.db"))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS outbox (id INTEGER PRIMARY KEY, payload TEXT NOT NULL, created REAL NOT NULL, attempts INTEGER NOT NULL DEFAULT 0)")

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(str(self.path), timeout=10)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def put(self, event: Dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute("INSERT INTO outbox(payload,created) VALUES(?,?)",
                         (json.dumps(event, default=str), time.time()))

    def pending(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT id,payload FROM outbox ORDER BY id LIMIT ?",
                                (max(1, limit),)).fetchall()
        return [{"id": row[0], "event": json.loads(row[1])} for row in rows]

    def remove(self, event_id: int) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM outbox WHERE id=?", (event_id,))
