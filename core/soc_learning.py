"""Long-horizon SOC baselines, case retrieval, campaigns, and safe response state."""
from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import time
from contextlib import contextmanager
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from core.soc_policy import ResponsePolicy
from core.untrusted import injection_signals


class SOCLearningStore:
    def __init__(self, path: str):
        self.path = Path(path)
        with self._connect() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS baselines(
              entity TEXT NOT NULL, feature TEXT NOT NULL, time_bucket INTEGER NOT NULL,
              n INTEGER NOT NULL, mean REAL NOT NULL, m2 REAL NOT NULL, updated REAL NOT NULL,
              PRIMARY KEY(entity,feature,time_bucket));
            CREATE TABLE IF NOT EXISTS case_vectors(
              case_id TEXT PRIMARY KEY, vector TEXT NOT NULL, updated REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS campaigns(
              id TEXT PRIMARY KEY, title TEXT NOT NULL, created REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS campaign_cases(
              campaign_id TEXT NOT NULL, case_id TEXT NOT NULL,
              similarity REAL NOT NULL, PRIMARY KEY(campaign_id,case_id));
            CREATE TABLE IF NOT EXISTS response_state(
              id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL,
              action TEXT NOT NULL, target TEXT NOT NULL, state TEXT NOT NULL,
              reversible INTEGER NOT NULL, created REAL NOT NULL, expires REAL NOT NULL,
              reverted REAL);
            """)

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(str(self.path), timeout=10)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        finally:
            db.close()

    def observe(self, entity: str, feature: str, value: float,
                timestamp: Optional[float] = None) -> Dict[str, Any]:
        bucket = time.gmtime(timestamp or time.time()).tm_hour
        with self._connect() as db:
            row = db.execute("SELECT * FROM baselines WHERE entity=? AND feature=? AND time_bucket=?",
                             (entity, feature, bucket)).fetchone()
            if row:
                n = row["n"] + 1
                delta = value - row["mean"]
                mean = row["mean"] + delta / n
                m2 = row["m2"] + delta * (value - mean)
                db.execute("UPDATE baselines SET n=?,mean=?,m2=?,updated=? WHERE entity=? AND feature=? AND time_bucket=?",
                           (n, mean, m2, time.time(), entity, feature, bucket))
            else:
                n, mean, m2 = 1, float(value), 0.0
                db.execute("INSERT INTO baselines VALUES(?,?,?,?,?,?,?)",
                           (entity, feature, bucket, n, mean, m2, time.time()))
        return {"entity": entity, "feature": feature, "bucket": bucket,
                "samples": n, "mean": mean, "stddev": math.sqrt(m2 / (n - 1)) if n > 1 else 0.0}

    def deviation(self, entity: str, feature: str, value: float,
                  timestamp: Optional[float] = None) -> Dict[str, Any]:
        bucket = time.gmtime(timestamp or time.time()).tm_hour
        with self._connect() as db:
            row = db.execute("SELECT * FROM baselines WHERE entity=? AND feature=? AND time_bucket=?",
                             (entity, feature, bucket)).fetchone()
        if not row or row["n"] < 5:
            return {"ready": False, "samples": int(row["n"]) if row else 0, "zscore": None}
        stddev = math.sqrt(row["m2"] / (row["n"] - 1))
        zscore = abs(float(value) - row["mean"]) / stddev if stddev > 0 else 0.0
        return {"ready": True, "samples": row["n"], "mean": row["mean"],
                "stddev": stddev, "zscore": round(zscore, 3), "anomalous": zscore >= 3.0}

    def baseline_status(self, limit: int = 30) -> List[Dict[str, Any]]:
        with self._connect() as db:
            return [dict(row) for row in db.execute(
                "SELECT entity,feature,time_bucket,n,mean,m2,updated FROM baselines ORDER BY updated DESC LIMIT ?",
                (max(1, min(500, int(limit))),))]

    def campaigns(self) -> List[Dict[str, Any]]:
        with self._connect() as db:
            return [dict(row) for row in db.execute("""
              SELECT c.id,c.title,c.created,COUNT(cc.case_id) cases
              FROM campaigns c LEFT JOIN campaign_cases cc ON cc.campaign_id=c.id
              GROUP BY c.id ORDER BY c.created DESC
            """)]

    @staticmethod
    def _vector(text: str) -> Dict[str, float]:
        tokens = re.findall(r"[a-z0-9._:-]{3,}", text.lower())
        counts = Counter(tokens)
        norm = math.sqrt(sum(value * value for value in counts.values())) or 1.0
        return {key: value / norm for key, value in counts.items()}

    @staticmethod
    def _cosine(left: Dict[str, float], right: Dict[str, float]) -> float:
        if len(left) > len(right):
            left, right = right, left
        return sum(value * right.get(key, 0.0) for key, value in left.items())

    def index_cases(self) -> int:
        with self._connect() as db:
            rows = db.execute("SELECT id,title,summary,disposition FROM cases").fetchall()
            for row in rows:
                vector = self._vector(" ".join(str(row[key] or "") for key in ("title", "summary", "disposition")))
                db.execute("INSERT OR REPLACE INTO case_vectors(case_id,vector,updated) VALUES(?,?,?)",
                           (row["id"], json.dumps(vector), time.time()))
        return len(rows)

    def similar(self, text_or_case: str, limit: int = 5) -> List[Dict[str, Any]]:
        self.index_cases()
        with self._connect() as db:
            case = db.execute("SELECT title,summary,disposition FROM cases WHERE id=?", (text_or_case,)).fetchone()
            query = self._vector(" ".join(str(case[key] or "") for key in case.keys())) if case else self._vector(text_or_case)
            rows = db.execute("SELECT v.case_id,v.vector,c.title,c.priority,c.status FROM case_vectors v JOIN cases c ON c.id=v.case_id").fetchall()
        scored = [{"case_id": row["case_id"], "title": row["title"],
                   "priority": row["priority"], "status": row["status"],
                   "similarity": round(self._cosine(query, json.loads(row["vector"])), 4)} for row in rows]
        scored = [row for row in scored if row["case_id"] != text_or_case and row["similarity"] > 0]
        return sorted(scored, key=lambda row: row["similarity"], reverse=True)[:limit]

    def build_campaign(self, seed_case: str, threshold: float = .35) -> Dict[str, Any]:
        matches = [row for row in self.similar(seed_case, 50) if row["similarity"] >= threshold]
        campaign_id = "CMP-" + hashlib.sha256(f"{seed_case}:{time.time()}".encode()).hexdigest()[:10]
        with self._connect() as db:
            db.execute("INSERT INTO campaigns VALUES(?,?,?)", (campaign_id, f"Campaign seeded by {seed_case}", time.time()))
            db.execute("INSERT INTO campaign_cases VALUES(?,?,?)", (campaign_id, seed_case, 1.0))
            for row in matches:
                db.execute("INSERT INTO campaign_cases VALUES(?,?,?)", (campaign_id, row["case_id"], row["similarity"]))
        return {"campaign_id": campaign_id, "seed": seed_case, "cases": 1 + len(matches)}

    def execute_local(self, case_id: str, action: str, target: str,
                      ttl_seconds: int = 3600) -> Dict[str, Any]:
        phrase = f"{action} {target}"
        if injection_signals(phrase):
            raise ValueError("response blocked: prompt-injection-like content in action")
        tier = ResponsePolicy.tier(action)
        if tier == "prohibited":
            raise ValueError("response action is prohibited")
        if tier != "local_reversible":
            raise ValueError("external response requires an approved connector action")
        expires = ResponsePolicy.expires_at(ttl_seconds)
        with self._connect() as db:
            if not db.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
                raise ValueError("case not found")
            cur = db.execute("INSERT INTO response_state(case_id,action,target,state,reversible,created,expires) VALUES(?,?,?,?,?,?,?)",
                             (case_id, action, target, "active", 1, time.time(), expires))
        return {"id": cur.lastrowid, "tier": tier, "state": "active", "expires": expires}

    def expire_responses(self) -> int:
        now = time.time()
        with self._connect() as db:
            cur = db.execute("UPDATE response_state SET state='reverted',reverted=? WHERE state='active' AND expires<=?",
                             (now, now))
        return max(0, cur.rowcount)

    def responses(self, case_id: str = "") -> List[Dict[str, Any]]:
        self.expire_responses()
        with self._connect() as db:
            if case_id:
                rows = db.execute("SELECT * FROM response_state WHERE case_id=? ORDER BY created DESC",
                                  (case_id,))
            else:
                rows = db.execute("SELECT * FROM response_state ORDER BY created DESC LIMIT 100")
            return [dict(row) for row in rows]
