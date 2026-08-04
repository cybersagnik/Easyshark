"""
memory.py — Phase 10 §10.1 session memory (SQLite).

Stores three cross-session knowledge tables so a second run over the
same (or a related) PCAP benefits from prior investigations:

    iocs          ip / domain / md5 indicators seen + verdict + pcaps
    verdicts      per-hypothesis investigation verdicts (critic-audited)

Storage rules:
    - SQLite only. No external DB, no network writes, no cloud sync.
    - PCAP bytes are NEVER written — only metadata and text verdicts.
    - pcap_hash is the md5 of the PCAP *path* (not the content — content
      hashing is too slow for large captures).
    - Connection-per-call pattern: every public function opens its own
      connection, commits, and closes. Safe from multiple threads.

API:
    upsert_ioc(ioc_dict)          store_verdict(verdict_dict)
    recall_ioc(value)             approved_verdicts(n=50)
    recent_verdicts(n=10)         clear_all()         db_path()
    pcap_hash(path)

The DB lives at ~/.easyshark/memory.db and the parent dir is created
on first write. Tests can override the path via the EASYSHARK_MEMORY_DB
env var or by passing db_path to each function.
"""
from __future__ import annotations

import hashlib
import logging
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

MEMORY_DIR = Path(os.environ.get(
    "EASYSHARK_MEMORY_DIR", str(Path.home() / ".easyshark")))
MEMORY_DB_PATH = Path(os.environ.get(
    "EASYSHARK_MEMORY_DB", str(MEMORY_DIR / "memory.db")))

_SCHEMA = """
CREATE TABLE IF NOT EXISTS iocs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT,
    domain      TEXT,
    md5         TEXT,
    type        TEXT,
    first_seen  TEXT,
    last_seen   TEXT,
    verdict     TEXT,
    source_pcap TEXT
);
CREATE INDEX IF NOT EXISTS idx_iocs_ip     ON iocs(ip);
CREATE INDEX IF NOT EXISTS idx_iocs_domain ON iocs(domain);
CREATE INDEX IF NOT EXISTS idx_iocs_md5    ON iocs(md5);

CREATE TABLE IF NOT EXISTS verdicts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    pcap_hash       TEXT,
    hypothesis      TEXT,
    verdict         TEXT,
    confidence      REAL,
    critic_approved INTEGER,
    tools_used      TEXT,
    ts              TEXT
);
CREATE INDEX IF NOT EXISTS idx_verdicts_pcap ON verdicts(pcap_hash);
"""


def db_path() -> Path:
    return MEMORY_DB_PATH


def _connect(db_path: Optional[Path] = None) -> sqlite3.Connection:
    path = Path(db_path) if db_path is not None else MEMORY_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    return conn


def pcap_hash(path: str) -> str:
    """md5 of the PCAP path (not content) — fast, stable per file."""
    return hashlib.md5(str(path).encode("utf-8")).hexdigest()


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# --------------------------------------------------------------------------- #
# IOCs                                                                         #
# --------------------------------------------------------------------------- #
def upsert_ioc(ioc_dict: Dict[str, Any],
               db_path: Optional[Path] = None) -> Optional[int]:
    """Insert or update an IOC row.

    Accepts keys: ip | domain | md5 (the value), plus optional type,
    first_seen, last_seen, verdict, source_pcap. Upsert is keyed on the
    value column that is populated (ip / domain / md5). Returns the row
    id or None on failure.
    """
    ip = (ioc_dict.get("ip") or "").strip()
    domain = (ioc_dict.get("domain") or "").strip()
    md5 = (ioc_dict.get("md5") or "").strip()
    if not (ip or domain or md5):
        return None
    try:
        conn = _connect(db_path)
        try:
            row = None
            if ip:
                row = conn.execute(
                    "SELECT * FROM iocs WHERE ip = ?", (ip,)).fetchone()
            elif domain:
                row = conn.execute(
                    "SELECT * FROM iocs WHERE domain = ?", (domain,)).fetchone()
            elif md5:
                row = conn.execute(
                    "SELECT * FROM iocs WHERE md5 = ?", (md5,)).fetchone()
            now = ioc_dict.get("last_seen") or _now()
            verdict = (ioc_dict.get("verdict") or "")
            source = (ioc_dict.get("source_pcap") or "")
            ioc_type = (ioc_dict.get("type") or "")
            if row:
                first_seen = row["first_seen"] or now
                conn.execute(
                    "UPDATE iocs SET last_seen = ?, verdict = ?, "
                    "source_pcap = ?, type = ?, first_seen = ? WHERE id = ?",
                    (now, verdict, source, ioc_type, first_seen, row["id"]),
                )
                conn.commit()
                return int(row["id"])
            cur = conn.execute(
                "INSERT INTO iocs (ip, domain, md5, type, first_seen, "
                "last_seen, verdict, source_pcap) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (ip or None, domain or None, md5 or None, ioc_type,
                 ioc_dict.get("first_seen") or now, now, verdict, source),
            )
            conn.commit()
            return int(cur.lastrowid)
        finally:
            conn.close()
    except Exception as exc:
        logger.warning("upsert_ioc failed: %s", exc)
        return None


def recall_ioc(value: str, db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Look up an IOC by its value across ip/domain/md5 columns."""
    if not value:
        return None
    try:
        conn = _connect(db_path)
        try:
            row = conn.execute(
                "SELECT * FROM iocs WHERE ip = ? OR domain = ? OR md5 = ? "
                "ORDER BY last_seen DESC LIMIT 1",
                (value, value, value)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()
    except Exception as exc:
        logger.warning("recall_ioc failed: %s", exc)
        return None


# --------------------------------------------------------------------------- #
# Verdicts                                                                    #
# --------------------------------------------------------------------------- #
def store_verdict(verdict_dict: Dict[str, Any],
                  db_path: Optional[Path] = None) -> Optional[int]:
    """Persist one hypothesis verdict. Keys: pcap_hash, hypothesis,
    verdict, confidence, critic_approved, tools_used (optional)."""
    try:
        conn = _connect(db_path)
        try:
            tools = verdict_dict.get("tools_used") or []
            if isinstance(tools, (list, tuple)):
                tools = ", ".join(str(t) for t in tools)
            cur = conn.execute(
                "INSERT INTO verdicts (pcap_hash, hypothesis, verdict, "
                "confidence, critic_approved, tools_used, ts) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (verdict_dict.get("pcap_hash") or "",
                 verdict_dict.get("hypothesis") or "",
                 verdict_dict.get("verdict") or "",
                 verdict_dict.get("confidence") or 0.0,
                 1 if verdict_dict.get("critic_approved") else 0,
                 str(tools) if tools else "",
                 verdict_dict.get("ts") or _now()),
            )
            conn.commit()
            return int(cur.lastrowid)
        finally:
            conn.close()
    except Exception as exc:
        logger.warning("store_verdict failed: %s", exc)
        return None


def recent_verdicts(n: int = 10, db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    try:
        conn = _connect(db_path)
        try:
            rows = conn.execute(
                "SELECT * FROM verdicts ORDER BY id DESC LIMIT ?",
                (max(1, n),)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()
    except Exception as exc:
        logger.warning("recent_verdicts failed: %s", exc)
        return []


def approved_verdicts(n: int = 50, db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Recent critic-approved verdicts — the learning signal."""
    try:
        conn = _connect(db_path)
        try:
            rows = conn.execute(
                "SELECT * FROM verdicts WHERE critic_approved = 1 "
                "ORDER BY id DESC LIMIT ?", (max(1, n),)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()
    except Exception as exc:
        logger.warning("approved_verdicts failed: %s", exc)
        return []


# --------------------------------------------------------------------------- #
# Maintenance                                                                 #
# --------------------------------------------------------------------------- #
def clear_all(db_path: Optional[Path] = None) -> None:
    """Wipe all memory tables."""
    try:
        conn = _connect(db_path)
        try:
            for t in ("iocs", "verdicts"):
                conn.execute(f"DELETE FROM {t}")
            conn.commit()
        finally:
            conn.close()
    except Exception as exc:
        logger.warning("clear_all failed: %s", exc)
