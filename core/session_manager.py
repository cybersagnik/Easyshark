"""
Phase 16 TASK 2 — session key save/restore.

A session ties one shell run to a PCAP. Each run gets a key of the form
``ESK-XXXX-XXXX`` (ESK- + 8 alphanumeric chars split 4+4, collision
checked against the store). Sessions are plain JSON files under
``~/.easyshark/sessions/<key>.json`` — PCAP bytes are NEVER written;
only the path hash, the deterministic triage cache, the Q&A
conversation, per-role x provider call counts and the per-role
exhaustion matrix.

Schema of a session file::

    {
        "key": "ESK-XXXX-XXXX",
        "created_at": "2026-08-04T...Z",
        "last_active": "2026-08-04T...Z",
        "pcap_path": "...",
        "pcap_hash": "<md5 of the pcap path>",
        "conversation": [{"role": "user|assistant", "content": "...", "ts": "..."}],
        "provider_counts": {"<role>": {"<provider>": <int>},
                            "__totals__": {"zen": <int>, "openrouter": <int>,
                                           "groq": <int>, "fallbacks": <int>,
                                           "ssl_failures": <int>}},
        "exhausted": {"<role>": ["<provider>", ...]},
        "triage_cache": {...},
        "investigation_state": {...}
    }

All writes are best-effort: save() returns a bool and never raises, so
the interactive shell can auto-save after every turn without ever
crashing the REPL.
"""
from __future__ import annotations

import json
import os
import secrets
import string
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.memory import pcap_hash
from ai.prompt_optimizer import estimate_tokens

SESSIONS_DIR = Path(
    os.environ.get(
        "EASYSHARK_SESSIONS_DIR",
        str(Path.home() / ".easyshark" / "sessions"),
    )
)

# Roles the routing layer understands (used for the provider_counts
# schema and for propagating global exhaustion).
ROLES = ("planner", "explainer", "coder", "critic")

# Key alphabet — uppercase alphanumerics (avoids I/O/1/0 ambiguity).
_KEY_ALPHABET = string.ascii_uppercase + string.digits
_MAX_TURNS = 30          # conversation is bounded to this many Q/A pairs
_MAX_TURN_CHARS = 4000   # per message cap before recording
_SAVE_LOCK = threading.RLock()


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass
class SessionData:
    """In-memory representation of one session file."""

    key: str
    created_at: str
    last_active: str
    pcap_path: str
    pcap_hash: str
    conversation: List[Dict[str, str]] = field(default_factory=list)
    provider_counts: Dict[str, Any] = field(default_factory=dict)
    exhausted: Dict[str, List[str]] = field(default_factory=dict)
    triage_cache: Dict[str, Any] = field(default_factory=dict)
    investigation_state: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SessionData":
        return cls(
            key=str(d.get("key", "")),
            created_at=str(d.get("created_at", "")),
            last_active=str(d.get("last_active", "")),
            pcap_path=str(d.get("pcap_path", "")),
            pcap_hash=str(d.get("pcap_hash", "")),
            conversation=list(d.get("conversation", []) or []),
            provider_counts=dict(d.get("provider_counts", {}) or {}),
            exhausted=dict(d.get("exhausted", {}) or {}),
            triage_cache=dict(d.get("triage_cache", {}) or {}),
            investigation_state=dict(d.get("investigation_state", {}) or {}),
        )


class SessionManager:
    """CRUD + Q&A helpers over the ~/.easyshark/sessions/ store."""

    def __init__(self, sessions_dir: Optional[Path] = None):
        self.dir = Path(sessions_dir) if sessions_dir is not None else SESSIONS_DIR
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # Storage                                                            #
    # ------------------------------------------------------------------ #
    def _path(self, key: str) -> Path:
        safe = "".join(c for c in str(key) if c.isalnum() or c in "-_")
        return self.dir / f"{safe}.json"

    def _generate_key(self) -> str:
        while True:
            head = "".join(secrets.choice(_KEY_ALPHABET) for _ in range(4))
            tail = "".join(secrets.choice(_KEY_ALPHABET) for _ in range(4))
            key = f"ESK-{head}-{tail}"
            if not self._path(key).exists():
                return key

    def create(self,
               pcap_path: str,
               triage_cache: Optional[Dict[str, Any]] = None,
               investigation_state: Optional[Dict[str, Any]] = None,
               ) -> SessionData:
        now = _now_iso()
        s = SessionData(
            key=self._generate_key(),
            created_at=now,
            last_active=now,
            pcap_path=str(pcap_path),
            pcap_hash=pcap_hash(pcap_path),
            triage_cache=dict(triage_cache or {}),
            investigation_state=dict(investigation_state or {}),
        )
        self.save(s)
        return s

    def save(self, s: SessionData) -> bool:
        """Write the session to disk. Best-effort; returns False on any
        failure (never raises)."""
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            target = self._path(s.key)
            # Replace in one operation so a dashboard never observes a
            # partially-written session while the CLI is saving a turn.
            with _SAVE_LOCK:
                with tempfile.NamedTemporaryFile(
                    "w", encoding="utf-8", dir=self.dir,
                    prefix=f".{target.stem}.", suffix=".tmp", delete=False,
                ) as fh:
                    json.dump(asdict(s), fh, indent=2, default=str)
                    temporary = Path(fh.name)
                temporary.replace(target)
            return True
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning(
                "session save failed for %s: %s", getattr(s, "key", "?"), exc)
            return False

    def load(self, key: str) -> Optional[SessionData]:
        p = self._path(key)
        if not p.exists():
            return None
        try:
            return SessionData.from_dict(json.loads(p.read_text()))
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning(
                "session load failed for %s: %s", key, exc)
            return None

    def delete(self, key: str) -> bool:
        p = self._path(key)
        try:
            if p.exists():
                p.unlink()
            return True
        except Exception:
            return False

    def list_sessions(self) -> List[SessionData]:
        """All sessions, sorted by last_active descending."""
        out: List[SessionData] = []
        try:
            files = list(self.dir.glob("*.json"))
        except Exception:
            return out
        for p in files:
            s = self.load(p.stem)
            if s is not None and s.key:
                out.append(s)
        out.sort(key=lambda s: s.last_active, reverse=True)
        return out

    def latest(self) -> Optional[SessionData]:
        lst = self.list_sessions()
        return lst[0] if lst else None

    # ------------------------------------------------------------------ #
    # Q&A helpers                                                        #
    # ------------------------------------------------------------------ #
    def record_turn(self, s: SessionData, question: str, answer: str) -> None:
        """Append one (user, assistant) pair and bump last_active."""
        now = _now_iso()
        s.conversation.append({
            "role": "user",
            "content": (question or "")[:_MAX_TURN_CHARS],
            "ts": now,
        })
        s.conversation.append({
            "role": "assistant",
            "content": (answer or "")[:_MAX_TURN_CHARS],
            "ts": now,
        })
        if len(s.conversation) > _MAX_TURNS * 2:
            s.conversation = s.conversation[-_MAX_TURNS * 2:]
        s.last_active = now

    def recent_pairs(self, s: SessionData, n: int = 3) -> List[Tuple[str, str]]:
        """The last n (question, answer) pairs, oldest-first."""
        msgs = s.conversation or []
        pairs: List[Tuple[str, str]] = []
        i = len(msgs)
        while i >= 2 and len(pairs) < n:
            q = msgs[i - 2]
            a = msgs[i - 1]
            if q.get("role") == "user" and a.get("role") == "assistant":
                pairs.append((q.get("content", ""), a.get("content", "")))
            i -= 2
        pairs.reverse()
        return pairs

    def conversation_context(self,
                             s: Optional[SessionData],
                             max_pairs: int = 3,
                             max_tokens: int = 600) -> List[str]:
        """Last few Q/A pairs formatted for LLM continuity injection.

        Returns a list of ``"Q: ...\\nA: ..."`` strings. Empty when fewer
        than 2 prior turns exist (the "only if >=2 prior turns" gate).
        The total is trimmed to ``max_tokens`` using the cheap
        estimate_tokens proxy so the injected block never blows the
        context budget.
        """
        if s is None:
            return []
        pairs = self.recent_pairs(s, max_pairs)
        if len(pairs) < 2:
            return []
        out: List[str] = []
        budget = 0
        for q, a in pairs:
            item = f"Q: {q}\nA: {a}"
            t = estimate_tokens(item)
            if out and budget + t > max_tokens:
                break
            out.append(item)
            budget += t
        return out
