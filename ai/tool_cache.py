"""
tool_cache.py — Phase 10 §10.3 session-scoped tool result cache.

Caches deterministic forensic tool results in an in-memory dict so a
second identical tool call (same tool, same args, same PCAP) within a
session short-circuits without recomputing. This matters because the
LLM tool loop frequently re-invokes the same tool (e.g. two hypotheses
both calling get_email_attachments) and the payload_analyzer parsers
are the slow part of a run.

Rules:
    - In-memory ONLY. Never persisted to disk, never shared across
      sessions, never written to the SQLite memory DB.
    - Keyed by sha256(tool_name + json(args, sorted) + pcap_hash).
      pcap_hash comes from core.memory.pcap_hash(pcap_path); when the
      ToolContext has no pcap path the hash part is empty (the cache is
      still correct within a single-capture session).
    - Cleared on PCAP reload (hot-reload path clears it).
    - Thread-safe (the DAG executor can run in threads in some flows).

Public API:
    get(tool_name, args, pcap_hash) -> Optional[dict]
    set(tool_name, args, pcap_hash, result) -> None
    stats() -> dict            # {size, hits, misses, keys}
    clear() -> None
"""
from __future__ import annotations

import hashlib
import json
import threading
from typing import Any, Dict, Optional

_lock = threading.Lock()
_cache: Dict[str, Dict[str, Any]] = {}
_hits = 0
_misses = 0


def _key(tool_name: str, args: Dict[str, Any],
         pcap_hash: Optional[str]) -> str:
    material = json.dumps(args or {}, sort_keys=True, default=str)
    raw = f"{tool_name}|{material}|{pcap_hash or ''}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def get(tool_name: str, args: Dict[str, Any],
        pcap_hash: Optional[str] = None) -> Optional[Dict[str, Any]]:
    global _hits, _misses
    k = _key(tool_name, args, pcap_hash)
    with _lock:
        if k in _cache:
            _hits += 1
            return _cache[k]
        _misses += 1
        return None


def set(tool_name: str, args: Dict[str, Any],
        pcap_hash: Optional[str], result: Dict[str, Any]) -> None:
    with _lock:
        _cache[_key(tool_name, args, pcap_hash)] = result


def stats() -> Dict[str, Any]:
    with _lock:
        return {
            "size": len(_cache),
            "hits": _hits,
            "misses": _misses,
            "keys": sorted(_cache.keys()),
        }


def clear() -> None:
    global _hits, _misses
    with _lock:
        _cache.clear()
        _hits = 0
        _misses = 0
