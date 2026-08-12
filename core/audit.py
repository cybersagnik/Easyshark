"""Append-only local audit events for autonomous operations."""
from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

AUDIT_PATH = Path(os.environ.get(
    "EASYSHARK_AUDIT_PATH", str(Path.home() / ".easyshark" / "audit.jsonl")))


def record(action: str, actor: str = "system", **details: Any) -> None:
    if not action or not isinstance(action, str):
        raise ValueError("audit action is required")
    row: Dict[str, Any] = {"ts": time.time(), "actor": actor,
                           "action": action, "details": details}
    try:
        AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, default=str, ensure_ascii=False) + "\n")
    except OSError as exc:
        # Audit failure must not stop packet monitoring or analysis. Try the
        # repository-local state fallback used by the CLI before giving up.
        fallback = Path(os.environ.get(
            "EASYSHARK_STATE_DIR", str(Path.cwd() / ".easyshark"))) / "audit.jsonl"
        if fallback != AUDIT_PATH:
            try:
                fallback.parent.mkdir(parents=True, exist_ok=True)
                with fallback.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(row, default=str, ensure_ascii=False) + "\n")
                return
            except OSError:
                pass
        logger.debug("audit write failed: %s", exc)


def path() -> Path:
    return AUDIT_PATH
