"""Local SOC ROI and LLM cost metrics derived from existing JSONL telemetry."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def roi_snapshot(log_path: str | None = None) -> dict[str, Any]:
    candidate = log_path or os.environ.get("EASYSHARK_LLM_LOG")
    path = Path(candidate) if candidate else Path.home() / ".easyshark" / "llm_calls.jsonl"
    calls = []
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
                if isinstance(row, dict):
                    calls.append(row)
            except ValueError:
                continue
    return {"report_calls": len(calls),
            "llm_calls": sum(1 for row in calls if not row.get("gate_skipped")),
            "gate_skips": sum(1 for row in calls if row.get("gate_skipped")),
            "avg_response_ms": round(sum(row.get("response_ms", 0) for row in calls) / len(calls), 1) if calls else 0,
            "estimated_review_minutes_saved": len(calls) * 10}
