"""Offline RSI benchmark scoring for labelled investigation cases."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List


def load_cases(path: str) -> List[Dict[str, Any]]:
    cases = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            if not row.get("question") or not row.get("expected_tools"):
                raise ValueError("benchmark cases require question and expected_tools")
            cases.append(row)
    return cases


def score(patterns: Iterable[Dict[str, Any]], cases: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Score tool recommendations against independent labelled cases."""
    rows = list(patterns)
    total = correct = predicted = expected = 0
    details = []
    for case in cases:
        words = set(str(case["question"]).lower().split())
        matching = [p for p in rows if words & set(p.get("question_keywords") or [])]
        tools = []
        for pattern in matching:
            if pattern.get("status") == "active":
                tools.extend(pattern.get("tool_sequence") or [])
        actual, wanted = set(tools), set(case["expected_tools"])
        correct += len(actual & wanted)
        predicted += len(actual)
        expected += len(wanted)
        total += 1
        details.append({"question": case["question"], "predicted": sorted(actual),
                        "expected": sorted(wanted), "correct": sorted(actual & wanted)})
    return {"cases": total,
            "precision": correct / predicted if predicted else 0.0,
            "recall": correct / expected if expected else 0.0,
            "details": details}
