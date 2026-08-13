"""Fail-closed production evidence gate for EasyShark v2."""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List


REQUIRED_TRAFFIC_CLASSES = {
    "attack", "benign", "encrypted", "malformed", "noisy",
}


def _gate(name: str, passed: bool, detail: str) -> Dict[str, Any]:
    return {"name": name, "passed": bool(passed), "detail": detail}


def assess_manifest(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    cases = payload.get("cases") if isinstance(payload, dict) else None
    cases = cases if isinstance(cases, list) else []
    provenance = payload.get("provenance", {}) if isinstance(payload, dict) else {}
    labeling = payload.get("labeling", {}) if isinstance(payload, dict) else {}
    classes = {str(tag).lower() for case in cases if isinstance(case, dict)
               for tag in case.get("traffic_classes", [])}
    held_out = sum(isinstance(case, dict)
                   and str(case.get("split", "")).lower() in {"test", "held_out"}
                   for case in cases)
    independent = (labeling.get("independent") is True
                   and int(labeling.get("reviewers", 0) or 0) >= 2
                   and str(provenance.get("kind", "")).lower() != "synthetic")
    unique_hashes = {str(case.get("sha256", "")).lower()
                     for case in cases if isinstance(case, dict)}
    return [
        _gate("schema", payload.get("schema") == "easyshark.corpus.v2",
              "manifest schema must be easyshark.corpus.v2"),
        _gate("case_count", len(cases) >= 500,
              f"{len(cases)} cases; production minimum is 500"),
        _gate("independent_labels", independent,
              "requires non-synthetic provenance and two independent reviewers"),
        _gate("held_out_split", held_out >= max(100, len(cases) // 5),
              f"{held_out} held-out cases; requires at least 100 and 20 percent"),
        _gate("traffic_classes", REQUIRED_TRAFFIC_CLASSES <= classes,
              "present=" + ",".join(sorted(classes))),
        _gate("unique_captures", len(unique_hashes) == len(cases)
              and "" not in unique_hashes,
              f"{len(unique_hashes)} unique non-empty capture hashes"),
    ]


def assess_metrics(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    failed = result.get("failed") or []
    by_subject = result.get("by_subject") or {}
    subject_errors = sum(int(row.get("false_positives", 0) or 0)
                         + int(row.get("false_negatives", 0) or 0)
                         for row in by_subject.values())
    ece = result.get("ece")
    brier = result.get("brier")
    return [
        _gate("corpus_execution", not failed,
              f"{len(failed)} cases failed to execute"),
        _gate("calibration_ece", ece is not None and float(ece) < 0.10,
              f"ECE={ece}; target is below 0.10"),
        _gate("brier_score", brier is not None and float(brier) <= 0.15,
              f"Brier={brier}; release ceiling is 0.15"),
        _gate("detector_errors", subject_errors == 0,
              f"{subject_errors} aggregate false positives/negatives"),
    ]


def environment_gates() -> List[Dict[str, Any]]:
    return [
        _gate("python", sys.version_info >= (3, 12), sys.version.split()[0]),
        _gate("tshark", shutil.which("tshark") is not None,
              shutil.which("tshark") or "not installed"),
    ]


def result_document(gates: Iterable[Dict[str, Any]], **extra: Any) -> Dict[str, Any]:
    rows = list(gates)
    return {"schema": "easyshark.production-gate.v1",
            "ready": bool(rows) and all(row["passed"] for row in rows),
            "gates": rows, **extra}


def run(manifest_path: str, *, metadata_only: bool = False) -> Dict[str, Any]:
    path = Path(manifest_path).resolve()
    payload = json.loads(path.read_text(encoding="utf-8"))
    gates = assess_manifest(payload) + environment_gates()
    evaluation = None
    if not metadata_only:
        from ai.oracle import run_corpus
        evaluation = run_corpus(str(path))
        gates.extend(assess_metrics(evaluation))
    return result_document(gates, manifest=str(path), evaluation=evaluation)


def main(argv: Any = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate v2 production evidence")
    parser.add_argument("manifest", help="independently labelled corpus manifest")
    parser.add_argument("--metadata-only", action="store_true",
                        help="validate corpus contract without opening captures")
    args = parser.parse_args(argv)
    result = run(args.manifest, metadata_only=args.metadata_only)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
