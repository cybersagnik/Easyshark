"""Independent SOC evaluation oracles and confidence calibration.

The critic may reject a claim inside one run, but only records in this store
are allowed to change cross-run tool patterns or confidence calibration.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence


ORACLE_KINDS = {"corpus", "synthetic", "rederive", "delayed_intel", "cross_path"}


class OracleStore:
    def __init__(self, path: Optional[str] = None):
        state = Path(os.environ.get("EASYSHARK_STATE_DIR", str(Path.home() / ".easyshark")))
        self.path = Path(path or os.environ.get("EASYSHARK_ORACLE_DB", str(state / "oracle.db")))
        schema = """
            CREATE TABLE IF NOT EXISTS runs(
              id TEXT PRIMARY KEY, kind TEXT NOT NULL, started REAL NOT NULL,
              completed REAL, cases INTEGER NOT NULL DEFAULT 0, metrics TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS outcomes(
              id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL,
              oracle_kind TEXT NOT NULL, subject TEXT NOT NULL,
              expected INTEGER NOT NULL, predicted INTEGER NOT NULL,
              confidence REAL NOT NULL, question TEXT NOT NULL DEFAULT '',
              tools TEXT NOT NULL DEFAULT '[]', evidence TEXT NOT NULL DEFAULT '{}',
              created REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_oracle_subject ON outcomes(subject,created);
            """
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self._connect() as db:
                db.executescript(schema)
        except (OSError, sqlite3.OperationalError):
            if path or os.environ.get("EASYSHARK_ORACLE_DB"):
                raise
            self.path = Path.cwd() / ".easyshark" / "oracle.db"
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self._connect() as db:
                db.executescript(schema)

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(str(self.path))
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        finally:
            db.close()

    def start(self, kind: str) -> str:
        if kind not in ORACLE_KINDS:
            raise ValueError(f"unknown oracle kind: {kind}")
        run_id = f"ORC-{int(time.time())}-{hashlib.sha256(os.urandom(8)).hexdigest()[:6]}"
        with self._connect() as db:
            db.execute("INSERT INTO runs(id,kind,started) VALUES(?,?,?)", (run_id, kind, time.time()))
        return run_id

    def record(self, run_id: str, *, kind: str, subject: str, expected: bool,
               predicted: bool, confidence: float, question: str = "",
               tools: Sequence[str] = (), evidence: Optional[Dict[str, Any]] = None) -> None:
        if kind not in ORACLE_KINDS:
            raise ValueError(f"unknown oracle kind: {kind}")
        confidence = max(0.0, min(1.0, float(confidence)))
        with self._connect() as db:
            db.execute("""INSERT INTO outcomes
              (run_id,oracle_kind,subject,expected,predicted,confidence,question,tools,evidence,created)
              VALUES(?,?,?,?,?,?,?,?,?,?)""", (run_id, kind, str(subject)[:200], int(expected),
              int(predicted), confidence, str(question)[:2000], json.dumps(list(tools)[:10]),
              json.dumps(evidence or {}, default=str), time.time()))

    def finish(self, run_id: str, cases: int = 0) -> Dict[str, Any]:
        metrics = self.metrics(run_id=run_id)
        with self._connect() as db:
            db.execute("UPDATE runs SET completed=?,cases=?,metrics=? WHERE id=?",
                       (time.time(), int(cases), json.dumps(metrics), run_id))
        return metrics

    def outcomes(self, limit: int = 500, run_id: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM outcomes"
        params: List[Any] = []
        if run_id:
            sql += " WHERE run_id=?"
            params.append(run_id)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(max(1, min(100000, int(limit))))
        with self._connect() as db:
            rows = [dict(row) for row in db.execute(sql, params)]
        for row in rows:
            row["tools"] = json.loads(row.get("tools") or "[]")
            row["evidence"] = json.loads(row.get("evidence") or "{}")
        return rows

    def metrics(self, run_id: Optional[str] = None) -> Dict[str, Any]:
        rows = self.outcomes(100000, run_id)
        if not rows:
            return {"samples": 0, "precision": None, "recall": None,
                    "brier": None, "ece": None}
        tp = sum(r["predicted"] and r["expected"] for r in rows)
        fp = sum(r["predicted"] and not r["expected"] for r in rows)
        fn = sum(not r["predicted"] and r["expected"] for r in rows)
        brier = sum((float(r["confidence"]) - int(r["expected"])) ** 2 for r in rows) / len(rows)
        ece = 0.0
        for low in [i / 10 for i in range(10)]:
            bucket = [r for r in rows if low <= float(r["confidence"]) <= (1.0 if low == .9 else low + .1)]
            if bucket:
                accuracy = sum(int(r["expected"]) for r in bucket) / len(bucket)
                mean_conf = sum(float(r["confidence"]) for r in bucket) / len(bucket)
                ece += len(bucket) / len(rows) * abs(accuracy - mean_conf)
        return {"samples": len(rows), "precision": round(tp / (tp + fp), 4) if tp + fp else None,
                "recall": round(tp / (tp + fn), 4) if tp + fn else None,
                "brier": round(brier, 4), "ece": round(ece, 4)}

    def calibrate(self, subject: str, raw: float) -> float:
        """Local reliability-bin calibration; falls back to raw with <5 labels."""
        rows = [r for r in self.outcomes(5000) if r["subject"] == subject]
        raw = max(0.0, min(1.0, float(raw)))
        near = [r for r in rows if abs(float(r["confidence"]) - raw) <= .15]
        if len(near) < 5:
            return raw
        empirical = sum(int(r["expected"]) for r in near) / len(near)
        # Beta(2,2) shrinkage avoids 0/1 certainty in small bins.
        return round((empirical * len(near) + 1.0) / (len(near) + 2.0), 4)

    def training_examples(self, limit: int = 200) -> List[Dict[str, Any]]:
        return [row for row in self.outcomes(limit) if row.get("question") and row.get("tools")]


def _capture_findings(path: Path) -> List[Dict[str, Any]]:
    """Run the deterministic PCAP path. Raw packet bytes remain local."""
    from core.loader import PCAPLoader
    from core.packet_metadata import PacketMetadata
    from core.flow_engine import FlowEngine
    from core.detectors import run_all
    raw = PCAPLoader(str(path)).load()
    packets = [PacketMetadata.from_packet(packet, index) for index, packet in enumerate(raw)]
    engine = FlowEngine()
    for packet in packets:
        engine.process_packet(packet)
    return [dict(type=item.type, score=item.score, hosts=item.hosts,
                 remote=item.remote, evidence=item.evidence)
            for item in run_all(packets, engine.get_all_flows())]


def run_corpus(manifest_path: str, store: Optional[OracleStore] = None) -> Dict[str, Any]:
    """Evaluate a JSON manifest of {pcap, labels:[detector_type,...]} cases."""
    manifest = Path(manifest_path).resolve()
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    cases = payload.get("cases", payload) if isinstance(payload, dict) else payload
    if not isinstance(cases, list):
        raise ValueError("corpus manifest must be a list or contain a cases list")
    oracle = store or OracleStore()
    oracle_kind = "synthetic" if isinstance(payload, dict) and payload.get("generated") else "corpus"
    run_id = oracle.start(oracle_kind)
    failures = []
    for index, case in enumerate(cases):
        try:
            pcap = (manifest.parent / str(case["pcap"])).resolve()
            expected = {str(x) for x in (case.get("labels") or case.get("detectors") or [])}
            findings = _capture_findings(pcap)
            scores = {str(row["type"]): max(float(row["score"]), 0.0) for row in findings}
            for subject in sorted(expected | set(scores)):
                oracle.record(run_id, kind=oracle_kind, subject=subject,
                              expected=subject in expected, predicted=subject in scores,
                              confidence=scores.get(subject, 0.0),
                              evidence={"case": index, "pcap_sha256": _sha256(pcap)})
        except Exception as exc:
            failures.append({"case": index, "error": str(exc)})
    metrics = oracle.finish(run_id, len(cases) - len(failures))
    return {"run_id": run_id, "cases": len(cases), "failed": failures, **metrics}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def cross_path_score(deterministic: Iterable[str], model_claims: Iterable[str],
                     store: Optional[OracleStore] = None) -> Dict[str, Any]:
    left, right = set(deterministic), set(model_claims)
    oracle = store or OracleStore()
    run_id = oracle.start("cross_path")
    for subject in sorted(left | right):
        oracle.record(run_id, kind="cross_path", subject=subject,
                      expected=subject in left, predicted=subject in right,
                      confidence=1.0 if subject in right else 0.0)
    return {"run_id": run_id, **oracle.finish(run_id, 1)}


def rederive_report(report_path: str, store: Optional[OracleStore] = None) -> Dict[str, Any]:
    """Re-score hypothesis claims solely from persisted evidence-graph links."""
    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    hypotheses = report.get("hypotheses") or []
    nodes = (report.get("evidence_graph") or {}).get("nodes") or []
    claims = {str(node.get("id")): node for node in nodes if node.get("kind") == "claim"}
    oracle = store or OracleStore()
    run_id = oracle.start("rederive")
    for index, hypothesis in enumerate(hypotheses, 1):
        claim = claims.get(f"hypothesis:{index}", {})
        expected = bool(claim.get("grounded"))
        predicted = str(hypothesis.get("verdict", "")).lower() == "confirmed"
        raw = hypothesis.get("numeric_confidence") or hypothesis.get("calibrated_confidence")
        try:
            confidence = float(raw)
        except (TypeError, ValueError):
            confidence = {"high": .85, "medium": .6, "low": .3}.get(
                str(hypothesis.get("confidence_after") or hypothesis.get("confidence", "low")).lower(), .3)
        oracle.record(run_id, kind="rederive", subject=str(hypothesis.get("name", "hypothesis")),
                      expected=expected, predicted=predicted, confidence=confidence,
                      question=str(hypothesis.get("name", "")),
                      tools=hypothesis.get("tools_used") or [], evidence={"claim": claim})
    return {"run_id": run_id, **oracle.finish(run_id, 1)}


def generate_synthetic_corpus(output_dir: str) -> Dict[str, Any]:
    """Create deterministic labelled PCAPs for repeatable detector regression."""
    target = Path(output_dir).resolve()
    target.mkdir(parents=True, exist_ok=True)
    try:
        from scapy.all import Ether, IP, TCP, Raw, wrpcap
    except ImportError as exc:
        raise RuntimeError("Scapy is required for synthetic PCAP generation") from exc

    beacon = []
    for index in range(20):
        packet = Ether()/IP(src="10.10.0.7", dst="198.51.100.20")/TCP(
            sport=45000 + index, dport=4444, flags="S")
        packet.time = 1700000000 + index * 30
        beacon.append(packet)
    beacon_path = target / "synthetic-beacon.pcap"
    wrpcap(str(beacon_path), beacon)

    scan = []
    for index in range(30):
        packet = Ether()/IP(src="10.10.0.8", dst=f"10.20.0.{index + 1}")/TCP(
            sport=46000 + index, dport=22 + index, flags="S")
        packet.time = 1700001000 + index
        scan.append(packet)
    scan_path = target / "synthetic-scan.pcap"
    wrpcap(str(scan_path), scan)

    manifest = {"schema": "easyshark.corpus.v1", "generated": time.time(), "cases": [
        {"pcap": beacon_path.name, "labels": ["beaconing"]},
        {"pcap": scan_path.name, "labels": ["port_scan_horizontal", "lateral_movement"]},
    ]}
    manifest_path = target / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return {"directory": str(target), "manifest": str(manifest_path), "cases": 2}
