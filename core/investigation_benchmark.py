"""Repeatable deterministic investigation latency benchmark."""
from __future__ import annotations

import argparse
import json
import tempfile
import time
from pathlib import Path
from typing import Any, Dict


def _timed(call):
    started = time.perf_counter()
    value = call()
    return value, round((time.perf_counter() - started) * 1000, 3)


def benchmark(pcap_path: str) -> Dict[str, Any]:
    from cli.investigate_commands import InvestigateCommandHandler
    from cli.shell import InteractiveShell
    from core.investigation_checkpoint import capture_sha256
    from core.session_manager import SessionManager

    capture = Path(pcap_path).resolve()
    if not capture.is_file():
        raise FileNotFoundError(str(capture))
    with tempfile.TemporaryDirectory(prefix="easyshark-benchmark-") as folder:
        manager = SessionManager(Path(folder) / "sessions")
        session = manager.create(str(capture))
        shell, load_ms = _timed(lambda: InteractiveShell(
            str(capture), enable_ai=False, session=session,
            session_manager=manager))
        handler = InvestigateCommandHandler(shell)
        first, cold_analysis_ms = _timed(handler._capture_analysis)
        second, memory_hit_ms = _timed(handler._capture_analysis)

        restored = manager.load(session.key)
        restarted, restart_load_ms = _timed(lambda: InteractiveShell(
            str(capture), enable_ai=False, session=restored,
            session_manager=manager))
        third, restart_analysis_ms = _timed(
            InvestigateCommandHandler(restarted)._capture_analysis)
        equivalent = ([vars(item) for item in first[3]]
                      == [vars(item) for item in second[3]]
                      == [vars(item) for item in third[3]]
                      and first[4] == second[4] == third[4])
        return {
            "schema": "easyshark.investigation-benchmark.v1",
            "pcap": str(capture),
            "pcap_sha256": capture_sha256(str(capture)),
            "packets": len(first[0]),
            "anomalies": len(first[3]),
            "equivalent": equivalent,
            "latency_ms": {
                "initial_load": load_ms,
                "cold_analysis": cold_analysis_ms,
                "memory_cache_hit": memory_hit_ms,
                "restart_load": restart_load_ms,
                "restart_cache_hit": restart_analysis_ms,
            },
        }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark cold, warm, and restarted deterministic analysis")
    parser.add_argument("pcap")
    parser.add_argument("--output", help="optional JSON output path")
    args = parser.parse_args(argv)
    result = benchmark(args.pcap)
    rendered = json.dumps(result, indent=2, sort_keys=True)
    print(rendered)
    if args.output:
        target = Path(args.output).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered + "\n", encoding="utf-8")
    return 0 if result["equivalent"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
