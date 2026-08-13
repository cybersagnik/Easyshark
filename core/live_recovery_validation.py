"""Opt-in real-provider autonomous crash/resume equivalence harness."""
from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict


class InjectedTermination(RuntimeError):
    pass


def _projection(state: Dict[str, Any]):
    return [{
        "id": row.get("id"), "hypothesis": row.get("hypothesis"),
        "verdict": row.get("verdict"), "evidence_refs": row.get("evidence_refs"),
    } for row in state.get("plan", [])]


def validate(pcap_path: str, mission: str) -> Dict[str, Any]:
    capture = Path(pcap_path).resolve()
    if not capture.is_file():
        raise FileNotFoundError(str(capture))
    previous = {name: os.environ.get(name) for name in (
        "EASYSHARK_STATE_DIR", "EASYSHARK_SESSIONS_DIR", "EASYSHARK_QUEUE_DB",
        "EASYSHARK_MEMORY_DIR", "EASYSHARK_REPORTS_DIR", "EASYSHARK_ORACLE_DB")}
    try:
        with tempfile.TemporaryDirectory(prefix="easyshark-live-recovery-") as folder:
            root = Path(folder)
            os.environ.update({
                "EASYSHARK_STATE_DIR": str(root),
                "EASYSHARK_SESSIONS_DIR": str(root / "sessions"),
                "EASYSHARK_QUEUE_DB": str(root / "jobs.db"),
                "EASYSHARK_MEMORY_DIR": str(root),
                "EASYSHARK_REPORTS_DIR": str(root / "reports"),
                "EASYSHARK_ORACLE_DB": str(root / "oracle.db"),
            })
            from cli.investigate_commands import InvestigateCommandHandler
            from cli.shell import InteractiveShell
            from core.session_manager import SessionManager

            manager = SessionManager(root / "sessions")

            def shell_for(session):
                shell = InteractiveShell(str(capture), enable_ai=True,
                                         session=session, session_manager=manager)
                client = shell._ensure_llm_client()
                if client is None or not client.is_available():
                    raise RuntimeError("no real LLM provider is available")
                return shell

            reference_session = manager.create(str(capture))
            reference = InvestigateCommandHandler(shell_for(reference_session))
            reference.handle("autonomous " + mission)
            reference_state = manager.load(reference_session.key).investigation_state

            crash_session = manager.create(str(capture))
            crash_handler = InvestigateCommandHandler(shell_for(crash_session))
            persist = crash_handler._checkpoint_event
            terminated = False

            def persist_then_terminate(event, payload):
                nonlocal terminated
                persist(event, payload)
                if event == "hypothesis_verdict" and not terminated:
                    terminated = True
                    raise InjectedTermination("injected after durable verdict")

            crash_handler._checkpoint_event = persist_then_terminate
            try:
                crash_handler.handle("autonomous " + mission)
            except InjectedTermination:
                pass
            if not terminated:
                raise RuntimeError("fault injection point was not reached")
            interrupted_state = manager.load(crash_session.key).investigation_state
            durable = [row for row in interrupted_state.get("plan", [])
                       if row.get("status") == "complete"]
            if not durable:
                raise RuntimeError("no verdict was durable before termination")

            resumed_session = manager.load(crash_session.key)
            resumed = InvestigateCommandHandler(shell_for(resumed_session))
            resumed.handle("autonomous " + mission)
            resumed_state = manager.load(crash_session.key).investigation_state
            preserved = all(next(
                (row for row in resumed_state["plan"] if row.get("id") == old.get("id")),
                {}) == old for old in durable)
            equivalent = _projection(reference_state) == _projection(resumed_state)
            gates = {
                "termination_injected": terminated,
                "durable_verdict_preserved": preserved,
                "resume_completed": resumed_state.get("status") == "complete",
                "reference_equivalent": equivalent,
            }
            return {
                "schema": "easyshark.live-recovery-validation.v1",
                "ready": all(gates.values()), "gates": gates,
                "reference": _projection(reference_state),
                "resumed": _projection(resumed_state),
                "provider_budget": resumed_state.get("budgets", {}),
            }
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Run an opt-in real-provider kill/resume equivalence test")
    parser.add_argument("pcap")
    parser.add_argument("--mission", default="Investigate suspicious activity")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    result = validate(args.pcap, args.mission)
    rendered = json.dumps(result, indent=2, sort_keys=True)
    print(rendered)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    return 0 if result["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
