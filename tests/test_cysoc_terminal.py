import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cli.cysoc_terminal import CYSOCTerminal
from cli.cysoc_commands import CYSOCCommandHandler
from core.soc_store import SOCStore


class _FlowEngine:
    def get_all_flows(self):
        return [SimpleNamespace()]


class _Rule:
    def get_alerts(self):
        return [SimpleNamespace(severity="high")]


class _Shell:
    pcap_file = "capture.pcap"
    session = SimpleNamespace(key="ESK-TEST-0001")
    flow_engine = _FlowEngine()
    rules = [_Rule()]
    llm_client = None

    def __init__(self):
        self.commands = []

    def get_packets(self):
        return [SimpleNamespace(), SimpleNamespace()]

    def _execute_command(self, line):
        self.commands.append(line)


class TestCYSOCTerminal(unittest.TestCase):
    def test_operational_commands_cover_queue_case_hunt_and_response(self):
        with tempfile.TemporaryDirectory() as folder:
            store = SOCStore(str(Path(folder) / "soc.db"))
            store.ingest([{"id": "A7", "severity": "critical",
                           "title": "C2 beacon", "hostname": "host-7",
                           "rule_name": "Beacon"}], "sentinel")
            handler = CYSOCCommandHandler(store)
            self.assertIn("critical=1", handler.handle("pulse"))
            self.assertIn("sentinel:A7", handler.handle("queue p1"))
            created = handler.handle("case create P1 Investigate host-7")
            case_id = created.split()[2].rstrip(".")
            self.assertIn("Linked", handler.handle(
                f"case link {case_id} sentinel:A7"))
            self.assertIn("host-7", handler.handle("hunt host-7"))
            requested = handler.handle(
                f"action request {case_id} Isolate host-7")
            self.assertIn("pending approval", requested)
            action_id = requested.split("#", 1)[1].split()[0]
            approved = handler.handle(f"action approve {action_id} lead")
            self.assertIn("execution still requires", approved)

    def test_nested_terminal_delegates_and_exit_returns(self):
        shell = _Shell()
        commands = iter(["overview", "events 5", "exit"])
        output = []
        with tempfile.TemporaryDirectory() as folder:
            store = SOCStore(str(Path(folder) / "soc.db"))
            CYSOCTerminal(shell, input_fn=lambda _prompt: next(commands),
                          output_fn=output.append, store=store).run()
        self.assertIn("events 5", shell.commands)
        self.assertNotIn("exit", shell.commands)
        self.assertTrue(any("CYSOC OVERVIEW" in row for row in output))
        self.assertEqual(output[-1], "Returning to EasyShark shell.")

    def test_case_status_reads_latest_soc_assessment(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(
                os.environ, {"EASYSHARK_REPORTS_DIR": folder}):
            Path(folder, "case.json").write_text(json.dumps({
                "conclusion": {"soc_assessment": {
                    "priority": "P1", "disposition": "confirmed_incident",
                    "evidence_coverage": 0.75,
                    "affected_hosts": ["10.0.0.7"],
                    "human_review_required": True,
                    "recommended_actions": [{"action": "isolate"}],
                }}
            }), encoding="utf-8")
            status = CYSOCTerminal(
                _Shell(), store=SOCStore(str(Path(folder) / "soc.db"))).case_status()
        self.assertIn("priority: P1", status)
        self.assertIn("evidence coverage: 75%", status)
        self.assertIn("10.0.0.7", status)

    def test_shell_entry_command_opens_nested_terminal(self):
        from cli.shell import InteractiveShell
        shell = InteractiveShell.__new__(InteractiveShell)
        with tempfile.TemporaryDirectory() as folder, patch.dict(
                os.environ, {"EASYSHARK_SOC_DB": str(Path(folder) / "soc.db")}), \
                patch("cli.cysoc_terminal.CYSOCTerminal.run") as run:
            shell._execute_command("soc-analyst terminal")
        run.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
