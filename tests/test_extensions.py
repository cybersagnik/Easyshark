import tempfile
import unittest
from pathlib import Path

from ai.mitre_export import generate_sigma, generate_spl, map_to_mitre
from core.analytics import roi_snapshot
from core.anonymizer import Anonymizer
from core.event_sink import EventBus


class Finding:
    type = "DNS tunnel"
    evidence = "packet 4"


class TestPlatformExtensions(unittest.TestCase):
    def test_event_bus_history_and_unsubscribe(self):
        with tempfile.TemporaryDirectory() as directory:
            bus = EventBus(store_path=str(Path(directory) / "events.db"))
            seen = []
            remove = bus.subscribe(seen.append)
            bus.publish("alert", {"id": 1})
            remove()
            bus.publish("alert", {"id": 2})
            self.assertEqual([row["payload"]["id"] for row in seen], [1])
            self.assertEqual(len(bus.history()), 2)

    def test_anonymizer_is_deterministic_and_redacts_email(self):
        anonymizer = Anonymizer("test-secret")
        text = anonymizer.text("connect 192.0.2.10 as alice@example.com")
        self.assertNotIn("192.0.2.10", text)
        self.assertNotIn("alice@example.com", text)
        self.assertEqual(text, anonymizer.text("connect 192.0.2.10 as alice@example.com"))

    def test_mitre_and_query_exports(self):
        findings = [Finding()]
        self.assertEqual(map_to_mitre(findings)[0]["id"], "T1071.004")
        self.assertIn("selection", generate_sigma(findings)["detection"])
        self.assertIn("T1071.004", generate_spl(findings))

    def test_roi_snapshot_reads_jsonl(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "calls.jsonl"
            path.write_text('{"gate_skipped": false, "response_ms": 100}\n'
                            '{"gate_skipped": true, "response_ms": 0}\n', encoding="utf-8")
            result = roi_snapshot(str(path))
        self.assertEqual(result["report_calls"], 2)
        self.assertEqual(result["llm_calls"], 1)
        self.assertEqual(result["gate_skips"], 1)


if __name__ == "__main__":
    unittest.main()
