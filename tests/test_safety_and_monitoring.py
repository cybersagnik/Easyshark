import tempfile
import unittest
import zipfile
import json
import urllib.error
import urllib.request
from types import SimpleNamespace
from pathlib import Path

from core.artifacts import describe, safe_zip_listing
from core.monitor import PCAPMonitor
from core.policy import ActionTier, authorize
from ai.evidence_graph import EvidenceGraph, references_from_evidence
from core.job_queue import JobQueue
from core.alert_outbox import AlertOutbox
from core.threat_intel import ThreatIntel
from core.event_sink import JsonlSink, WebhookSink
from core.health import HealthServer
from ai.investigator import InvestigationReport
from cli.investigate_commands import InvestigateCommandHandler


class TestSafetyAndMonitoring(unittest.TestCase):
    def test_policy_requires_approval_for_external_action(self):
        self.assertFalse(authorize(ActionTier.EXTERNAL_NOTIFY))
        self.assertTrue(authorize(ActionTier.EXTERNAL_NOTIFY, approved=True))

    def test_artifact_hash_and_zip_listing(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            sample = root / "sample.bin"
            sample.write_bytes(b"abc")
            self.assertEqual(describe(str(sample))["size"], 3)
            archive = root / "sample.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("inside.txt", "ok")
            self.assertEqual(safe_zip_listing(str(archive))[0]["name"], "inside.txt")

    def test_monitor_processes_each_capture_once(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "a.pcap").write_bytes(b"x")
            seen = []
            monitor = PCAPMonitor(folder, seen.append, stable_for=0)
            self.assertEqual(monitor.scan_once(), 1)
            monitor._jobs.join()
            self.assertEqual(monitor.scan_once(), 0)
            self.assertEqual(len(seen), 1)

    def test_evidence_graph_links_claims(self):
        graph = EvidenceGraph()
        graph.node("packet:1", "packet", index=1)
        graph.claim("claim:1", "suspicious packet 1", references_from_evidence(["packet 1 observed"]))
        self.assertEqual(graph.as_dict()["edges"][0]["relation"], "supported_by")

    def test_evidence_graph_builds_capture_flows(self):
        from ai.evidence_graph import from_capture
        packet = SimpleNamespace(protocol="TCP", flow_key="a-b",
                                 src_ip="10.0.0.1", dst_ip="8.8.8.8")
        graph = from_capture([packet], [SimpleNamespace(src_ip="10.0.0.1",
                                                        dst_ip="8.8.8.8",
                                                        packet_count=1)], [])
        self.assertIn("flow:a-b", graph.nodes)

    def test_threat_intel_enriches_report_values(self):
        feed = tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                            delete=False, encoding="utf-8")
        try:
            feed.write('[{"value":"8.8.8.8","verdict":"malicious"}]')
            feed.close()
            handler = InvestigateCommandHandler.__new__(InvestigateCommandHandler)
            handler.threat_intel = ThreatIntel(feed.name)
            report = InvestigationReport(narrative="connection to 8.8.8.8")
            report.conclusion = {"iocs": []}
            handler._enrich_report(report)
            self.assertEqual(report.conclusion["threat_intel"]["8.8.8.8"]["verdict"],
                             "malicious")
        finally:
            Path(feed.name).unlink(missing_ok=True)

    def test_webhook_requires_explicit_api_approval(self):
        from core.monitor import WebhookAlerter
        with self.assertRaises(PermissionError):
            WebhookAlerter("https://example.invalid/events")

    def test_process_sandbox_allowlist(self):
        from ai.sandbox import run
        self.assertEqual(run("result = len(packets)", {"packets": [1, 2]})["result"], 2)
        self.assertIn("not allowed", run("import os", {})["error"])

    def test_health_endpoint_requires_token_and_reports_status(self):
        server = HealthServer(port=0, token="secret",
                              status_fn=lambda: {"queue": {"done": 2}})
        server.start()
        port = server.server.server_port
        try:
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2)
            self.assertEqual(ctx.exception.code, 401)
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/health",
                headers={"X-EasyShark-Token": "secret"})
            body = json.loads(urllib.request.urlopen(req, timeout=2).read())
            self.assertEqual(body["queue"]["done"], 2)
        finally:
            server.close()

    def test_job_queue_is_durable_and_retries(self):
        with tempfile.TemporaryDirectory() as folder:
            queue = JobQueue(str(Path(folder) / "jobs.db"))
            job_id = queue.enqueue("capture.pcap", "1:2", "inspect")
            self.assertEqual(queue.enqueue("capture.pcap", "1:2", "inspect"), job_id)
            job = queue.claim()
            self.assertEqual(job["status"], "running")
            queue.fail(job_id, "temporary")
            self.assertEqual(queue.claim()["id"], job_id)
            queue.complete(job_id)
            self.assertEqual(queue.stats()["done"], 1)

    def test_alert_outbox_persists_events(self):
        with tempfile.TemporaryDirectory() as folder:
            outbox = AlertOutbox(str(Path(folder) / "alerts.db"))
            outbox.put({"event": "mission_failed"})
            self.assertEqual(outbox.pending()[0]["event"]["event"], "mission_failed")

    def test_local_threat_intel_and_event_sink(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            feed = root / "intel.json"
            feed.write_text('[{"value":"evil.example","verdict":"malicious"}]', encoding="utf-8")
            intel = ThreatIntel(str(feed))
            self.assertEqual(intel.lookup("EVIL.EXAMPLE")["verdict"], "malicious")
            out = root / "events.jsonl"
            JsonlSink(str(out)).send("test", {"ok": True})
            self.assertIn('"schema": "easyshark.event.v1"', out.read_text(encoding="utf-8"))

    def test_webhook_event_sink_wraps_versioned_envelope(self):
        sent = []
        class FakeAlerter:
            def send(self, event):
                sent.append(event)
        WebhookSink(FakeAlerter()).send("mission_complete", {"id": 1})
        self.assertEqual(sent[0]["schema"], "easyshark.event.v1")
        self.assertEqual(sent[0]["payload"]["id"], 1)


if __name__ == "__main__":
    unittest.main()
