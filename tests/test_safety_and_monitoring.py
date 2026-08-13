import tempfile
import unittest
import zipfile
import os
import json
import urllib.error
import urllib.request
from unittest.mock import patch
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
from cli.commands import CommandHandler


class TestSafetyAndMonitoring(unittest.TestCase):
    def test_investigation_reuses_deterministic_capture_analysis(self):
        packet = SimpleNamespace()
        shell = SimpleNamespace(
            pcap_file="missing-test-capture.pcap",
            index=SimpleNamespace(packets=[packet]),
            flow_engine=SimpleNamespace(get_all_flows=lambda: []),
            rules=[],
            get_packets=lambda: [packet],
        )
        anomaly = SimpleNamespace(type="beaconing")
        with patch("core.detectors.run_all", return_value=[anomaly]) as detect, \
                patch("core.narrative.build", return_value="cached narrative") as build:
            first = InvestigateCommandHandler(shell)._capture_analysis()
            second = InvestigateCommandHandler(shell)._capture_analysis()
            shell.index.packets.append(SimpleNamespace())
            InvestigateCommandHandler(shell)._capture_analysis()
        self.assertIs(first[3], second[3])
        self.assertEqual(second[4], "cached narrative")
        self.assertEqual(detect.call_count, 2,
                         "packet-count changes must invalidate the cache")
        self.assertEqual(build.call_count, 2)

    def test_manual_decline_skips_expensive_hypothesis_verification(self):
        class FakeLLM:
            calls = 0

            def is_available(self):
                return True

            def query_with_tools(self, *args, **kwargs):
                self.calls += 1
                return '{}'

        shell = SimpleNamespace(
            llm_client=FakeLLM(),
            get_packets=lambda: [],
            flow_engine=SimpleNamespace(get_all_flows=lambda: []),
            rules=[],
            stats_engine=None,
            pcap_file="missing-test-capture.pcap",
            triage={},
            dissection={},
        )

        def decline(event, payload):
            if event == "hypothesis_start":
                payload["_skip_this"] = True

        hypothesis_json = json.dumps([{
            "name": "Test hypothesis",
            "description": "Needs verification",
            "confidence": "medium",
        }])
        conclusion_json = json.dumps({"analyst_summary": "declined"})
        with patch("core.detectors.run_all", return_value=[]), \
                patch("core.narrative.build", return_value="summary"), \
                patch("ai.investigator._single_completion",
                      side_effect=[hypothesis_json, conclusion_json]):
            from ai.investigator import investigate
            report = investigate(shell, on_event=decline)
        self.assertEqual(shell.llm_client.calls, 0)
        self.assertEqual(report.hypotheses[0].verdict, "ruled_out")
        self.assertIn("declined", report.hypotheses[0].reasoning)

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

    def test_webhook_failure_is_drained_after_recovery(self):
        calls = []
        class Response:
            status = 200
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                return False
        def fake_urlopen(_request, timeout=None):
            calls.append(timeout)
            if len(calls) == 1:
                raise RuntimeError("temporary delivery failure")
            return Response()
        with tempfile.TemporaryDirectory() as folder:
            outbox = str(Path(folder) / "outbox.db")
            from core.monitor import WebhookAlerter
            alerter = WebhookAlerter("https://example.invalid/events", retries=0,
                                     outbox_path=outbox, approved=True)
            with patch("core.monitor.urllib.request.urlopen", fake_urlopen):
                with self.assertRaises(RuntimeError):
                    alerter.send({"event": "mission_failed"})
                self.assertEqual(len(alerter.outbox.pending()), 1)
                self.assertEqual(alerter.drain(), 1)
                self.assertEqual(alerter.outbox.pending(), [])
                self.assertEqual(len(calls), 2)

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

    def test_threat_intel_provider_normalization_and_persistence(self):
        intel = ThreatIntel()
        responses = [
            [{"ip_address": "1.2.3.4", "port": 443,
              "malware": "QakBot", "status": "online"}],
            {"urls": [{"url": "https://bad.example/drop", "threat": "malware",
                       "tags": "elf, loader"}]},
            {"query_status": "ok", "data": [{
                "ioc": "5.6.7.8:8443", "threat_type": "botnet_cc",
                "malware": "win.test", "tags": ["c2"]}]},
        ]
        with patch.object(intel, "_request_json", side_effect=responses):
            self.assertEqual(intel.update_provider("feodo"), 1)
            self.assertEqual(intel.update_provider("urlhaus", "key"), 2)
            self.assertEqual(intel.update_provider("threatfox", "key"), 2)
        self.assertEqual(intel.lookup("1.2.3.4")["source"], "feodo")
        self.assertEqual(intel.lookup("bad.example")["source"], "urlhaus")
        self.assertEqual(intel.lookup("5.6.7.8")["source"], "threatfox")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "intel.json"
            self.assertEqual(intel.save_file(str(path)), 5)
            self.assertEqual(ThreatIntel(str(path)).lookup("bad.example")["verdict"],
                             "malicious")

    def test_terminal_feed_update_and_ioc_check(self):
        with tempfile.TemporaryDirectory() as folder:
            cache = Path(folder) / "intel.json"
            handler = CommandHandler(SimpleNamespace())
            with patch.dict(os.environ,
                            {"EASYSHARK_THREAT_FEED_CACHE": str(cache)}, clear=False), \
                    patch.object(ThreatIntel, "_request_json", return_value=[{
                        "ip_address": "9.8.7.6", "port": 443,
                        "malware": "QakBot", "status": "online",
                    }]):
                updated = handler.handle("update-feeds feodo")
                match = handler.handle("ioc-check 9.8.7.6")
            self.assertIn("feodo: 1 new", updated)
            self.assertTrue(cache.is_file())
            self.assertIn("IOC MATCH: 9.8.7.6", match)

    def test_linear_autonomous_report_contains_evidence_graph(self):
        from ai.investigator import Hypothesis
        import cli.investigate_commands as commands
        report = InvestigationReport(
            narrative="packet 0 was suspicious",
            hypotheses=[Hypothesis(
                name="Beacon", description="Periodic traffic", confidence="high",
                evidence_found=["packet 0 observed"], verdict="confirmed",
                confidence_after="high", reasoning="packet 0 supports it")],
            conclusion={"incident_narrative": "Beaconing observed.",
                        "suspect_hosts": [], "mitre_techniques": [],
                        "iocs": [], "next_steps": []})
        packet = SimpleNamespace(protocol="TCP", flow_key=None, src_ip="10.0.0.1",
                                 dst_ip="10.0.0.2", timestamp=1.0)
        shell = SimpleNamespace(
            pcap_file="capture.pcap", get_packets=lambda: [packet],
            flow_engine=SimpleNamespace(get_all_flows=lambda: []), rules=[],
            llm_client=None)
        handler = InvestigateCommandHandler(shell)
        with tempfile.TemporaryDirectory() as folder, \
                patch.object(commands, "REPORTS_DIR", Path(folder)), \
                patch.object(commands, "investigate", return_value=report), \
                patch("builtins.print"):
            handler._run_linear(auto=True)
            saved = json.loads(next(Path(folder).glob("*.json")).read_text(encoding="utf-8"))
        graph = saved["evidence_graph"]
        self.assertTrue(graph["nodes"])
        self.assertIn("hypothesis:1", {node["id"] for node in graph["nodes"]})
        self.assertTrue(graph["edges"])

    def test_soc_analyst_assessment_is_actionable_and_approval_gated(self):
        from ai.investigator import Hypothesis
        from ai.soc_analyst import AutonomousSOCAnalyst
        graph = EvidenceGraph()
        graph.node("packet:0", "packet", src_ip="10.0.0.1")
        graph.claim("hypothesis:1", "Beacon", ["packet:0"])
        report = InvestigationReport(
            narrative="packet 0 beaconed",
            hypotheses=[Hypothesis(
                name="Beacon", description="Periodic traffic", confidence="high",
                evidence_found=["packet 0"], verdict="confirmed")],
            conclusion={"suspect_hosts": [{"ip": "10.0.0.1"}],
                        "iocs": ["bad.example"]})
        assessment = AutonomousSOCAnalyst().assess(
            report, alerts=[SimpleNamespace(severity="high")],
            evidence_graph=graph)
        self.assertEqual(assessment["priority"], "P2")
        self.assertEqual(assessment["disposition"], "confirmed_incident")
        self.assertEqual(assessment["evidence_coverage"], 1.0)
        disruptive = [action for action in assessment["recommended_actions"]
                      if "Isolate" in action["action"] or "Block" in action["action"]]
        self.assertTrue(disruptive)
        self.assertTrue(all(action["approval_required"] for action in disruptive))

    def test_sandbox_auto_mode_falls_back_to_local_process(self):
        from ai.sandbox import run
        with patch.dict(os.environ, {"EASYSHARK_SANDBOX_BACKEND": "auto"},
                        clear=False):
            os.environ.pop("OPEN_SANDBOX_DOMAIN", None)
            result = run("result = sum(values)", {"values": [2, 3]})
        self.assertEqual(result["result"], 5)
        self.assertEqual(result["sandbox_backend"], "local-process")

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
