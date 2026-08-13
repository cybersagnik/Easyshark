"""Autonomous PCAP monitoring daemon backed by the durable job queue."""
from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Optional

from .audit import record
from .job_queue import JobQueue
from .monitor import PCAPMonitor, WebhookAlerter


class MissionDaemon:
    def __init__(self, directory: str, mission: str,
                 interval: float = 30.0, queue_path: Optional[str] = None,
                 webhook: Optional[str] = None, health_port: Optional[int] = None,
                 event_log: Optional[str] = None,
                 threat_feed: Optional[str] = None,
                 event_webhook: Optional[str] = None,
                 mode: str = "standard"):
        if not mission.strip():
            raise ValueError("mission must not be empty")
        self.directory = str(Path(directory).resolve())
        self.mission = mission.strip()
        self.interval = interval
        if mode not in ("standard", "soc-analyst"):
            raise ValueError("mode must be standard or soc-analyst")
        self.mode = mode
        self.stop_event = threading.Event()
        self.queue = JobQueue(queue_path)
        from .threat_intel import ThreatIntel
        self.threat_intel = ThreatIntel(
            threat_feed or os.environ.get("EASYSHARK_THREAT_FEED"))
        self.event_sink = None
        self.event_alerter = None
        if event_log:
            from .event_sink import JsonlSink
            self.event_sink = JsonlSink(event_log)
        token = os.environ.get("EASYSHARK_WEBHOOK_TOKEN")
        self.alerter = (WebhookAlerter(webhook, token=token, approved=True)
                        if webhook else None)
        if event_webhook:
            from .event_sink import MultiSink, WebhookSink
            self.event_alerter = WebhookAlerter(
                event_webhook, token=os.environ.get("EASYSHARK_EVENT_TOKEN", token),
                approved=True,
                outbox_path=str(self.queue.path.with_name("event_alerts.db")))
            webhook_sink = WebhookSink(self.event_alerter)
            self.event_sink = (webhook_sink if not self.event_sink else
                               MultiSink([self.event_sink, webhook_sink]))
        self.monitor = PCAPMonitor(self.directory, self._enqueue, workers=1)
        self.health = None
        if health_port:
            from .health import HealthServer
            self.health = HealthServer(
                port=health_port, token=os.environ.get("EASYSHARK_HEALTH_TOKEN"),
                status_fn=self._health_status)
            self.health.start()
        if self.alerter:
            self.alerter.drain()
        if self.event_alerter:
            self.event_alerter.drain()

    def _enqueue(self, path: str) -> None:
        from .artifacts import describe
        from .investigation_checkpoint import ENGINE_VERSION, POLICY_VERSION
        artifact = describe(path)
        fp = f"{artifact['sha256']}:{ENGINE_VERSION}:{POLICY_VERSION}"
        job_id = self.queue.enqueue(path, fp, self.mission)
        record("mission_queued", job_id=job_id, path=path, artifact=artifact)
        self._emit("mission_queued", {"job_id": job_id, "path": path,
                                      "artifact": artifact})

    def process_one(self) -> bool:
        job = self.queue.claim()
        if not job:
            return False
        try:
            from cli.investigate_commands import InvestigateCommandHandler
            from cli.shell import InteractiveShell
            from core.session_manager import SessionManager
            manager = SessionManager()
            session = (manager.load(job.get("session_key"))
                       if job.get("session_key") else None)
            if session is not None:
                from .investigation_checkpoint import validate
                valid, _ = validate(session.investigation_state,
                                    job["mission"], job["path"])
                report_path = session.investigation_state.get("report_path")
                if valid and session.investigation_state.get("status") == "complete" \
                        and report_path and Path(report_path).is_file():
                    self.queue.complete(job["id"], report_path)
                    return True
            if session is None:
                session = manager.create(job["path"], investigation_state={
                    "mission_id": f"job-{job['id']}"})
            self.queue.bind_session(job["id"], session.key)
            shell = InteractiveShell(job["path"], enable_ai=True,
                                     session=session, session_manager=manager)
            result = InvestigateCommandHandler(
                shell, threat_intel=self.threat_intel, mode=self.mode,
                checkpoint_callback=lambda state: self.queue.checkpoint(
                    job["id"], state)).handle(
                ("soc-analyst" if self.mode == "soc-analyst" else "autonomous")
                + " " + job["mission"])
            if result:
                raise RuntimeError(result)
            manager.save(session)
            self.queue.complete(job["id"],
                                session.investigation_state.get("report_path"))
            record("mission_complete", job_id=job["id"], path=job["path"])
            self._emit("mission_complete", {"job_id": job["id"], "path": job["path"]})
            self._alert({"event": "mission_complete", "job_id": job["id"],
                        "path": job["path"]})
        except Exception as exc:
            self.queue.fail(job["id"], str(exc))
            record("mission_failed", job_id=job["id"], error=str(exc))
            self._emit("mission_failed", {"job_id": job["id"], "error": str(exc)})
            self._alert({"event": "mission_failed", "job_id": job["id"],
                        "error": str(exc)})
        return True

    def _alert(self, event) -> None:
        if not self.alerter:
            return
        try:
            self.alerter.send(event)
        except Exception as exc:
            record("alert_failed", error=str(exc), event=event)

    def _emit(self, event: str, payload) -> None:
        # Keep daemon activity visible to an in-process dashboard subscriber.
        from .event_sink import event_bus
        event_bus.publish(event, payload)
        if self.event_sink:
            try:
                self.event_sink.send(event, payload)
            except Exception as exc:
                record("event_sink_failed", event=event, error=str(exc))

    def _health_status(self):
        return {"queue": self.queue.stats(),
                "stopping": self.stop_event.is_set(), "mode": self.mode}

    def run(self, once: bool = False) -> None:
        if self.interval <= 0:
            raise ValueError("interval must be positive")
        while not self.stop_event.is_set():
            self.monitor.scan_once()
            # The monitor callback is queued on its worker; give it a chance
            # to enqueue, then drain one durable mission each cycle.
            self.monitor._jobs.join()
            while self.process_one():
                pass
            if once:
                return
            self.stop_event.wait(self.interval)

    def stop(self) -> None:
        """Request a graceful stop after the current mission finishes."""
        self.stop_event.set()
        if self.health:
            self.health.close()
