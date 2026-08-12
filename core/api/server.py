"""Optional FastAPI facade over the existing session store and event bus.

Importing this module does not make web dependencies mandatory for the CLI.
Install ``fastapi`` and ``uvicorn`` to run it.
"""
from __future__ import annotations

import asyncio
import json
import logging
import queue
import os
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, Optional
from types import SimpleNamespace

from core.event_sink import event_bus
from core.session_manager import SessionManager

logger = logging.getLogger(__name__)


def _session_payload(session) -> Dict[str, Any]:
    return asdict(session)


def _reports_for(session) -> list[Dict[str, Any]]:
    reports_dir = Path(__import__("os").environ.get(
        "EASYSHARK_REPORTS_DIR", str(Path.home() / ".easyshark" / "reports")))
    reports = []
    if not reports_dir.exists():
        return reports
    for path in sorted(reports_dir.glob("*.json"), reverse=True):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if data.get("pcap") == session.pcap_path:
                reports.append({"file": path.name, **data})
        except (OSError, ValueError):
            continue
    return reports[:20]


def conclusion_findings(report: Dict[str, Any]) -> list[Any]:
    conclusion = report.get("conclusion", {}) or {}
    return [SimpleNamespace(type=item.get("technique", ""),
                             evidence=item.get("evidence", ""))
            for item in conclusion.get("mitre_techniques", [])]


def create_app(session_manager: Optional[SessionManager] = None):
    try:
        from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
        from fastapi.responses import Response
    except ImportError as exc:
        raise RuntimeError("Web mode requires fastapi and uvicorn") from exc

    manager = session_manager or SessionManager()
    api = FastAPI(title="EasyShark API", version="1.0")
    capture_cache: dict[str, Any] = {}

    @api.middleware("http")
    async def optional_auth(request: Request, call_next):
        expected = os.environ.get("EASYSHARK_API_TOKEN")
        if expected and request.url.path.startswith("/api/"):
            supplied = request.headers.get("authorization", "")
            if supplied != f"Bearer {expected}" and request.headers.get("X-EasyShark-Token") != expected:
                return Response("Unauthorized", status_code=401)
        return await call_next(request)

    def capture_for(session):
        if session.key not in capture_cache:
            from cli.shell import InteractiveShell
            capture_cache[session.key] = InteractiveShell(
                session.pcap_path, enable_ai=False,
                session=session, session_manager=manager)
        return capture_cache[session.key]

    def packet_payload(packet) -> dict[str, Any]:
        return {"index": packet.index, "timestamp": packet.timestamp,
                "length": packet.length, "src_ip": packet.src_ip,
                "dst_ip": packet.dst_ip, "src_port": packet.src_port,
                "dst_port": packet.dst_port, "protocol": packet.protocol,
                "tcp_flags": packet.tcp_flags, "ttl": packet.ttl,
                "payload_size": packet.payload_size,
                "payload_hex": (packet.payload or b"")[:256].hex(),
                "attributes": packet.attributes}

    def safe_value(value):
        if hasattr(value, "__dict__"):
            return {key: safe_value(item) for key, item in vars(value).items()
                    if not key.startswith("_") and key not in {"raw_packet", "payload"}}
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        if isinstance(value, (list, tuple)):
            return [safe_value(item) for item in value]
        return str(value)

    @api.get("/api/v1/health")
    def health():
        return {"status": "ok", "service": "easyshark", "events": len(event_bus.history())}

    @api.get("/api/v1/sessions")
    def sessions():
        rows = []
        for session in manager.list_sessions():
            row = _session_payload(session)
            row["status"] = (session.investigation_state or {}).get("status", "idle")
            row["report_count"] = len(_reports_for(session))
            rows.append(row)
        return {"sessions": rows}

    @api.get("/api/v1/session/{key}")
    def session_detail(key: str):
        session = manager.load(key)
        if session is None:
            raise HTTPException(status_code=404, detail="session not found")
        return {"session": _session_payload(session), "reports": _reports_for(session)}

    @api.get("/api/v1/alerts")
    def alerts():
        rows = []
        for session in manager.list_sessions():
            for report in _reports_for(session):
                for alert in report.get("alerts", []):
                    rows.append({"session": session.key, **alert})
            try:
                for index, alert in enumerate(sum((rule.get_alerts() for rule in capture_for(session).rules), [])):
                    rows.append({"session": session.key, "index": index,
                                 "event": "detector_alert", "payload": safe_value(alert)})
            except Exception:
                continue
        return {"alerts": rows[-100:]}

    @api.get("/api/v1/events")
    def events():
        return {"events": event_bus.history()}

    @api.get("/api/v1/session/{key}/packets")
    def packets(key: str, offset: int = 0, limit: int = 100, query: str = ""):
        session = manager.load(key)
        if session is None:
            raise HTTPException(status_code=404, detail="session not found")
        if offset < 0 or limit < 1 or limit > 500:
            raise HTTPException(status_code=400, detail="invalid offset or limit")
        try:
            items = [packet_payload(packet) for packet in capture_for(session).get_packets()]
        except Exception as exc:
            raise HTTPException(status_code=422, detail=f"capture could not be loaded: {exc}")
        if query:
            query = query.lower()
            items = [item for item in items if query in json.dumps(item, default=str).lower()]
        return {"total": len(items), "offset": offset, "limit": limit,
                "packets": items[offset:offset + limit]}

    @api.get("/api/v1/session/{key}/flows")
    def flows(key: str):
        session = manager.load(key)
        if session is None:
            raise HTTPException(status_code=404, detail="session not found")
        try:
            values = capture_for(session).flow_engine.get_all_flows()
            return {"flows": [safe_value(flow) for flow in values]}
        except Exception as exc:
            raise HTTPException(status_code=422, detail=f"flows could not be loaded: {exc}")

    @api.get("/api/v1/analytics/roi")
    def analytics():
        from core.analytics import roi_snapshot
        return roi_snapshot()

    @api.get("/api/v1/session/{key}/graph")
    def session_graph(key: str):
        session = manager.load(key)
        if session is None:
            raise HTTPException(status_code=404, detail="session not found")
        reports = _reports_for(session)
        latest = reports[0] if reports else {}
        return {"session": session.key, "graph": latest.get("evidence_graph", {}),
                "alerts": latest.get("alerts", []),
                "tls_fingerprints": latest.get("tls_fingerprints", [])}

    @api.post("/api/v1/session/{key}/alerts/{index}/ack")
    def acknowledge_alert(key: str, index: int):
        session = manager.load(key)
        if session is None:
            raise HTTPException(status_code=404, detail="session not found")
        state = dict(session.investigation_state or {})
        acknowledged = list(state.get("acknowledged_alerts", []))
        if index not in acknowledged:
            acknowledged.append(index)
        state["acknowledged_alerts"] = acknowledged[-200:]
        session.investigation_state = state
        manager.save(session)
        event_bus.publish("alert_acknowledged", {"session": key, "index": index})
        return {"acknowledged": True, "index": index}

    @api.get("/api/v1/session/{key}/report/{filename}")
    def report_export(key: str, filename: str, format: str = "json"):
        session = manager.load(key)
        if session is None:
            raise HTTPException(status_code=404, detail="session not found")
        report = next((row for row in _reports_for(session) if row.get("file") == filename), None)
        if report is None:
            raise HTTPException(status_code=404, detail="report not found")
        if format == "json":
            body, media = json.dumps(report, indent=2, default=str), "application/json"
        elif format == "markdown":
            conclusion = report.get("conclusion", {})
            body = "# EasyShark Incident Report\n\n" + str(conclusion.get("incident_narrative", "")) + "\n\n"
            body += "## IOCs\n" + "\n".join(f"- {item}" for item in conclusion.get("iocs", []))
            media = "text/markdown"
        elif format == "sigma":
            from ai.mitre_export import sigma_yaml
            body, media = sigma_yaml(conclusion_findings(report)), "application/yaml"
        elif format == "spl":
            from ai.mitre_export import spl_query
            body, media = spl_query(conclusion_findings(report)), "text/plain"
        else:
            raise HTTPException(status_code=400, detail="format must be json, markdown, sigma, or spl")
        return Response(body, media_type=media,
                        headers={"Content-Disposition": f'attachment; filename="{filename}.{format}"'})

    @api.post("/api/v1/investigate")
    async def investigate(request: Dict[str, Any]):
        key = request.get("session") or request.get("session_key")
        session = manager.load(key) if key else None
        pcap = request.get("pcap") or (session.pcap_path if session else None)
        if not pcap:
            raise HTTPException(status_code=400, detail="pcap or session is required")
        if not Path(pcap).is_file():
            raise HTTPException(status_code=404, detail="pcap not found")
        if session is None:
            session = manager.create(pcap)
        question = str(request.get("question") or "Analyze the suspicious activity in this capture.")
        session.investigation_state = {"status": "queued", "question": question,
                                      "started_at": __import__("time").time()}
        manager.save(session)
        event_bus.publish("investigation_queued", {"session": session.key, "question": question})

        def run_sync():
            try:
                session.investigation_state = {**session.investigation_state, "status": "running"}
                manager.save(session)
                from cli.investigate_commands import InvestigateCommandHandler
                from cli.shell import InteractiveShell
                shell = InteractiveShell(pcap, enable_ai=True, session=session, session_manager=manager)
                result = InvestigateCommandHandler(shell).handle("autonomous " + question)
                if result:
                    raise RuntimeError(result)
                manager.save(session)
                session.investigation_state = {**session.investigation_state, "status": "complete",
                                               "completed_at": __import__("time").time()}
                manager.save(session)
                event_bus.publish("investigation_complete", {"session": session.key})
            except Exception as exc:
                logger.exception("API investigation failed")
                session.investigation_state = {**session.investigation_state, "status": "failed", "error": str(exc)}
                manager.save(session)
                event_bus.publish("investigation_failed", {"session": session.key, "error": str(exc)})

        asyncio.create_task(asyncio.to_thread(run_sync))
        return {"accepted": True, "session": session.key}

    @api.websocket("/ws/live")
    async def live(websocket: WebSocket):
        expected = os.environ.get("EASYSHARK_API_TOKEN")
        if expected and websocket.headers.get("authorization") != f"Bearer {expected}" and websocket.headers.get("x-easyshark-token") != expected:
            await websocket.close(code=1008)
            return
        await websocket.accept()
        try:
            cursor = 0
            await websocket.send_json({"event": "snapshot", "payload": {"events": event_bus.history()}})
            cursor = len(event_bus.history())
            while True:
                history = event_bus.history()
                for message in history[cursor:]:
                    await websocket.send_json(message)
                cursor = len(history)
                await asyncio.sleep(0.25)
        except (WebSocketDisconnect, RuntimeError):
            return

    # Serve the compiled dashboard from the same port when available. The
    # Vite dev server remains useful for hot reload, but production users only
    # need `python main.py --web`.
    dist = Path(__file__).resolve().parents[2] / "ui" / "dist"
    if dist.is_dir():
        try:
            from fastapi.staticfiles import StaticFiles
            api.mount("/", StaticFiles(directory=str(dist), html=True), name="dashboard")
        except (ImportError, RuntimeError):
            logger.warning("dashboard static files could not be mounted")

    return api


try:
    app = create_app()
except RuntimeError:
    app = None
