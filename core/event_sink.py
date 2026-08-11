"""Pluggable event sinks for SIEM/SOAR adapters."""
from __future__ import annotations

import json
import queue
import threading
import time
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional


def envelope(event: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    return {"schema": "easyshark.event.v1", "event": event,
            "ts": time.time(), "payload": payload}


class JsonlSink:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def send(self, event: str, payload: Dict[str, Any]) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(envelope(event, payload), default=str) + "\n")


class WebhookSink:
    """Send versioned events through an existing durable webhook transport."""

    def __init__(self, alerter):
        self.alerter = alerter

    def send(self, event: str, payload: Dict[str, Any]) -> None:
        self.alerter.send(envelope(event, payload))


class MultiSink:
    def __init__(self, sinks: Iterable[Any]):
        self.sinks = list(sinks)

    def send(self, event: str, payload: Dict[str, Any]) -> None:
        for sink in self.sinks:
            sink.send(event, payload)


class EventBus:
    """Small process-local fan-out bus shared by CLI and web mode.

    Subscribers receive the same versioned envelope used by durable sinks.
    A bounded history makes a newly opened dashboard useful without turning
    the bus into a second database.
    """

    def __init__(self, history_size: int = 200, store_path: Optional[str] = None):
        self._history: List[Dict[str, Any]] = []
        self._subscribers: List[Callable[[Dict[str, Any]], None]] = []
        self._lock = threading.RLock()
        self._history_size = max(1, int(history_size))
        self.store_path = Path(store_path or os.environ.get(
            "EASYSHARK_EVENT_STORE", str(Path.home() / ".easyshark" / "events.db")))
        self._last_id = 0
        self._init_store()
        self._load_store()

    @contextmanager
    def _connection(self):
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(str(self.store_path), timeout=10)
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            yield connection
        finally:
            connection.close()

    def _init_store(self) -> None:
        try:
            with self._connection() as connection:
                connection.execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL, ts REAL NOT NULL, payload TEXT NOT NULL)")
                connection.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
        except (OSError, sqlite3.Error):
            pass

    def _rows(self):
        with self._connection() as connection:
            return connection.execute("SELECT id,event,ts,payload FROM events ORDER BY id DESC LIMIT ?", (self._history_size,)).fetchall()[::-1]

    @staticmethod
    def _message(row) -> Dict[str, Any]:
        event_id, event, ts, payload = row
        return {"id": event_id, "schema": "easyshark.event.v1", "event": event,
                "ts": ts, "payload": json.loads(payload)}

    def _load_store(self) -> None:
        try:
            rows = self._rows()
            self._history = [self._message(row) for row in rows]
            self._last_id = rows[-1][0] if rows else 0
        except (OSError, ValueError, sqlite3.Error):
            self._history = []

    def _refresh_store(self) -> None:
        try:
            rows = self._rows()
            if rows and rows[-1][0] != self._last_id:
                self._history = [self._message(row) for row in rows]
                self._last_id = rows[-1][0]
        except (OSError, ValueError, sqlite3.Error):
            return

    def publish(self, event: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        message = envelope(event, payload or {})
        with self._lock:
            self._history.append(message)
            del self._history[:-self._history_size]
            try:
                with self._connection() as connection:
                    cursor = connection.execute(
                        "INSERT INTO events(event,ts,payload) VALUES(?,?,?)",
                        (event, message["ts"], json.dumps(message["payload"], default=str)))
                    message["id"] = cursor.lastrowid
                    self._last_id = int(cursor.lastrowid)
            except (OSError, sqlite3.Error):
                pass
            subscribers = list(self._subscribers)
        for subscriber in subscribers:
            try:
                subscriber(message)
            except Exception:
                # A disconnected browser must never break packet analysis.
                continue
        return message

    def subscribe(self, callback: Callable[[Dict[str, Any]], None]) -> Callable[[], None]:
        with self._lock:
            self._subscribers.append(callback)
        return lambda: self.unsubscribe(callback)

    def unsubscribe(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        with self._lock:
            if callback in self._subscribers:
                self._subscribers.remove(callback)

    def history(self) -> List[Dict[str, Any]]:
        with self._lock:
            self._refresh_store()
            return list(self._history)

    def stream(self):
        """Yield future events until the consumer closes the generator."""
        events: queue.Queue = queue.Queue()
        remove = self.subscribe(events.put)
        try:
            while True:
                yield events.get()
        finally:
            remove()


event_bus = EventBus()


class BusSink:
    """Adapter allowing existing daemon code to publish to the shared bus."""

    def send(self, event: str, payload: Dict[str, Any]) -> None:
        event_bus.publish(event, payload)
