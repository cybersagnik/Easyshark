"""
Interactive PCAP analysis shell.

Public API:
    InteractiveShell(pcap_path).run()   — start REPL on stdin/stdout
"""
from __future__ import annotations

import io
import logging
import sys
from contextlib import redirect_stdout
from pathlib import Path
from typing import List, Optional

from .commands import CommandHandler
from .ai_commands import AICommandHandler
from .capture_commands import CaptureCommandHandler
from .info_commands import InfoCommandHandler, header, row, section, error
from .investigate_commands import InvestigateCommandHandler
from .formatter import OutputFormatter

from core import PCAPLoader, FlowEngine, StatsEngine, PacketIndex, PacketMetadata
from core.fast_parser import FastParser

from preprocessors import (
    FlowPreprocessor, DNSPreprocessor, TLSPreprocessor,
    ARPPreprocessor, HTTPPreprocessor,
)
from detect import (
    PortScanRule, DNSTunnelRule, BeaconingRule,
    TLSAnomalyRule, ARPSpoofRule, SignatureEngine, C2ExfilRule,
)

from config.settings import PREPROCESSORS, DETECTION_RULES

from main import RESET, BOLD, DIM, CYAN, BRIGHT_CYAN, BRIGHT_GREEN, YELLOW, WHITE, BORDER, _box

logger = logging.getLogger(__name__)

TOOL_TOTAL_CHAR_CAP = 12000


def _build_preprocessors() -> list:
    cfg = PREPROCESSORS or {}
    out = []
    if cfg.get("flow", True):
        out.append(FlowPreprocessor())
    if cfg.get("dns", True):
        out.append(DNSPreprocessor())
    if cfg.get("tls", True):
        out.append(TLSPreprocessor())
    if cfg.get("arp", True):
        out.append(ARPPreprocessor())
    if cfg.get("http", True):
        out.append(HTTPPreprocessor())
    return out


def _build_rules() -> list:
    cfg = DETECTION_RULES or {}
    out: list = []
    if cfg.get("portscan", {}).get("enabled", True):
        c = cfg.get("portscan", {})
        out.append(PortScanRule(threshold=c.get("threshold", 20), time_window=c.get("time_window", 60.0)))
    if cfg.get("dns_tunnel", {}).get("enabled", True):
        c = cfg.get("dns_tunnel", {})
        out.append(DNSTunnelRule(query_threshold=c.get("query_threshold", 50), entropy_threshold=c.get("entropy_threshold", 3.5)))
    if cfg.get("beaconing", {}).get("enabled", True):
        c = cfg.get("beaconing", {})
        out.append(BeaconingRule(min_connections=c.get("min_connections", 10), interval_tolerance=c.get("interval_tolerance", 0.2)))
    if cfg.get("tls_anomaly", {}).get("enabled", True):
        out.append(TLSAnomalyRule())
    if cfg.get("arp_spoof", {}).get("enabled", True):
        out.append(ARPSpoofRule())
    if cfg.get("signatures", {}).get("enabled", True):
        out.append(SignatureEngine())
    if cfg.get("c2_exfil", {}).get("enabled", True):
        out.append(C2ExfilRule())
    return out


class InteractiveShell:
    def __init__(self, pcap_file: str, enable_ai: bool = True,
                 session=None, session_manager=None):
        self.pcap_file = pcap_file
        self.enable_ai = enable_ai

        self.session = session
        self.session_manager = session_manager
        self._session_restored = False

        sys.stdout.write(DIM + f"Loading: {pcap_file} ... " + RESET)
        sys.stdout.flush()
        self.loader = PCAPLoader(pcap_file)
        self.packets_raw = self.loader.load()
        sys.stdout.write(DIM + f"done. {len(self.packets_raw)} packets.\n" + RESET)
        sys.stdout.flush()

        self.index = PacketIndex()
        self.flow_engine = FlowEngine()
        self.stats_engine = StatsEngine()

        self.preprocessors = _build_preprocessors()
        self.rules = _build_rules()

        self._process_packets()

        self.llm_client: Optional[object] = None
        self.cmd_handler = CommandHandler(self)
        self.ai_handler = AICommandHandler(self, None) if enable_ai else None
        self.capture_handler = CaptureCommandHandler(self)
        self.info_handler = InfoCommandHandler(self)
        self.capture_session = None
        self.formatter = OutputFormatter()

        from core.triage import triage_capabilities, render_capabilities
        self.triage = triage_capabilities(self.index.packets)

        from core.dissector import dissect_packets
        self.dissection = dissect_packets(self.index.packets)
        self.dissector_skips = self.dissection.get("skipped", 0)

        sys.stdout.write(DIM + f"Indexed {len(self.index.packets)} packets.\n" + RESET)
        sys.stdout.flush()

        self._restore_session_state()
        self._sync_session_triage()

    def _sync_session_triage(self) -> None:
        s = getattr(self, "session", None)
        sm = getattr(self, "session_manager", None)
        if s is None or sm is None:
            return
        try:
            from core.memory import pcap_hash as _ph
            cur = _ph(self.pcap_file)
            if s.pcap_hash and s.pcap_hash != cur:
                return
            s.triage_cache = dict(getattr(self, "triage", {}) or {})
            s.pcap_hash = cur
            sm.save(s)
        except Exception as exc:
            logger.debug("session triage sync failed: %s", exc)

    def _restore_session_state(self) -> None:
        s = self.session
        if s is None:
            return
        from core.memory import pcap_hash as _ph
        cur = _ph(self.pcap_file)
        if s.pcap_hash and s.pcap_hash != cur:
            print(DIM + f"  [session] warning: session {s.key} recorded for different PCAP" + RESET)
            return
        cache = getattr(s, "triage_cache", {}) or {}
        if isinstance(cache, dict) and cache.get("active_protocols"):
            self.triage = dict(cache)
            self._session_restored = True

    def _ensure_llm_client(self):
        if self.llm_client is None and self.enable_ai:
            from ai.llm_client import LLMClient
            sys.stdout.write(DIM + "Initialising AI backend ... " + RESET)
            sys.stdout.flush()
            self.llm_client = LLMClient()
            sys.stdout.write(DIM + "done.\n" + RESET)
            sys.stdout.flush()
            s = getattr(self, "session", None)
            if s is not None:
                try:
                    self.llm_client.restore_role_call_counts(getattr(s, "provider_counts", None))
                    self.llm_client.restore_exhausted(getattr(s, "exhausted", None))
                except Exception as exc:
                    logger.debug("session AI-state restore failed: %s", exc)
            if self.ai_handler is not None:
                self.ai_handler.attach_llm(self.llm_client)
            if not self.llm_client.is_available():
                print(YELLOW + "⚠ Warning: no AI backend reachable." + RESET)
        return self.llm_client

    def _process_packets(self):
        n = len(self.packets_raw)
        report_every = max(1000, n // 10)
        for idx, pkt in enumerate(self.packets_raw):
            fast = FastParser.quick_parse(bytes(pkt))
            meta = PacketMetadata.from_packet(pkt, idx, fast)
            self.index.add_packet(meta)
            self.flow_engine.process_packet(meta)
            self.stats_engine.update(meta)
            for pre in self.preprocessors:
                if pre.enabled:
                    try:
                        pre.process(meta)
                    except Exception:
                        continue
            if n > report_every and (idx + 1) % report_every == 0:
                sys.stdout.write(DIM + f"  ... {idx + 1}/{n} packets\n" + RESET)
                sys.stdout.flush()
        context = {"packets": self.index.packets, "flows": self.flow_engine.get_all_flows()}
        for rule in self.rules:
            if rule.enabled:
                try:
                    rule.analyze(context)
                except Exception:
                    continue

    def reload_packets(self, pcap_path: str) -> int:
        from core import PCAPLoader, FlowEngine, StatsEngine, PacketIndex
        from core.fast_parser import FastParser
        from core.packet_metadata import PacketMetadata

        self.pcap_file = pcap_path
        sys.stdout.write(DIM + f"Hot-reloading: {pcap_path}\n" + RESET)
        sys.stdout.flush()
        self.loader = PCAPLoader(pcap_path)
        self.packets_raw = self.loader.load()

        self.index = PacketIndex()
        self.flow_engine = FlowEngine()
        self.stats_engine = StatsEngine()
        self._process_packets()
        from core.triage import triage_capabilities
        self.triage = triage_capabilities(self.index.packets)
        from core.dissector import dissect_packets
        self.dissection = dissect_packets(self.index.packets)
        self.dissector_skips = self.dissection.get("skipped", 0)
        from ai import tool_cache
        tool_cache.clear()
        sys.stdout.write(DIM + f"Reloaded: {len(self.index.packets)} packets, "
                              f"{len(self.flow_engine.flows)} flows.\n" + RESET)
        sys.stdout.flush()
        return len(self.index.packets)

    def get_packets(self):
        return list(self.index.packets)

    def run(self):
        print(DIM + "Type 'help' for commands, 'exit' to quit." + RESET)
        print()
        while True:
            try:
                user_input = input("pcap > ")
            except EOFError:
                break
            except KeyboardInterrupt:
                print("\nUse 'exit' to quit")
                continue
            low = user_input.strip().lower()
            if low in ("exit", "quit"):
                break
            try:
                self._execute_command(user_input)
            except MemoryError:
                print(YELLOW + "\n⚠ Error: out of memory. Free RAM and retry." + RESET)
                logger.warning("out of memory while executing command")
            except Exception as exc:
                print(YELLOW + f"⚠ {exc}" + RESET)
                logger.error("Command error: %s", exc, exc_info=True)

        try:
            if getattr(self, "llm_client", None) is not None:
                if hasattr(self.llm_client, "print_session_summary"):
                    self.llm_client.print_session_summary()
        except Exception as exc:
            logger.debug("session summary failed: %s", exc)

        sm = getattr(self, "session_manager", None)
        s = getattr(self, "session", None)
        if sm is not None and s is not None:
            try:
                sm.save(s)
                print()
                from main import _ljust_visible
                border = CYAN
                r = RESET
                W = 62
                def el(content: str) -> str:
                    return border + "║" + _ljust_visible(content, W) + "║" + r
                print(border + "╔" + "═" * W + "╗" + r)
                print(el("  Session saved."))
                print(el("  Restore: python3 main.py --session " + BRIGHT_GREEN + s.key + r))
                print(el("  Latest:  python3 main.py --session latest"))
                print(border + "╚" + "═" * W + "╝" + r)
            except Exception as exc:
                logger.debug("session exit save failed: %s", exc)

    def _execute_command(self, line: str):
        line = line.strip()
        if not line:
            return

        if line.startswith("/"):
            query = line[1:].strip()
            self._ensure_llm_client()
            if self.ai_handler:
                self._capture_and_box_analyze(query)
            else:
                print("AI features disabled")
            return

        if line.lower().startswith("analyze "):
            self._ensure_llm_client()
            if self.ai_handler:
                self._capture_and_box_analyze(line[8:].strip())
            else:
                print("AI features disabled")
            return

        low = line.lower().lstrip()
        if low == "capture" or low.startswith("capture "):
            out = self.capture_handler.handle(line)
            if out is not None:
                print(out)
            return

        if low.startswith("investigate"):
            self._ensure_llm_client()
            handler = InvestigateCommandHandler(self)
            out = handler.handle(line)
            if out is not None:
                # Wrap the final incident report in a box
                lines = out.split("\n")
                # Find and box the conclusion section
                print(out)
            return

        if line.lower().startswith("rule "):
            self._ensure_llm_client()
            if not self.ai_handler:
                print("AI features disabled")
                return
            rest = line[5:].strip()
            kind = "snort"
            for k in ("snort ", "yara ", "python "):
                if rest.lower().startswith(k):
                    kind = k.strip()
                    rest = rest[len(k):].strip()
                    break
            self.ai_handler.generate_rule(rest, kind=kind)
            return

        info_verbs = ("protocols", "ips", "flows", "dns", "creds",
                      "summary", "extract")
        if low in info_verbs or low.startswith(tuple(v + " " for v in info_verbs)):
            out = self.info_handler.handle(line)
            if out is not None:
                print(out)
            return

        if low == "sessions" or low == "session" or low.startswith("session "):
            self._handle_session_command(line)
            return

        if low in ("help", "?"):
            self._print_help()
            return

        out = self.cmd_handler.handle(line)
        if out is not None:
            print(out)

    def _capture_and_box_analyze(self, query: str):
        """Run analyze_traffic, capture its output, and wrap in _box()."""
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.ai_handler.analyze_traffic(query)
        raw = buf.getvalue()

        # Split captured output into answer lines and metadata lines
        parts = raw.split("\n")
        answer_lines = []
        meta_lines = []
        in_meta = False
        for line in parts:
            if line.startswith("[backend:") or line.startswith("--- Claim grounding") or line.startswith("[hallucination"):
                in_meta = True
            if in_meta:
                meta_lines.append(line)
            else:
                answer_lines.append(line)

        # Filter empty answer lines
        answer_lines = [l for l in answer_lines if l.strip()]

        if answer_lines:
            print()
            print(_box("Answer", answer_lines))
        for ml in meta_lines:
            if ml.startswith("[backend:"):
                print(DIM + ml + RESET)
            elif ml.startswith("--- Claim grounding"):
                print()
                print(DIM + ml + RESET)
            elif ml.startswith("[hallucination"):
                score_text = ml
                if "LOW CONFIDENCE" in ml:
                    print(YELLOW + ml + RESET)
                else:
                    print(DIM + ml + RESET)
                # Print remaining hallucination lines below
            else:
                if ml.strip():
                    print(DIM + ml + RESET)

    def _print_help(self):
        commands = [
            ("analyze <question>", "Ask a forensic question"),
            ("investigate <q>", "Multi-hypothesis investigation"),
            ("protocols", "Protocol breakdown table"),
            ("ips", "Host summary table"),
            ("flows", "Top flows table"),
            ("files", "Extracted files list"),
            ("dns", "DNS queries and anomalies"),
            ("creds", "Extracted credentials"),
            ("summary", "Capture overview (0 LLM calls)"),
            ("extract <filename>", "Save extracted file to disk"),
            ("capture interfaces", "List capture interfaces"),
            ("capture start <iface>", "Start live capture"),
            ("capture stop", "Stop and reload capture"),
            ("sessions", "List saved sessions"),
            ("session info", "Current session details"),
            ("session forget", "Delete current session"),
            ("exit / quit", "Exit EasyShark"),
        ]
        lines = []
        for cmd, desc in commands:
            lines.append(BRIGHT_CYAN + cmd + RESET + "  " + WHITE + desc + RESET)
        print(_box("Commands", lines))

    def _record_session_turn(self, question: str, answer: str) -> None:
        sm = getattr(self, "session_manager", None)
        s = getattr(self, "session", None)
        if sm is None or s is None:
            return
        try:
            sm.record_turn(s, question, answer)
            sm.save(s)
        except Exception as exc:
            logger.debug("session turn record failed: %s", exc)

    def _session_context(self, max_pairs: int = 3) -> List[str]:
        sm = getattr(self, "session_manager", None)
        s = getattr(self, "session", None)
        if sm is None or s is None:
            return []
        try:
            return sm.conversation_context(s, max_pairs=max_pairs)
        except Exception as exc:
            logger.debug("session context failed: %s", exc)
            return []

    def _handle_session_command(self, line: str) -> None:
        low = line.strip().lower()
        if low == "sessions":
            self._session_list()
            return
        parts = line.split(None, 2)
        verb = parts[1].lower() if len(parts) > 1 else "info"
        arg = parts[2] if len(parts) > 2 else ""
        if verb == "info":
            self._session_info(arg)
        elif verb == "forget":
            self._session_forget(arg)
        else:
            print(f"Unknown session subcommand: {verb}")
            print("Usage: sessions | session info [key] | session forget <key>")

    def _session_list(self) -> None:
        sm = getattr(self, "session_manager", None)
        if sm is None:
            print("No session store configured.")
            return
        try:
            sessions = sm.list_sessions()
        except Exception as exc:
            print(f"Error listing sessions: {exc}")
            return
        if not sessions:
            print("No saved sessions.")
            return
        print(header("KEY", "LAST ACTIVE", "PCAP"))
        for s in sessions:
            mark = " *" if (getattr(self, "session", None) is not None
                            and s.key == self.session.key) else ""
            print(row(f"  {s.key}", s.last_active, s.pcap_path + mark))
        print("\n  * = current session   |   resume: python3 main.py --session <key>")

    def _session_info(self, key: str) -> None:
        sm = getattr(self, "session_manager", None)
        if sm is None:
            print("No session store configured.")
            return
        s = None
        if key:
            try:
                s = sm.load(key) if key != "latest" else sm.latest()
            except Exception:
                s = None
        else:
            s = getattr(self, "session", None)
        if s is None:
            print(f"No session found for {key or 'current'} (run `sessions` to list).")
            return
        pairs = sm.recent_pairs(s, 3)
        c = CYAN
        r = RESET
        print(section("Session " + s.key))
        print(row("Created", s.created_at))
        print(row("Last active", s.last_active))
        print(row("PCAP", s.pcap_path))
        print(row("PCAP hash", s.pcap_hash))
        print(row("Turns", str(len(s.conversation) // 2)))
        print(row("Triage cache", "yes" if s.triage_cache else "no"))
        pc = s.provider_counts or {}
        if pc:
            print(section("Provider call counts"))
            for role in ("planner", "explainer", "coder", "critic"):
                if role in pc:
                    print(row(role, str(pc[role])))
        if pairs:
            print(section("Last conversation"))
            for q, a in pairs:
                print(f"  Q: {q.replace(chr(10), ' ')[:70]}")
                if a:
                    print(f"  A: {a.replace(chr(10), ' ')[:50]}")

    def _session_forget(self, key: str) -> None:
        sm = getattr(self, "session_manager", None)
        if sm is None:
            print("No session store configured.")
            return
        target = key if key else getattr(getattr(self, "session", None), "key", None)
        if not target:
            print("Usage: session forget <key>")
            return
        s = sm.load(target) if target != "latest" else sm.latest()
        if s is None:
            print(f"No session found for {target!r}.")
            return
        if s.key == getattr(self, "session", None) and s.key == self.session.key:
            print(YELLOW + f"⚠ Warning: {s.key} is the CURRENT session." + RESET)
        try:
            answer = input(f"Forget session {s.key} ({s.pcap_path})? [y/N] ").strip()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer.lower() not in ("y", "yes"):
            print("Aborted.")
            return
        if sm.delete(s.key):
            print(f"Forgot session {s.key}.")
            if getattr(self, "session", None) is not None and s.key == self.session.key:
                self.session = None
                self.session_manager = None
                print("Current session cleared.")
        else:
            print(f"Failed to forget session {s.key}.")
