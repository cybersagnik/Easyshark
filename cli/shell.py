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
        self._load_log: List[str] = []

        self.loader = PCAPLoader(pcap_file)
        self.packets_raw = self.loader.load()
        self._load_log.append(
            f"Loading: {pcap_file} ... done. {len(self.packets_raw)} packets."
        )

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
        from .report_commands import ReportCommandHandler
        self.report_handler = ReportCommandHandler(self)
        self.capture_session = None
        self.last_iocs: List[str] = []
        self.formatter = OutputFormatter()

        from core.triage import triage_capabilities
        self.triage = triage_capabilities(self.index.packets)

        from core.dissector import dissect_packets
        self.dissection = dissect_packets(self.index.packets)
        self.dissector_skips = self.dissection.get("skipped", 0)

        self._load_log.append(f"Indexed {len(self.index.packets)} packets.")

        self._restore_session_state()
        self._sync_session_triage()

    def flush_load_log(self) -> None:
        """L12 — print the buffered load-log lines (called after the banner
        renders, so the banner appears first)."""
        if not self._load_log:
            return
        for line in self._load_log:
            sys.stdout.write(DIM + line + "\n" + RESET)
        sys.stdout.flush()
        self._load_log = []

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
        self.flush_load_log()
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
        if low in ("cysoc-terminal", "soc-analyst terminal",
                   "soc-analyst --terminal"):
            from .cysoc_terminal import CYSOCTerminal
            CYSOCTerminal(self).run()
            return

        if low == "capture" or low.startswith("capture "):
            out = self.capture_handler.handle(line)
            if out is not None:
                print(out)
            return

        if (low.startswith("investigate") or low.startswith("autonomous") or
                low.startswith("soc-analyst")):
            self._ensure_llm_client()
            handler = InvestigateCommandHandler(self)
            out = handler.handle(line)
            if out is not None:
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

        if low == "report" or low.startswith("report ") or \
                low in ("anomalies", "timeline") or \
                low.startswith(("anomalies ", "timeline ")) or \
                low == "analyze-auto" or low.startswith("analyze-auto "):
            out = self.report_handler.handle(line)
            if out is not None:
                print(out)
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

        if low == "memory" or low.startswith("memory "):
            self._handle_memory_command(line)
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

        # Premise-mismatch refusal: render as a yellow ⚠ warning OUTSIDE the
        # "Answer" box so a refusal is never mistaken for a genuine finding.
        if any(l.strip() == "[REFUSAL-START]" for l in answer_lines):
            try:
                start = next(i for i, l in enumerate(answer_lines)
                             if l.strip() == "[REFUSAL-START]")
                end = next(i for i, l in enumerate(answer_lines)
                           if l.strip() == "[REFUSAL-END]")
            except StopIteration:
                start, end = 0, len(answer_lines)
            refusal_body = [l for l in answer_lines[start + 1:end]
                            if l.strip()]
            print()
            print(YELLOW + "⚠ Refused — question premise does not match the capture" + RESET)
            for rl in refusal_body:
                print(YELLOW + rl + RESET)
            print()
            for ml in meta_lines:
                if ml.strip():
                    print(DIM + ml + RESET)
            return

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
        self._print_degradation_notes()

    def _print_degradation_notes(self) -> None:
        """M8 — surface provider-degradation notes (Zen SSL, OpenRouter cap,
        fallbacks) on stdout so a backend change is visible, not just logged."""
        llm = getattr(self, "llm_client", None)
        if llm is None or not hasattr(llm, "drain_degradation_notes"):
            return
        try:
            notes = llm.drain_degradation_notes()
        except Exception:
            return
        if not notes:
            return
        for note in notes:
            print(YELLOW + "⚠ " + note + RESET)

    def _print_help(self):
        commands = [
            ("analyze <question>", "Ask a forensic question"),
            ("/ <question>", "AI shortcut for ask-the-AI"),
            ("report [--json] [--force]", "Incident report (detectors + LLM)"),
            ("anomalies", "Ranked anomaly list (no LLM, <2s)"),
            ("timeline", "Behavioral timeline (no LLM, <2s)"),
            ("investigate <q>", "Multi-hypothesis investigation"),
            ("autonomous [mission]", "Run a headless investigation and save its report"),
            ("soc-analyst [mission]", "Autonomous SOC triage, disposition, and response plan"),
            ("soc-analyst terminal", "Open the nested CYSOC Terminal workspace"),
            ("update-feeds [provider]", "Update Feodo, URLhaus, or ThreatFox IOC cache"),
            ("ioc-check <value>", "Check an IOC against the local feed cache"),
            ("events [limit]", "Recent durable investigation/SOC events"),
            ("reports", "List saved investigation reports"),
            ("evidence [index]", "Inspect a saved report evidence graph"),
            ("rule snort|yara|python <desc>", "Generate detection rule"),
            ("list", "List all packets"),
            ("show <idx>", "One-line packet summary"),
            ("stats", "Traffic counters"),
            ("alerts [idx]", "Triggered detection alerts"),
            ("flows", "Conversations + top flows"),
            ("filter <expr>", "Wireshark-style display filter"),
            ("search <regex>", "Regex search over TCP/UDP payloads"),
            ("dissect <idx>", "Full breakdown of one packet"),
            ("hex <idx>", "Hex+ASCII dump of one packet payload"),
            ("follow tcp|udp <id>", "Reassembled stream for a flow"),
            ("protocols", "Protocol breakdown table"),
            ("ips", "Host summary table"),
            ("dns", "DNS queries and anomalies"),
            ("creds", "Extracted credentials"),
            ("summary", "Capture overview (0 LLM calls)"),
            ("extract <filename>", "Save extracted file to disk"),
            ("capture interfaces", "List capture interfaces"),
            ("capture start <iface>", "Start live capture"),
            ("capture stop", "Stop and reload capture"),
            ("capture status", "Active capture status"),
            ("sessions", "List saved sessions"),
            ("session info", "Current session details"),
            ("session forget", "Delete current session"),
            ("memory", "Self-learning memory"),
            ("help / ?", "This message"),
            ("exit / quit", "Exit EasyShark"),
        ]
        lines = []
        for cmd, desc in commands:
            lines.append(BRIGHT_CYAN + cmd + RESET + "  " + WHITE + desc + RESET)
        print()
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
        headers = ("KEY", "LAST ACTIVE", "PCAP")
        data = []
        for s in sessions:
            mark = " *" if (getattr(self, "session", None) is not None
                            and s.key == self.session.key) else ""
            data.append((f"  {s.key}", s.last_active, s.pcap_path + mark))
        widths = [len(h) for h in headers]
        for d in data:
            for i, cell in enumerate(d):
                widths[i] = max(widths[i], len(cell))
        print(header(*headers))
        for d in data:
            print(row(*d, widths=widths))
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
        info_rows = [
            ("Created", s.created_at),
            ("Last active", s.last_active),
            ("PCAP", s.pcap_path),
            ("PCAP hash", s.pcap_hash),
            ("Turns", str(len(s.conversation) // 2)),
            ("Triage cache", "yes" if s.triage_cache else "no"),
        ]
        print(section("Session " + s.key))
        label_w = max(len(a) for a, _ in info_rows)
        for label, val in info_rows:
            print(row(label, val, widths=(label_w, len(val))))
        pc = s.provider_counts or {}
        if pc:
            print(section("Provider call counts"))
            for role in ("planner", "explainer", "coder", "critic"):
                if role in pc:
                    print(row(role, str(pc[role]),
                              widths=(label_w, len(str(pc[role])))))
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
        cur = getattr(self, "session", None)
        if cur is not None and s.key == cur.key:
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

    # ------------------------------------------------------------------ #
    # Gap 2 — `memory` commands: surface the self-learning stores that
    # used to be write-only (failures.jsonl, patterns.jsonl, memory.db).
    # ------------------------------------------------------------------ #
    def _handle_memory_command(self, line: str) -> None:
        parts = line.split(None, 1)
        verb = (parts[1].strip() if len(parts) > 1 else "status").lower()
        if verb in ("status", ""):
            self._memory_status()
        elif verb.startswith("show-failures") or verb == "failures":
            self._memory_show_failures(parts[1].strip() if len(parts) > 1 else "")
        elif verb.startswith("show-patterns") or verb == "patterns":
            self._memory_show_patterns()
        elif verb.startswith("show-verdicts") or verb == "verdicts":
            self._memory_show_verdicts()
        elif verb.startswith("show-iocs") or verb == "iocs":
            self._memory_show_iocs()
        elif verb.startswith("rsi status"):
            from ai.rsi import status
            print("RSI status: " + ", ".join(
                f"{k}={v}" for k, v in status().items()))
        elif verb.startswith("rsi label "):
            raw = verb[len("rsi label "):].strip()
            parts = raw.split(None, 1)
            if len(parts) != 2 or parts[0] not in ("good", "bad"):
                print("Usage: memory rsi label good|bad <question>")
                return
            from ai.rsi import record_feedback
            count = record_feedback(parts[1], parts[0] == "good")
            print(f"RSI feedback recorded; updated {count} pattern(s).")
        elif verb in ("jobs", "queue"):
            from core.job_queue import JobQueue
            print("Mission queue: " + ", ".join(
                f"{k}={v}" for k, v in JobQueue().stats().items()))
        else:
            print("Usage:")
            print("  memory status            — stores + sizes")
            print("  memory show-failures     — recent heuristic/critic misses")
            print("  memory show-patterns     — learned tool-usage patterns")
            print("  memory show-verdicts     — recent critic-approved verdicts")
            print("  memory show-iocs         — remembered IOC indicators")
            print("  memory rsi status        — candidate/active/retired patterns")
            print("  memory rsi label good|bad <question>")
            print("  memory jobs             — autonomous mission queue status")

    def _memory_status(self) -> None:
        print(section("Self-learning stores"))
        from core.memory import db_path
        import os as _os
        shown = False
        for name, path in (
            ("memory.db", db_path()),
            ("patterns.jsonl", None),
            ("failures.jsonl", None),
            ("distilled_prompts.jsonl", None),
        ):
            p = path or Path.home() / ".easyshark" / name
            exists = p.exists()
            size = p.stat().st_size if exists else 0
            print(row(name, f"{size:,} B" if exists else "not created yet"))
            shown = True
        if not shown:
            print("No learning stores found.")

    def _memory_show_failures(self, arg: str) -> None:
        try:
            from ai.failure_library import read_failures
            limit = 20
            if arg:
                try:
                    limit = int(arg)
                except ValueError:
                    limit = 20
            rows = read_failures(limit=limit)
        except Exception as exc:
            print(f"Error reading failures: {exc}")
            return
        if not rows:
            print("No failures logged yet. Run `analyze` / `investigate` to build them up.")
            return
        print(section("Failures (heuristic misses / critic rejections)"))
        for i, r in enumerate(rows, 1):
            kind = r.get("kind") or r.get("type") or "?"
            q = (r.get("question") or r.get("hypothesis") or "?")[:80]
            ts = (r.get("ts") or "")[:19]
            print(f"  {i:>2}. [{kind}] {q}")
            if ts:
                print(f"       {ts}")
            issues = r.get("issues") or r.get("critic_issues")
            if issues:
                print(f"       issues: {'; '.join(str(x)[:60] for x in issues[:3])}")
            tools = r.get("tools_used")
            if tools:
                print(f"       tools: {str(tools)[:80]}")

    def _memory_show_patterns(self) -> None:
        try:
            from ai.pattern_learner import read_patterns
            rows = read_patterns(limit=20)
        except Exception as exc:
            print(f"Error: {exc}")
            return
        if not rows:
            print("No learned patterns yet. Run `investigate` to start learning.")
            return
        print(section("Learned tool-usage patterns"))
        for i, r in enumerate(reversed(rows), 1):
            rate = float(r.get("success_rate", 0.0))
            n = int(r.get("sample_count", 0))
            kws = ", ".join((r.get("question_keywords") or [])[:4]) or "?"
            tools = ", ".join(str(t) for t in (r.get("tool_sequence") or [])[:4])
            state = r.get("status", "candidate")
            feedback = f"{int(r.get('feedback_pass', 0))}/{int(r.get('feedback_total', 0))}"
            print(f"       state: {state}  analyst feedback: {feedback}")
            print(f"  {i:>2}. [{rate:.0%}×{n}] {kws}")
            print(f"       tools: {tools}")

    def _memory_show_verdicts(self) -> None:
        try:
            from core.memory import approved_verdicts
            rows = approved_verdicts(n=15)
        except Exception as exc:
            print(f"Error: {exc}")
            return
        if not rows:
            print("No critic-approved verdicts yet.")
            return
        print(section("Critic-approved verdicts"))
        for r in rows:
            v = (r.get("verdict") or "?").upper()
            conf = float(r.get("confidence") or 0.0)
            hyp = (r.get("hypothesis") or "?")[:70]
            print(f"  [{v:<12}] conf={conf:.2f}  {hyp}")
            tools = r.get("tools_used")
            if tools:
                print(f"        tools: {str(tools)[:80]}")

    def _memory_show_iocs(self) -> None:
        try:
            from core.memory import _connect
            conn = _connect()
            try:
                rows = conn.execute(
                    "SELECT ip, domain, md5, verdict, source_pcap, last_seen "
                    "FROM iocs ORDER BY id DESC LIMIT 25").fetchall()
            finally:
                conn.close()
        except Exception as exc:
            print(f"Error: {exc}")
            return
        if not rows:
            print("No IOCs remembered yet.")
            return
        print(section("Remembered IOCs (prior-session knowledge)"))
        for r in rows:
            value = r["ip"] or r["domain"] or r["md5"]
            v = (r["verdict"] or "?").upper()
            src = (r["source_pcap"] or "?")[:30]
            ts = (r["last_seen"] or "")[:16]
            print(f"  {value:<28} [{v}] {src} {ts}")
