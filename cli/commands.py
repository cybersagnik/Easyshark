"""
CommandHandler — the read-only shell commands (no AI).

Implements:
    list, show <idx>, stats, alerts, flows, filter <expr>, search <regex>
    dissect <idx>, hex <idx>, follow <flow_id>

These never call the LLM. The AI commands (analyze, ask) live in
ai_commands.py. File extraction/export is agentic-only (the LLM uses
the extract_files tool) — there is no bulk `export files` verb.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, List, Optional

from .formatter import OutputFormatter

logger = logging.getLogger(__name__)


class CommandHandler:
    def __init__(self, shell):
        self.shell = shell
        self.fmt = OutputFormatter()

    # ------------------------------------------------------------------ #
    # Entry                                                              #
    # ------------------------------------------------------------------ #
    def handle(self, line: str) -> Optional[str]:
        line = line.strip()
        if not line:
            return None
        parts = line.split(None, 1)
        verb = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""
        return self._dispatch(verb, arg)

    def _dispatch(self, verb: str, arg: str) -> Optional[str]:
        table = {
            "list":      self.cmd_list,
            "packets":   self.cmd_list,
            "show":      self.cmd_show,
            "stats":     self.cmd_stats,
            "alerts":    self.cmd_alerts,
            "flows":     self.cmd_flows,
            "filter":    self.cmd_filter,
            "tshark":    self.cmd_filter,
            "search":    self.cmd_search,
            "find":      self.cmd_search,
            "dissect":   self.cmd_dissect,
            "hex":       self.cmd_hex,
            "follow":    self.cmd_follow,
            "help":      self.cmd_help,
            "?":         self.cmd_help,
        }
        fn = table.get(verb)
        if fn is None:
            return self.fmt.error(f"unknown command: {verb} (type 'help')")
        try:
            return fn(arg)
        except Exception as exc:
            logger.error("command %s failed: %s", verb, exc)
            return self.fmt.error(str(exc))

    # ------------------------------------------------------------------ #
    # Read commands                                                      #
    # ------------------------------------------------------------------ #
    def cmd_list(self, arg: str) -> str:
        packets = self.shell.get_packets()
        return self.fmt.packet_list(packets)

    def cmd_show(self, arg: str) -> str:
        try:
            idx = int(arg.strip())
        except ValueError:
            return self.fmt.error(f"show needs integer index, got {arg!r}")
        pkt = self.shell.index.get(idx)
        if pkt is None:
            return self.fmt.error(f"no packet {idx}")
        return self.fmt.packet_line(pkt)

    def cmd_stats(self, arg: str) -> str:
        return self.fmt.stats_block(self.shell.stats_engine.summary())

    def cmd_alerts(self, arg: str) -> str:
        alerts = []
        for rule in self.shell.rules:
            alerts.extend(rule.get_alerts())
        if not arg:
            return self.fmt.alerts_block(alerts)
        # 'alerts <idx>' -> explain the Nth alert via the LLM.
        try:
            idx = int(arg.strip())
        except ValueError:
            return self.fmt.error(f"alerts needs integer index or no argument, got {arg!r}")
        if not (0 <= idx < len(alerts)):
            return self.fmt.error(f"alert index {idx} out of range (0..{len(alerts)-1})")
        target = alerts[idx]
        ai = getattr(self.shell, "ai_handler", None)
        if ai and getattr(ai, "llm", None):
            try:
                explanation = ai.explain_alert(target)
            except Exception as exc:
                logger.error("explain_alert failed: %s", exc)
                explanation = f"{target.rule_name}: {target.message}"
        else:
            explanation = f"{target.rule_name}: {target.message}"
        return (f"Alert {idx}: {target.short()}\n"
                f"  severity: {target.severity}\n"
                f"  metadata: {target.metadata}\n"
                f"\nAI explanation:\n{explanation}")

    def cmd_flows(self, arg: str) -> str:
        return self.fmt.flows_block(self.shell.flow_engine.get_all_flows())

    def cmd_filter(self, arg: str) -> str:
        from core.filter_engine import DisplayFilter, SimpleFilter
        if not arg:
            return self.fmt.error("filter needs an expression (e.g. tcp.port == 80)")
        try:
            df = DisplayFilter(arg)
            matches = df.apply(self.shell.get_packets())
        except Exception:
            sf = SimpleFilter(arg)
            matches = sf.apply(self.shell.get_packets())
        return f"Filter: {arg}  ->  {len(matches)} match(es)\n" + self.fmt.packet_list(matches)

    def cmd_search(self, arg: str) -> str:
        if not arg:
            return self.fmt.error("search needs a regex")
        from ai.tool_registry import tool_search_payloads
        from ai.tool_registry import ToolContext
        ctx = ToolContext(packets=self.shell.get_packets(),
                          flows=self.shell.flow_engine.get_all_flows(),
                          alerts=[],
                          stats_engine=self.shell.stats_engine,
                          flow_engine=self.shell.flow_engine,
                          pcap_path=getattr(self.shell, "pcap_file", None))
        result = tool_search_payloads({"regex": arg}, ctx)
        if "error" in result:
            return self.fmt.error(result["error"])
        hits = result.get("hits", [])
        if not hits:
            return "(no hits)"
        from core.sanitise import sanitise
        lines = [f"{h['pkt']:>5}  {sanitise(h['match'][:60])}" for h in hits[:30]]
        return "\n".join(lines)

    def cmd_dissect(self, arg: str) -> str:
        try:
            idx = int(arg.strip())
        except ValueError:
            return self.fmt.error("dissect needs integer index")
        pkt = self.shell.index.get(idx)
        if pkt is None:
            return self.fmt.error(f"no packet {idx}")
        lines = [self.fmt.packet_line(pkt)]
        lines.append(f"  src_mac: {pkt.src_mac}")
        lines.append(f"  dst_mac: {pkt.dst_mac}")
        lines.append(f"  ttl:     {pkt.ttl}")
        lines.append(f"  tcp_flags: {pkt.tcp_flags}")
        lines.append(f"  payload_size: {pkt.payload_size}")
        if pkt.payload:
            from core.sanitise import sanitise
            preview = pkt.payload[:60].decode("latin-1", "replace")
            lines.append(f"  payload_preview: {sanitise(preview)!r}")
        return "\n".join(lines)

    def cmd_hex(self, arg: str) -> str:
        try:
            idx = int(arg.strip())
        except ValueError:
            return self.fmt.error("hex needs integer index")
        pkt = self.shell.index.get(idx)
        if pkt is None:
            return self.fmt.error(f"no packet {idx}")
        payload = pkt.payload or b""
        header = (f"Packet {idx}  {pkt.protocol or '?'}  "
                  f"{pkt.src_ip or '?'}:{pkt.src_port} -> "
                  f"{pkt.dst_ip or '?'}:{pkt.dst_port}  "
                  f"len={pkt.length}  payload={len(payload)} bytes")
        return header + "\n" + self._hex_dump(payload)

    def _hex_dump(self, data: bytes) -> str:
        lines = ["Offset    Hex                                              ASCII"]
        for off in range(0, len(data), 16):
            chunk = data[off:off+16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{off:08x}  {hex_part:<47}  {ascii_part}")
        return "\n".join(lines) if lines else "(empty)"

    def cmd_follow(self, arg: str) -> str:
        m = re.match(r"^(?:tcp|udp|http)\s+(\d+)", arg.strip())
        if not m:
            return self.fmt.error("follow expects: follow tcp|udp|http <flow_id>")
        try:
            idx = int(m.group(1))
        except ValueError:
            return self.fmt.error("flow id must be integer")
        flows = self.shell.flow_engine.get_all_flows()
        if not (0 <= idx < len(flows)):
            return self.fmt.error(f"flow_id {idx} out of range")
        flow = flows[idx]
        from core.sanitise import sanitise
        text = (getattr(flow, "payload_bytes", b"") or b"").decode("latin-1", "replace")
        return (f"Flow {idx}: {flow.src_ip}:{flow.src_port} -> "
                f"{flow.dst_ip}:{flow.dst_port}\n\n"
                f"{sanitise(text)[:4000]}")

    def cmd_help(self, arg: str) -> str:
        # L19 — the REPL intercepts `help`/`?` and calls
        # shell._print_help() directly; this dispatch entry is a
        # fallback that delegates to the same single source of truth
        # rather than maintaining a second, drifting command list.
        if hasattr(self.shell, "_print_help"):
            self.shell._print_help()
            return None
        return (
            "Commands:\n"
            "  list | show <idx> | stats | alerts [idx]\n"
            "  flows | filter <expr> | search <regex>\n"
            "  dissect <idx> | hex <idx> | follow tcp|udp <id>\n"
            "  protocols | ips | dns | creds | summary | extract <filename>\n"
            "  anomalies | timeline | report [--json] [--force]\n"
            "  analyze <question> | / <question> | investigate <q>\n"
            "  rule snort|yara|python <desc>\n"
            "  capture interfaces | start <iface> | stop | status\n"
            "  sessions | session info | session forget | memory\n"
            "  help | exit\n"
        )
