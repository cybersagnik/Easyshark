"""
TrafficExplainer — the LLM-driven answer generator.

Public methods:
    explain_traffic(question, packets, flows, alerts, rules=None, ...) -> str
        Primary entry. Uses tool-calling (query_with_tools) so the LLM
        can gather real evidence before answering. Falls back to:
        1. Legacy single-prompt explainer (small models without tools)
        2. Offline-only summary (no LLM reachable)
    explain_traffic_oneshot(question, packets, flows, alerts) -> Optional[str]
        Legacy payload-aware single-prompt path.
    explain_alert(alert) -> str
        Short explanation of one alert.
"""
from __future__ import annotations

from .llm_client import LLMClient
from ai.tool_registry import ToolContext

from collections import Counter
from typing import Any, Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


class TrafficExplainer:
    def __init__(self, llm_client: LLMClient):
        self.llm = llm_client

    # ------------------------------------------------------------------ #
    # Primary entry — tool-calling                                       #
    # ------------------------------------------------------------------ #
    def explain_traffic(self,
                        question: str,
                        packets: list,
                        flows: list,
                        alerts: list,
                        rules: Optional[list] = None,
                        stats_engine: Any = None,
                        flow_engine: Any = None,
                        pcap_path: Optional[str] = None,
                        triage: Optional[dict] = None,
                        dissection: Optional[dict] = None,
                        conversation_context: Optional[List[str]] = None) -> str:
        if not self.llm.is_available():
            return self._fallback_analysis(
                question, self._create_summary(packets, flows, alerts)
            )

        ctx = ToolContext(
            packets=list(packets or []),
            flows=list(flows or []),
            alerts=list(alerts or []),
            stats_engine=stats_engine,
            flow_engine=flow_engine,
            pcap_path=pcap_path,
            triage=triage,
            dissection=dissection,
        )

        # Phase 16 Task 2 — conversation continuity. Prepend prior Q&A
        # pairs (already capped at ~600 tokens by the session manager)
        # so follow-up questions can refer back to earlier answers.
        if conversation_context:
            question = (
                "Earlier Q&A on this capture (session memory — use it for "
                "context, the CURRENT question is at the end):\n\n"
                + "\n\n".join(conversation_context)
                + "\n\nCURRENT QUESTION: " + question
            )

        # Phase 14 TASK 2 — compact system prompt from triage + patterns.
        system_prompt = None
        try:
            from ai.prompt_optimizer import build_system_prompt, top_patterns
            system_prompt = build_system_prompt(
                "explainer", triage=triage, patterns=top_patterns(2))
        except Exception as exc:
            logger.debug("prompt_optimizer explainer failed: %s", exc)

        response = self.llm.query_with_tools(
            question=question, context=ctx, system_prompt=system_prompt)
        if response:
            return response

        # Tool-calling produced nothing. Retry once with a more forceful
        # system prompt that demands tool use before answering.
        logger.info("Tool-calling returned empty; retrying with forceful prompt")
        retry_prompt = (
            "You are a senior network forensic investigator. The analyst asks "
            "a question about a packet capture. You MUST call at least one of "
            "your available tools before giving any answer. Do NOT reply with "
            "a plan or describe what you would do — actually call the tool. "
            "Your available tools are listed below. Pick the most relevant one, "
            "call it, then answer concisely from the result. After you get the "
            "tool result, reply 'Answer: <value> (source: <tool>).'"
        )
        response = self.llm.query_with_tools(
            question=question, context=ctx,
            system_prompt=retry_prompt)
        if response:
            return response

        # Both attempts failed — build evidence from dissection + triage
        # and do a single-shot LLM call.
        logger.info("Tool-calling failed twice; using dissection-aware single-shot")
        return self._fallback_analysis(
            question, self._create_summary(packets, flows, alerts, dissection)
        )

    # ------------------------------------------------------------------ #
    # Legacy single-prompt path                                          #
    # ------------------------------------------------------------------ #
    def explain_traffic_oneshot(self,
                                question: str,
                                packets: list,
                                flows: list,
                                alerts: list) -> Optional[str]:
        from ai.payload_analyzer import summarize_payloads
        summary = self._create_summary(packets, flows, alerts)
        try:
            summary["payload_analysis"] = summarize_payloads(packets or [])
        except Exception as exc:
            logger.warning("summarize_payloads failed: %s", exc)
        if not self.llm.is_available():
            return None
        return self.llm.query_explainer(question, summary)

    # ------------------------------------------------------------------ #
    # Summary builders                                                   #
    # ------------------------------------------------------------------ #
    def _create_summary(self, packets, flows, alerts,
                        dissection: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        protocols = Counter()
        ips = Counter()
        ports = Counter()
        for pkt in packets[:1000]:
            if getattr(pkt, "protocol", None):
                protocols[pkt.protocol] += 1
            if getattr(pkt, "src_ip", None):
                ips[pkt.src_ip] += 1
            if getattr(pkt, "dst_ip", None):
                ips[pkt.dst_ip] += 1
            if getattr(pkt, "src_port", None) is not None:
                ports[pkt.src_port] += 1
            if getattr(pkt, "dst_port", None) is not None:
                ports[pkt.dst_port] += 1
        alert_types = Counter()
        for alert in alerts[:100]:
            alert_types[getattr(alert, "rule_name", "?")] += 1
        result = {
            "total_packets": len(packets),
            "total_flows":   len(flows),
            "total_alerts":  len(alerts),
            "top_protocols": dict(protocols.most_common(5)),
            "top_ips":       dict(ips.most_common(10)),
            "top_ports":     dict(ports.most_common(10)),
            "alert_types":   dict(alert_types.most_common(10)),
        }
        if dissection:
            for key in ("smtp_sessions", "http_requests", "dns_queries",
                        "credentials", "transferred_files", "tls_sessions",
                        "arp_table", "dhcp_leases", "ssh_sessions"):
                val = dissection.get(key)
                if val:
                    result[f"dissector_{key}"] = val
        return result

    # ------------------------------------------------------------------ #
    # Offline-only fallback                                              #
    # ------------------------------------------------------------------ #
    def _fallback_analysis(self, question: str, summary: Dict[str, Any]) -> str:
        if not self.llm.is_available():
            return self._offline_summary(question, summary)
        parts: List[str] = [
            "Question: " + question,
            "",
            "Capture data:",
            f"  Packets: {summary.get('total_packets', 0)}"
            f"  | Flows: {summary.get('total_flows', 0)}"
            f"  | Alerts: {summary.get('total_alerts', 0)}",
        ]
        if summary.get("top_protocols"):
            parts.append("  Protocols: " + ", ".join(
                f"{p}={c}" for p, c in summary["top_protocols"].items()))
        if summary.get("top_ips"):
            parts.append("  Top IPs: " + ", ".join(
                f"{ip}({c})" for ip, c in
                list(summary["top_ips"].items())[:5]))
        # Include dissection data collected by _create_summary
        for key in sorted(summary):
            if key.startswith("dissector_") and summary[key]:
                label = key.replace("dissector_", "").replace("_", " ")
                val = summary[key]
                if isinstance(val, list):
                    items = [str(v)[:200] for v in val[:5]]
                    parts.append(f"  {label}: {', '.join(items)}")
                elif isinstance(val, dict):
                    items = [f"{k}={v}" for k, v in list(val.items())[:5]]
                    parts.append(f"  {label}: {', '.join(items)}")
        if summary.get("alert_types"):
            parts.append("  Alerts: " + ", ".join(
                f"{a}({c})" for a, c in summary["alert_types"].items()))
        parts.extend([
            "",
            "Output ONLY the answer. No thinking, no analysis.",
            "Format: 'Answer: <value> (source: <field>)'",
            "If the data doesn't contain the answer, reply: 'Insufficient data'",
        ])
        prompt = "\n".join(parts)
        return self.llm.query(prompt, model_type="explainer", temperature=0.2) or \
            self._offline_summary(question, summary)

    def _offline_summary(self, question: str, summary: Dict[str, Any]) -> str:
        lines = []
        lines.append("Traffic Analysis Summary:")
        lines.append(f"- Total packets: {summary.get('total_packets', 0)}")
        lines.append(f"- Total flows:   {summary.get('total_flows', 0)}")
        lines.append(f"- Total alerts:  {summary.get('total_alerts', 0)}")
        if summary.get("top_protocols"):
            lines.append("\nTop Protocols:")
            for proto, count in summary["top_protocols"].items():
                lines.append(f"  - {proto}: {count}")
        if summary.get("top_ips"):
            lines.append("\nTop IPs:")
            for ip, count in list(summary["top_ips"].items())[:5]:
                lines.append(f"  - {ip}: {count} packets")
        if summary.get("alert_types"):
            lines.append("\nAlert Types:")
            for at, count in summary["alert_types"].items():
                lines.append(f"  - {at}: {count}")
        lines.append(f"\nQuery: {question}")
        lines.append(
            "\n(Note: no AI backend reachable. Start Ollama or set "
            "GROQ_ENABLED=1 with a valid GROQ_API_KEY.)"
        )
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    # Alert explanation (unchanged)                                      #
    # ------------------------------------------------------------------ #
    def explain_alert(self, alert) -> str:
        if not self.llm.is_available():
            return f"{getattr(alert, 'rule_name', '?')}: {getattr(alert, 'message', '')}"
        prompt = (
            f"Explain this security alert concisely:\n\n"
            f"Rule: {getattr(alert, 'rule_name', '')}\n"
            f"Severity: {getattr(alert, 'severity', '')}\n"
            f"Message: {getattr(alert, 'message', '')}\n"
            f"Metadata: {getattr(alert, 'metadata', '')}\n\n"
            f"Explanation:"
        )
        response = self.llm.query(prompt, model_type="explainer", temperature=0.2)
        return response if response else f"{getattr(alert, 'rule_name', '?')}: {getattr(alert, 'message', '')}"
