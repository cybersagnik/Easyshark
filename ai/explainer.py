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
import json
import logging
import os
import re

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Architecture fix (2026-08-06): the tool-calling loop used to be the primary
# answer path, making the model "discover" facts through 3-6 serial full
# round-trips. The deterministic evidence bundle (ai/evidence.py) is now
# extracted once per capture and given to the model up-front so it can answer
# in ONE streaming round. The tool loop remains as a fallback for questions
# the bundle does not cover.
# ---------------------------------------------------------------------------
# Free-tier reasoning models (deepseek-v4-flash-free via Zen) think out loud
# before answering. 500 tokens was enough for their deliberation but NOT for
# the trailing "Answer: ..." line, so the reply came back truncated mid-thought.
# 1200 gives a short deliberation + the answer line a realistic chance to
# complete; the tool loop still catches everything the single shot misses.
SINGLE_SHOT_MAX_TOKENS = 1200

# Architecture fix (2026-08-06) — the single-shot evidence path must NOT
# receive the tools-advertising explainer prompt: the request is a plain
# completion with no tool schemas, and a tools-laden system prompt makes
# free-tier models print their intended calls as literal JSON text instead
# of answering. A minimal prompt keeps them answering from the evidence.
_NO_TOOLS_SYSTEM_PROMPT = (
    "You are a network forensics analyst. You are given an evidence digest "
    "extracted from a packet capture. Answer the analyst's question using "
    "ONLY the evidence digest. You have NO tools available — never mention, "
    "propose, or output tool calls, JSON, or function invocations."
)

_ANSWER_LINE_RE = re.compile(r"^\s*Answer\s*:\s*(.+?)\s*$", re.IGNORECASE)


def _valid_answer_value(value: str) -> bool:
    """True when the text after 'Answer:' is a real value, not a template
    placeholder or an empty slot."""
    v = value.strip()
    if not v:
        return False
    low = v.lower()
    if low.startswith(("<value", "<field", "<tool", "{", "[")):
        return False
    return True


def _extract_single_shot_answer(text: Optional[str]) -> Optional[str]:
    """Return the genuine ``Answer: <value>`` from a single-shot reply, or
    None.

    Free-tier reasoning models (deepseek-v4-flash-free via Zen) think out
    loud and frequently echo the prompt's format template (``Answer: <value>
    (source: <field>)'``) as part of that thinking — often in the same
    paragraph as the real answer. Only a real value counts: the template
    echo and a truncated deliberation (no answer line at all) both return
    None, so the caller falls through to the tool loop instead of printing
    deliberation garbage.
    """
    if not text:
        return None
    # 1) Prefer a line that begins with "Answer:".
    for line in reversed(text.splitlines()):
        m = _ANSWER_LINE_RE.match(line)
        if m and _valid_answer_value(m.group(1)):
            return line.strip()
    # 2) Otherwise grab the text after the LAST "Answer:" anywhere —
    #    reasoning models often write the answer mid-paragraph.
    idx = text.lower().rfind("answer:")
    if idx >= 0:
        tail = text[idx + len("answer:"):].strip()
        if _valid_answer_value(tail) and len(tail) <= 300:
            return "Answer: " + tail
    return None


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

        # Architecture fix — deterministic evidence bundle, built (and
        # cached) once per capture. Fed to the model so one streaming
        # round suffices for questions the extractors already cover.
        bundle = ""
        try:
            from ai.evidence import build_evidence_bundle
            bundle = build_evidence_bundle(
                packets=packets, flows=flows, alerts=alerts,
                dissection=dissection, pcap_path=pcap_path)
        except Exception as exc:
            logger.debug("evidence bundle failed: %s", exc)

        # Phase 14 TASK 2 — compact system prompt from triage + patterns.
        system_prompt = None
        try:
            from ai.prompt_optimizer import build_system_prompt, top_patterns
            system_prompt = build_system_prompt(
                "explainer", triage=triage, patterns=top_patterns(2))
        except Exception as exc:
            logger.debug("prompt_optimizer explainer failed: %s", exc)

        # ---- Primary path: single-shot streaming over the evidence ----
        if bundle:
            single = self._explain_from_evidence(
                question, bundle, system_prompt=system_prompt)
            if single:
                return single

        # ---- Fallback: tool-calling loop, seeded with the evidence -----
        if bundle:
            question = (
                question
                + "\n\n[DETERMINISTIC EVIDENCE from capture pre-analysis "
                "(use it; the tools below return the same data)]\n"
                + bundle
            )
        response = self.llm.query_with_tools(
            question=question, context=ctx, system_prompt=system_prompt,
            evidence_seeded=bool(bundle))
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
        # L3 gate — when the analyst opted into LLM-written code, remind the
        # model it has the python_eval escape hatch (and the create_tool
        # escape hatch for minting new named tools) for computations no
        # fixed tool can express.
        if os.environ.get("EASYSHARK_ALLOW_PYTHON_EVAL", "0") == "1":
            retry_prompt += (
                "\n\nIf no existing tool can express the computation, write a "
                "short python_eval snippet over {packets, flows, alerts, "
                "stats} that sets result = <answer> — but try the dedicated "
                "tools first. If you need a reusable computation, define a new "
                "tool with create_tool (name + description + parameter schema "
                "+ a python body over {packets, flows, alerts, stats} that "
                "sets result, reading call args from the dict `args`), then "
                "call it by name."
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
    # Evidence-seeded single-shot (architecture fix — primary path)     #
    # ------------------------------------------------------------------ #
    def _explain_from_evidence(self,
                               question: str,
                               bundle: str,
                               system_prompt: Optional[str] = None) -> Optional[str]:
        """One streaming round over the deterministic evidence bundle.

        Returns the answer string, or None when the model surrenders
        ('Insufficient data') or the call fails — the caller then falls
        through to the tool-calling loop. Never blocks on a second call.
        """
        from core.untrusted import envelope
        trusted_bundle = json.dumps(envelope(
            bundle, source="deterministic_evidence_bundle", field="evidence",
            limit=16000), ensure_ascii=False)
        prompt = (
            "Question: " + question + "\n\n"
            + trusted_bundle + "\n\n"
            "Rules:\n"
            "1. Do not write out your reasoning or analysis — think "
            "internally and output only the answer.\n"
            "2. The VERY LAST line of your reply must be the answer, "
            "formatted exactly: Answer: <value> (source: <field>)\n"
            "3. Do not quote, repeat, or explain this format instruction "
            "in your reply.\n"
            "4. If the evidence above does not contain the answer, make "
            "the last line exactly: Insufficient data"
        )
        try:
            if hasattr(self.llm, "query_stream"):
                parts = []
                for delta in self.llm.query_stream(
                        prompt, model_type="explainer", temperature=0.1,
                        max_tokens=SINGLE_SHOT_MAX_TOKENS,
                        system_prompt=_NO_TOOLS_SYSTEM_PROMPT):
                    if delta:
                        parts.append(delta)
                text = "".join(parts).strip()
            else:
                text = self.llm.query(
                    prompt, model_type="explainer", temperature=0.1,
                    max_tokens=SINGLE_SHOT_MAX_TOKENS,
                    system_prompt=_NO_TOOLS_SYSTEM_PROMPT) or ""
                text = text.strip()
        except Exception as exc:
            logger.debug("evidence single-shot failed: %s", exc)
            return None
        if not text or "insufficient data" in text.lower():
            return None
        # Architecture fix — a reply that is really tool calls written out
        # as JSON ({"tool": ...}) is not an answer; fall through so the
        # tool loop can handle it properly.
        try:
            from ai.llm_client import _looks_like_tool_plan
            if _looks_like_tool_plan(text):
                return None
        except Exception:
            pass
        # Architecture fix — reasoning models echo the format template
        # ("Answer: <value> (source: ...)") mid-thought. Generic strip
        # helpers get fooled by that; extract only a REAL last Answer line.
        # When none exists (truncated before answering), fall through to
        # the tool loop rather than print deliberation.
        return _extract_single_shot_answer(text)

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
