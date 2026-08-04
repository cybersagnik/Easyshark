"""
CommandPlanner — turns a free-form user input into one directive line.

The planner has two stages:
  1. Heuristic keyword match — handles the common cases without
     spending an LLM round-trip.
  2. LLM round-trip — only fires for inputs the heuristic can't
     classify, and only if an LLM is reachable.

Recognised directive verbs:
    list | show <idx> | stats | alerts [<idx>] | flows
    filter <expr> | search <regex> | dissect <idx> | hex <idx>
    follow tcp|udp <id> | export files | analyze <question>
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from .llm_client import LLMClient

logger = logging.getLogger(__name__)


_VERBS_THAT_TAKE_NO_ARG = {"list", "packets", "stats", "flows",
                            "export files", "help"}
_VERBS_THAT_TAKE_IDX = {"show", "dissect", "hex", "alerts"}
_VERBS_THAT_TAKE_EXPR = {"filter", "tshark", "search", "find"}


class CommandPlanner:
    def __init__(self, llm_client: Optional[LLMClient]):
        self.llm = llm_client

    # ------------------------------------------------------------------ #
    # Public entry                                                        #
    # ------------------------------------------------------------------ #
    def plan(self, user_input: str, context: Dict[str, Any]) -> Optional[str]:
        directive = self._heuristic(user_input)
        if directive:
            return directive
        if not self.llm or not self.llm.is_available():
            return None
        prompt = self._build_llm_prompt(user_input, context)
        # Phase 14 TASK 2 — compact system prompt from triage + patterns.
        system_prompt = None
        try:
            from ai.prompt_optimizer import build_system_prompt, top_patterns
            system_prompt = build_system_prompt(
                "planner", triage=context.get("triage"), patterns=top_patterns(2))
        except Exception as exc:
            logger.debug("prompt_optimizer planner failed: %s", exc)
        try:
            resp = self.llm.query(prompt, model_type="planner", temperature=0.1,
                                  system_prompt=system_prompt)
        except Exception as exc:
            logger.warning("Planner LLM call failed: %s", exc)
            return None
        if not resp:
            return None
        first = resp.strip().splitlines()[0].strip()
        # Validate the LLM didn't hallucinate a verb outside our set.
        head = first.split(None, 1)[0].lower() if first else ""
        if head not in _ALL_KNOWN_VERBS:
            return None
        return first

    # ------------------------------------------------------------------ #
    # Heuristic stage                                                     #
    # ------------------------------------------------------------------ #
    def _heuristic(self, user_input: str) -> Optional[str]:
        if user_input is None:
            return None
        # Strip wrapping quotes ("What is ...?" passed through as
        # `analyze "what is..."` keeps them). Do this before the
        # starts-with checks so quoted questions route correctly.
        s = user_input.strip()
        while len(s) >= 2 and s[0] in ("\"", "'", "“", "”") and s[-1] in ("\"", "'", "“", "”"):
            s = s[1:-1].strip()
        if not s:
            return None
        low = s.lower()

        # Pure numeric index → show <n>
        if re.fullmatch(r"\d{1,7}", s):
            return f"show {s}"

        # Already a valid directive → pass through unchanged.
        head = s.split(None, 1)[0].lower()
        if head in _ALL_KNOWN_VERBS:
            return s

        # Index extraction (highest priority when an explicit N is given)
        m_idx = re.search(r"\b(?:packet|pkt|alert|#)\s*(\d{1,7})\b", low)
        if m_idx:
            idx = m_idx.group(1)
            if any(k in low for k in ("hex", "raw", "byte", "dump")):
                return f"hex {idx}"
            if any(k in low for k in ("dissect", "breakdown", "decode", "show detail",
                                       "details", "what is")):
                return f"dissect {idx}"
            if "alert" in low and "packet" not in low and "pkt" not in low:
                return f"alerts {idx}"
            if any(k in low for k in ("show", "display")):
                return f"show {idx}"
            return f"show {idx}"

        # Factual question with specific IPs/ports — needs the explainer.
        # Heuristic: contains an IP and a question word, or contains a
        # port number and a question word.
        has_ip = bool(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", low))
        question_words = ("how many", "how much", "who", "what", "where",
                          "which", "source ip", "destination ip",
                          "username", "password", "recipient", "sender")
        is_factual = any(w in low for w in question_words)
        if has_ip and is_factual:
            return f"analyze {s}"

        # Forensic-entity question (no IP required). "How many usernames
        # are involved in the AIM conversation?" must reach the explainer,
        # not the "how many" -> stats bucket below.
        _FORENSIC_ENTITIES = (
            "username", "user name", "password", "recipient", "sender",
            "email", "mail", "credential", "login", "attachment",
            "attached", "transferred", "transfer", "conversation",
            "message", "chat", "buddy", "screen name", "md5", "hash",
            "filename", "file", "docx", "magic byte", "smtp", "aim",
            "im ", "port",
        )
        if is_factual and any(e in low for e in _FORENSIC_ENTITIES):
            return f"analyze {s}"

        # Keyword buckets (order matters: more specific first).
        keyword_map: List[Tuple[List[str], str]] = [
            (["follow stream", "follow tcp", "follow udp", "tcp stream",
               "reassemble"],
             lambda m: None),
            (["hex dump", "raw byte", "raw bytes", "hex view"],
             lambda m: None),  # need an index
            (["dissect", "breakdown", "decode", "decompose"],
             lambda m: None),  # need an index
            (["alert", "warning", "suspicious event", "finding"],
             lambda m: "alerts"),
            (["how many", "how much", "stat", "summary", "overview",
              "protocol breakdown", "top talker", "how big", "total"],
             lambda m: "stats"),
            (["flow", "conversation", "stream"],
             lambda m: None if any(low.startswith(q) for q in
                                   ("what", "who", "which", "where",
                                    "when", "why", "how")) else "flows"),
            (["all packet", "list packet", "show packet", "every packet"],
             lambda m: "list"),
            (["export", "carve", "extract file", "save file"],
             lambda m: "export files"),
            (["filter", "only show", "match", "where", "with src",
              "with dst", "from port", "to port", "between"],
             lambda m: None),  # need expression
            (["search", "grep", "find string", "look for"],
             lambda m: None),  # need regex
        ]
        for keywords, fn in keyword_map:
            for kw in keywords:
                if kw in low:
                    mapped = fn(keywords)
                    if mapped is None:
                        # Need more context — drop down to LLM.
                        break
                    return mapped

        # Default: ask the LLM via the explainer.
        return f"analyze {s}"

    # ------------------------------------------------------------------ #
    # LLM stage                                                           #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _build_llm_prompt(user_input: str, context: Dict[str, Any]) -> str:
        verbs_list = ", ".join(sorted(_ALL_KNOWN_VERBS))
        return f"""Parse this user utterance into ONE directive line.

User: {user_input}

Context:
- Packets: {context.get('packet_count', 0)}
- Protocols: {', '.join(context.get('protocols', []))}
- Alerts: {context.get('alert_count', 0)}

Return ONE of these forms (no other text):
  list
  stats
  alerts [<idx>]
  flows
  show <index>
  dissect <index>
  hex <index>
  filter <expression>
  search <regex>
  follow tcp|udp <flow_id>
  export files
  analyze <question>

Valid verbs: {verbs_list}

Response:"""


_ALL_KNOWN_VERBS = (
    _VERBS_THAT_TAKE_NO_ARG
    | _VERBS_THAT_TAKE_IDX
    | _VERBS_THAT_TAKE_EXPR
    | {"analyze", "follow", "export", "rule", "/"}
)


# ===========================================================================
# HypothesisPlanner — Phase 9 §9.1 (multi-agent DAG)
#
# Decomposes an analyst's investigation question into a DAG of up to 5
# testable hypotheses, each with tool hints and dependencies. Uses the
# small/fast planner role (OPENROUTER_PLANNER_MODEL, Ollama fallback
# llama3.2:3b). Every LLM call goes through LLMClient so the Phase 8
# OpenRouter→Ollama→Groq chain and the Phase 9 rate limiter apply.
# ===========================================================================
HYPOTHESIS_PLAN_SYSTEM_PROMPT = """You are a senior SOC investigation planner. Given an analyst's question
about a packet capture, plus a protocol triage summary and a list of
anomalies, decompose the question into up to 5 testable hypotheses.

Return a JSON array only. Each element:
{
  "id": "H1",
  "hypothesis": "one-sentence hypothesis",
  "depends_on": ["H2"],
  "tools_hint": ["get_statistics"],
  "priority": 1
}

Rules:
- IDs are H1..H5 in priority order (1 = highest).
- depends_on lists hypothesis ids that must be tested first; keep the
  graph shallow (depth <= 2). Use [] when a hypothesis is independent.
- tools_hint: pick from get_statistics, get_alerts, apply_display_filter,
  search_payloads, extract_strings, extract_files, follow_stream,
  get_smtp_credentials, get_email_attachments, get_packet_detail,
  list_flows, python_eval.
- Only emit hypotheses the triage and anomalies actually support. If the
  capture looks benign, emit exactly one:
  [{"id":"H1","hypothesis":"Traffic appears benign","depends_on":[],
    "tools_hint":["get_statistics"],"priority":1}]
- Output ONLY the JSON array. No markdown fences, no prose."""


def _make_fallback_plan(anomalies) -> Optional[List[Dict[str, Any]]]:
    """One trivial hypothesis from the top anomaly (no LLM)."""
    if not anomalies:
        return [{
            "id": "H1",
            "hypothesis": "Traffic appears benign",
            "depends_on": [],
            "tools_hint": ["get_statistics"],
            "priority": 1,
        }]
    a = max(anomalies, key=lambda x: x.score)
    return [{
        "id": "H1",
        "hypothesis": a.type.replace("_", " ").title(),
        "depends_on": [],
        "tools_hint": ["apply_display_filter", "get_packet_detail"],
        "priority": 1,
    }]


class HypothesisPlanner:
    """Turns an analyst question + triage + alerts into a hypothesis DAG."""

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm = llm_client

    def plan(self,
             question: str,
             triage: Optional[Dict[str, bool]] = None,
             alerts: Optional[List[Any]] = None,
             anomalies: Optional[List[Any]] = None,
             narrative: str = "",
             max_hypotheses: int = 5,
             tools_hint: Optional[List[str]] = None) -> Optional[List[Dict[str, Any]]]:
        """Return a validated list of hypothesis dicts, or None on failure.

        On any failure (LLM unavailable, JSON parse error, schema error)
        the caller is expected to fall back to the linear investigator.

        ``tools_hint`` (Phase 11 §11.1): optional list of tool names learned
        from prior critic-approved investigations. When supplied and
        non-empty, the planner uses it as an *override* for every
        hypothesis's tools_hint instead of trusting the LLM's guess.
        """
        if self.llm is None or not getattr(self.llm, "is_available", lambda: False)():
            return _make_fallback_plan(anomalies or [])

        learned_hint = [str(t) for t in (tools_hint or []) if t][:5]

        from core.triage import TRIAGE_FLAG_KEYS
        triage_on = sorted(k for k in TRIAGE_FLAG_KEYS
                           if (triage or {}).get(k))
        alert_lines = [
            (f"- {getattr(a, 'rule_name', '?')}: {getattr(a, 'message', '')}"
             f" {getattr(a, 'metadata', {})}")
            for a in (alerts or [])[:10]
        ]
        anomaly_lines = [
            (f"- {a.type} (score {a.score:.2f}) {a.evidence} {a.hosts}")
            for a in (anomalies or [])[:8]
        ]
        narrative_excerpt = (narrative or "")[:1500]

        user = (
            f"Analyst question: {question}\n\n"
            f"Protocols present (triage): {', '.join(triage_on) or '(none)'}\n\n"
            f"Alerts ({len(alerts or [])}):\n" + ("\n".join(alert_lines) or "  (none)") + "\n\n"
            f"Anomalies ({len(anomalies or [])}):\n" + ("\n".join(anomaly_lines) or "  (none)") + "\n\n"
            f"Capture summary (abridged):\n{narrative_excerpt}\n\n"
            "Produce the hypothesis plan as a JSON array."
        )
        from ai.investigator import _single_completion, _extract_json_array
        raw = _single_completion(
            self.llm, HYPOTHESIS_PLAN_SYSTEM_PROMPT, user,
            model_type="planner", temperature=0.1, max_tokens=3000,
        )
        if not raw:
            logger.warning("HypothesisPlanner: LLM returned no plan")
            return None

        parsed = _extract_json_array(raw)
        if not parsed:
            logger.warning("HypothesisPlanner: unparseable plan: %.200s", raw)
            return None

        items = []
        seen_ids: set = set()
        fallback_counter = 1
        for item in parsed[:max_hypotheses]:
            if not isinstance(item, dict):
                continue
            h = self._validate(item, fallback_id=f"H{fallback_counter}")
            if h is None or h["id"] in seen_ids:
                continue
            # Phase 11 §11.1 — learned tool hints override the LLM's guess.
            if learned_hint:
                merged = list(dict.fromkeys(learned_hint
                                            + (h.get("tools_hint") or [])))
                h["tools_hint"] = merged[:5]
            fallback_counter += 1
            seen_ids.add(h["id"])
            items.append(h)
        if not items:
            logger.warning("HypothesisPlanner: no valid hypotheses in plan")
            return None

        # Normalise dependency references to known ids only.
        valid_ids = {h["id"] for h in items}
        for h in items:
            h["depends_on"] = [d for d in h.get("depends_on", []) if d in valid_ids]
        return items

    @staticmethod
    def _validate(item: Dict[str, Any],
                  fallback_id: str = "H1") -> Optional[Dict[str, Any]]:
        hid = str(item.get("id", "")).strip()
        if not re.fullmatch(r"H\d+", hid, re.IGNORECASE):
            hid = fallback_id
        name = str(item.get("hypothesis", "")).strip()
        if not name:
            return None
        deps = [str(d) for d in (item.get("depends_on") or [])]
        hints = [str(h) for h in (item.get("tools_hint") or [])][:5]
        try:
            priority = int(item.get("priority", 2))
        except (TypeError, ValueError):
            priority = 2
        priority = max(1, min(3, priority))
        return {
            "id": hid,
            "hypothesis": name[:200],
            "depends_on": deps[:4],
            "tools_hint": hints,
            "priority": priority,
        }

