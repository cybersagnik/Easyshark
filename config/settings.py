"""
Application settings and configuration.

Architecture (from EasyShark master brief §1):

  FROZEN sections (read-only, never modify without brief update):
    - Detection thresholds (DETECTION_RULES)
    - Flow / TCP / threading settings
    - PCAP / cache

  ACTIVE sections (the LLM layer — primary work zone):
    
    - GROQ_* constants (optional cloud fallback)
    - Tool-calling knobs
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader (no external dependency).

    Reads KEY=VALUE lines into os.environ WITHOUT overriding values that
    are already set (standard dotenv semantics). Empty values are treated
    as unset so empty values in .env do not clobber defaults.
    """
    try:
        if not path.exists():
            return
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and val and key not in os.environ:
                os.environ[key] = val
    except Exception:
        # Never fail the import because of a malformed .env file.
        return


_load_dotenv(BASE_DIR / ".env")

# ---------------------------------------------------------------------------
# Groq cloud — optional. Disabled by default in this build.
# ---------------------------------------------------------------------------
# Keep the API key plumbing so the existing .env / CI configs still work,
# but the LLM client does NOT use Groq unless GROQ_ENABLED=1 is exported.
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_BASE_URL = "https://api.groq.com"
GROQ_ENABLED  = os.environ.get("GROQ_ENABLED", "0") == "1"

# Role -> Groq model identifier mapping. Roles are stable; identifiers may
# change as Groq rotates its catalog.
GROQ_MODELS = {
    "planner":   "llama-3.1-8b-instant",
    "explainer": "llama-3.3-70b-versatile",
    "coder":     "qwen/qwen3.6-27b",
    "critic":    "llama-3.3-70b-versatile",
}
# Phase 14 .env contract — a single GROQ_MODEL applies to ALL roles
# (Groq is the last-resort backend; keep it simple with one model).
GROQ_MODEL = os.environ.get("GROQ_MODEL", "").strip()
if GROQ_MODEL:
    for _k in list(GROQ_MODELS):
        GROQ_MODELS[_k] = GROQ_MODEL
# Phase 16 — per-role Groq overrides take precedence over GROQ_MODEL
# (e.g. GROQ_EXPLAINER_MODEL=llama-3.3-70b-versatile). Mirrors the
# ZEN_* / OPENROUTER_* / GROQ_* per-role override pattern.
for _role in ("planner", "explainer", "coder", "critic"):
    _env_key = f"GROQ_{_role.upper()}_MODEL"
    if os.environ.get(_env_key):
        GROQ_MODELS[_role] = os.environ[_env_key]

GROQ_TIMEOUT = 30
GROQ_MAX_TOKENS = 1024
GROQ_MAX_TOKENS_TOOLS = 2048

# Per-role temperature defaults. Lower = more deterministic output.
# Cloud models (Zen/Groq) are instruction-tuned for tool-calling.
SYSTEM_TEMPERATURE = {
    "planner":   0.1,      # deterministic for tool decisions
    "explainer": 0.2,      # slightly creative for explanations
    "coder":     0.1,      # strict output format
    "critic":    0.1,      # strict verification
}

# Gap 5 — Zen (primary transport) per-role temperatures.
ZEN_TEMPERATURE = {
    "planner":   0.1,
    "explainer": 0.3,
    "coder":     0.2,
    "critic":    0.1,
}

# Default temperature the public query() API uses when caller passes 0.7.
DEFAULT_TEMPERATURE = 0.2

# ---------------------------------------------------------------------------
# Tool-calling knobs
# ---------------------------------------------------------------------------
TOOL_CALL_MAX_STEPS    = 6       # how many tool round-trips before forcing an answer
TOOL_RESULT_CHAR_CAP   = 2000    # per-tool-result size limit before truncation
# Phase 15: raised from 6000 — the dissection tools (31-file listings) plus
# the system/user/tool history overflowed the old budget and _trim_messages
# evicted the evidence rounds from the front, so the model claimed its own
# tool results were "not visible". Backends (Zen, Groq) have 32K+ contexts.
TOOL_TOTAL_CHAR_CAP    = 12000   # total tool context budget; oldest entries dropped first

# ---------------------------------------------------------------------------
# File export / carving
# ---------------------------------------------------------------------------
EXPORT_DIR = "./exported"

# ---------------------------------------------------------------------------
# System prompts
#
# Tuned for cloud models (Zen/Groq). Three rules:
#   1. Be EXPLICIT about the output format — show the exact template.
#   2. Constrain vocabulary — small models hallucinate domain terms.
#   3. Tell the model to call tools BY NAME — no invented tool names.
# ---------------------------------------------------------------------------
SYSTEM_PROMPTS = {
    "planner": (
        "You are the command router for a packet-capture analysis shell.\n"
        "The analyst types natural-language questions; you decide which "
        "tools to call (and in what order) until you can answer the "
        "question from real evidence in the capture.\n\n"
        "TOOLS YOU CAN CALL (use exactly these names):\n"
        "  - get_statistics         (overall packet/flow/alert counts)\n"
        "  - get_alerts            (list triggered alerts)\n"
        "  - apply_display_filter  (filter packets by ip/port/protocol)\n"
        "  - search_payloads       (regex search over TCP/UDP payloads)\n"
        "  - extract_strings       (printable strings from payloads)\n"
        "  - extract_files         (carve files from TCP flows)\n"
        "  - follow_stream         (reassembled ASCII stream for a flow)\n"
        "  - get_smtp_credentials  (decoded SMTP AUTH credentials)\n"
        "  - get_email_attachments (SMTP/POP3 attachment metadata)\n"
        "  - get_packet_detail     (full packet breakdown by index)\n"
        "  - list_flows            (active TCP/UDP flows)\n\n"
        "RULES (strictly follow):\n"
        "1. Never invent IPs, ports, usernames, filenames, MD5s, or text.\n"
        "2. When evidence supports a verdict (benign / suspicious / "
        "likely-malicious), state it AND cite the packet, IP, file, or alert.\n"
        "3. If you cannot find the requested item after investigation, "
        "say 'Insufficient data' and suggest ONE follow-up tool call.\n"
        "4. Output format on FINAL answer (no tool calls):\n"
        "   Answer: <value> (source: <tool_name>)\n"
        "5. Be concise — 2 to 5 sentences max.\n"
    ),

    "explainer": (
        "You are a senior network forensic investigator. The analyst "
        "asks a free-form question; you call tools to gather real "
        "evidence and answer.\n\n"
        "TOOLS YOU CAN CALL (use exactly these names):\n"
        "  - get_statistics\n"
        "  - get_alerts\n"
        "  - apply_display_filter\n"
        "  - search_payloads\n"
        "  - extract_strings\n"
        "  - extract_files\n"
        "  - follow_stream\n"
        "  - get_smtp_credentials\n"
        "  - get_email_attachments\n"
        "  - get_packet_detail\n"
        "  - list_flows\n"
        "  - compute_packets\n"
        "  - extract_embedded_media (extracts embedded images/media from a\n"
        "    .docx attachment and SAVES them to a host path the analyst gives)\n"
        "  - python_eval (only if enabled; LAST resort for computations no\n"
        "    fixed tool can express)\n"
        "  - create_tool (only if enabled; defines a NEW sandboxed tool at\n"
        "    runtime — use it when NO existing tool answers the question)\n\n"
        "TYPICAL TOOL SEQUENCES (use them as starting points):\n"
        "  IM / chat (AIM / MSN / Yahoo): extract_strings -> search_payloads\n"
        "  File transferred over IM: extract_files\n"
        "  SMTP creds: get_smtp_credentials\n"
        "  Email attachments: get_email_attachments\n"
        "  Embedded image in docx -> SAVE to path: extract_embedded_media\n"
        "  Packets to port from IP: apply_display_filter (or search_payloads) -> get_packet_detail\n"
        "  Ad-network / domain: search_payloads with regex 'at.atwola|ads\\\\.|adiframe|addyn|doubleclick'\n"
        "  Docx / file content: extract_files lists carved .docx blobs (format,\n"
        "    size, md5) but does NOT always include the parsed text (fragmented\n"
        "    transfers lack text_preview). To READ a docx body, unzip it:\n"
        "    python_eval with zipfile over the carved bytes, or define a\n"
        "    reusable docx-reading tool with create_tool.\n\n"
        "RULES (strictly follow):\n"
        "1. EVERY claim must be backed by a tool result. Never fabricate "
        "IPs, ports, usernames, filenames, MD5s, or text.\n"
        "2. When the question asks for a specific identifier (username, "
        "filename, MD5, magic number, email address, password, chat "
        "message, file content, location), CALL the appropriate tool to "
        "retrieve it. Default to 2-3 tool calls before forming an answer.\n"
        "3. If extract_files returns a .docx WITHOUT text_preview, its "
        "text is not available from that tool — use python_eval (or "
        "create_tool) to read word/document.xml inside the carved zip.\n"
        "4. 'Insufficient data' is a LAST RESORT. Only emit it after you "
        "have called at least 2 different tools AND inspected at least "
        "one tool result that confirms the item is absent. Suggest ONE "
        "follow-up tool call after stating Insufficient data.\n"
        "5. Final-answer format:\n"
        "   Answer: <value> (source: <tool_name>)\n"
        "6. Be concise — 2 to 5 sentences max.\n"
        "7. PREFER quoting the exact value from a tool result over "
        "paraphrasing — substring matchers will reject synonyms.\n"
    ),

    "coder": (
        "You are a senior detection engineer writing security rules for "
        "an enterprise SOC. You receive a task description and context, "
        "and must emit exactly one of:\n"
        "  - a Snort rule (single line, valid Snort syntax)\n"
        "  - a YARA rule (strings + condition blocks)\n"
        "  - a Python detection function\n\n"
        "STRICT OUTPUT RULES:\n"
        "1. Output ONLY the rule or code. No preamble, no explanation, "
        "no markdown fences, no trailing commentary.\n"
        "2. Use realistic placeholders only where the task does not "
        "specify a value (e.g. <ATTACKER_IP>, <PORT>); never invent "
        "specific IPs, domains, or signatures.\n"
        "3. For Snort: emit ONE line starting with 'alert '. Include "
        "msg:, sid: (>= 1000001), and rev:.\n"
        "4. For YARA: include a rule name, a meta block with author and "
        "description, a strings block, and a condition.\n"
        "5. For Python: a single function with a clear signature, a "
        "docstring, and inline comments. Return True for malicious, "
        "False otherwise.\n"
    ),

    "critic": (
        "You are a rigorous evidence critic in a SOC. An executor agent "
        "has verified a hypothesis against a packet capture using forensic "
        "tools, and you must audit its verdict.\n\n"
        "Your job:\n"
        "1. Are every claim in the verdict GROUNDED in the raw tool output? "
        "Reject any IP, port, hash, username, filename, or count that does "
        "not appear in the evidence.\n"
        "2. Is the numeric confidence (0.0-1.0) reasonable given the "
        "strength and quantity of evidence?\n"
        "3. Is the verdict ('confirmed'/'weakened'/'ruled_out') consistent "
        "with the evidence?\n\n"
        "STRICT OUTPUT RULES:\n"
        "1. Output ONLY a JSON object, no prose, no markdown fences:\n"
        "{\n"
        '  "approved": true|false,\n'
        '  "corrected_verdict": <string or null>,\n'
        '  "issues": ["short issue 1", "short issue 2"]\n'
        "}\n"
        "2. 'approved' is true only when every claim is grounded AND the "
        "confidence matches the evidence. Correct small problems by setting "
        "'corrected_verdict' to a short corrected summary.\n"
        "3. Never invent evidence that is not in the tool output.\n"
    ),
}

# Groq uses the same prompts. Kept identical here for simplicity.
GROQ_SYSTEM_PROMPTS = SYSTEM_PROMPTS

# ---------------------------------------------------------------------------
# OpenCode Zen cloud — PRIMARY transport (replaces OpenRouter, 2026-08-03).
# ---------------------------------------------------------------------------
# Zen is the OpenAI-compatible endpoint at opencode.ai/zen/v1. The agentic
# DAG (planner->executor->critic) needs tool calling; all Zen free models
# support it. Groq remains as last-resort fallback.
# NOTE: requests MUST send a browser-like User-Agent header or Cloudflare
# returns 403 (error code 1010) — handled inside llm_client._zen_* methods.
ZEN_ENABLED = os.environ.get("ZEN_ENABLED", "0") != "0"
ZEN_API_KEY  = os.environ.get("ZEN_API_KEY", "")
ZEN_BASE_URL = os.environ.get("ZEN_BASE_URL",
                              "https://opencode.ai/zen/v1").rstrip("/")
ZEN_TIMEOUT   = int(os.environ.get("ZEN_TIMEOUT", "120"))
ZEN_MAX_TOKENS = int(os.environ.get("ZEN_MAX_TOKENS", "2048"))

# Role -> Zen free model identifier. All free-tier, no API cost.
# Override per role via env (e.g. ZEN_EXPLAINER_MODEL=deepseek-v4-flash-free).
ZEN_MODELS = {
    "planner":   os.environ.get("ZEN_PLANNER_MODEL",
                                "ling-3.0-flash-free"),
    "explainer": os.environ.get("ZEN_EXPLAINER_MODEL",
                                "deepseek-v4-flash-free"),
    "coder":     os.environ.get("ZEN_CODER_MODEL",
                                "north-mini-code-free"),
    "critic":    os.environ.get("ZEN_CRITIC_MODEL",
                                "deepseek-v4-flash-free"),
}

# Session rate-limiter guard (mirrors the Phase 9 §9.5 pattern). Counters
# live in LLMClient; these are the thresholds. Zen free tier is generous;
# defaults are higher than OpenRouter's old free tier.
ZEN_DAILY_SOFT_CAP = int(os.environ.get("ZEN_DAILY_SOFT_CAP", "200"))
ZEN_DAILY_HARD_CAP = int(os.environ.get("ZEN_DAILY_HARD_CAP", "250"))
ZEN_MINUTE_SOFT_CAP = int(os.environ.get("ZEN_MINUTE_SOFT_CAP", "30"))
ZEN_MINUTE_SLEEP_SEC = float(os.environ.get("ZEN_MINUTE_SLEEP_SEC", "2"))

# ---------------------------------------------------------------------------
# OpenRouter cloud — legacy transport (retained for rollback/tests).
# Disabled by default now that Zen is primary; re-enable with
# OPENROUTER_ENABLED=1 to use it again.
# ---------------------------------------------------------------------------
OPENROUTER_ENABLED = os.environ.get("OPENROUTER_ENABLED", "0") != "0"
OPENROUTER_API_KEY  = os.environ.get("OPENROUTER_API_KEY", "")
OPENROUTER_BASE_URL = os.environ.get("OPENROUTER_BASE_URL",
                                     "https://openrouter.ai/api/v1").rstrip("/")
OPENROUTER_TIMEOUT   = int(os.environ.get("OPENROUTER_TIMEOUT", "90"))
OPENROUTER_MAX_TOKENS = int(os.environ.get("OPENROUTER_MAX_TOKENS", "2048"))

# Role -> OpenRouter model identifier. Free-tier models, no API cost.
# Override per role via env (e.g. OPENROUTER_EXPLAINER_MODEL=gpt-5:free).
OPENROUTER_MODELS = {
    "planner":   os.environ.get("OPENROUTER_PLANNER_MODEL",
                                "nvidia/nemotron-nano-9b-v2:free"),
    "explainer": os.environ.get("OPENROUTER_EXPLAINER_MODEL",
                                "openai/gpt-oss-20b:free"),
    "coder":     os.environ.get("OPENROUTER_CODER_MODEL",
                                "cohere/north-mini-code:free"),
    "critic":    os.environ.get("OPENROUTER_CRITIC_MODEL",
                                "openai/gpt-oss-20b:free"),
}

# Session rate-limiter guard (Phase 9 §9.5). Counters live in LLMClient;
# these are the thresholds.
OPENROUTER_DAILY_SOFT_CAP = int(os.environ.get("OPENROUTER_DAILY_SOFT_CAP", "45"))
OPENROUTER_DAILY_HARD_CAP = int(os.environ.get("OPENROUTER_DAILY_HARD_CAP", "50"))
OPENROUTER_MINUTE_SOFT_CAP = int(os.environ.get("OPENROUTER_MINUTE_SOFT_CAP", "18"))
OPENROUTER_MINUTE_SLEEP_SEC = float(os.environ.get("OPENROUTER_MINUTE_SLEEP_SEC", "3"))

# ---------------------------------------------------------------------------
# PCAP / flow / detection — FROZEN thresholds
# ---------------------------------------------------------------------------
FLOW_TIMEOUT = 300.0
TCP_REASSEMBLY_ENABLED = True
MAX_PACKET_SIZE = 65535
CACHE_ENABLED = True
CACHE_MAX_SIZE = 1000
THREADING_MAX_WORKERS = 4

LOG_LEVEL = "INFO"
LOG_FILE = None

PREPROCESSORS = {
    'flow': True,
    'dns':  True,
    'tls':  True,
    'arp':  True,
    'http': True,
}

DETECTION_RULES = {
    'portscan':    {'enabled': True, 'threshold': 20, 'time_window': 60.0},
    'dns_tunnel':  {'enabled': True, 'query_threshold': 50, 'entropy_threshold': 3.5},
    'beaconing':   {'enabled': True, 'min_connections': 10, 'interval_tolerance': 0.2},
    'tls_anomaly': {'enabled': True},
    'arp_spoof':   {'enabled': True},
    'signatures':  {'enabled': True},
    'c2_exfil':    {'enabled': True},
}

# ---------------------------------------------------------------------------
# Threat-intel blocklist (local, offline)
# ---------------------------------------------------------------------------
THREAT_INTEL_CIDRS = [
    "203.0.113.0/24",
    "10.10.10.0/24",
]  
