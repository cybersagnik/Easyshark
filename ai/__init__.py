"""ai package — public exports."""
from .llm_client import LLMClient
from .explainer import TrafficExplainer
from .planner import CommandPlanner, HypothesisPlanner
from .rule_generator import RuleGenerator
from .dag_runner import DagRunner, DAGHypothesis, DAGResult
from .critic import Critic
from .payload_analyzer import (
    extract_strings,
    extract_transferred_files,
    extract_transferred_files_blobs,
    decode_smtp_auth_credentials,
    parse_smtp_attachments,
    summarize_payloads,
)
from .tool_registry import (
    ToolContext,
    TOOL_SCHEMAS,
    TOOL_EXECUTORS,
    execute_tool,
    register_tool,
)

__all__ = [
    "LLMClient",
    "TrafficExplainer",
    "CommandPlanner",
    "HypothesisPlanner",
    "DagRunner",
    "DAGHypothesis",
    "DAGResult",
    "Critic",
    "RuleGenerator",
    "extract_strings",
    "extract_transferred_files",
    "extract_transferred_files_blobs",
    "decode_smtp_auth_credentials",
    "parse_smtp_attachments",
    "summarize_payloads",
    "ToolContext",
    "TOOL_SCHEMAS",
    "TOOL_EXECUTORS",
    "execute_tool",
    "register_tool",
]
