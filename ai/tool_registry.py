"""
Tool registry — the read-only investigation toolbox the LLM can call.

Every tool:
  - has a JSON schema (TOOL_SCHEMAS) the model sees,
  - has a Python executor (TOOL_EXECUTORS) that runs over a ToolContext,
  - is bounded in output size,
  - never raises — catches internally and returns {"error": str(e)}.

Phase 6 additions:
  - python_eval sandbox: read-only Python execution over a frozen
    context of {packets, flows, alerts, stats, pcap}. 5-second wall-clock
    timeout, 50 MB RSS cap. No network, no subprocess, no file I/O.
  - Each tool schema's description carries 2-3 few-shot invocation
    examples (Task 6.4) so the models pick the right
    tool the first time without inventing tool names.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import signal
import sys
import threading
import time as _time_mod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from core.packet_metadata import PacketMetadata

logger = logging.getLogger(__name__)


def _perf_counter() -> float:
    return _time_mod.perf_counter()


# ---------------------------------------------------------------------------
# ToolContext — what the LLM can investigate
# ---------------------------------------------------------------------------
@dataclass
class ToolContext:
    packets: List[PacketMetadata] = field(default_factory=list)
    flows:   List[Any]            = field(default_factory=list)   # core.Flow
    alerts:  List[Any]            = field(default_factory=list)
    stats_engine: Any = None
    flow_engine:   Any = None
    pcap_path: Optional[str] = None   # used for the tool-cache key (Phase 10.3)

    # Phase 15 — deterministic capture analysis attached at shell load time.
    # Used by the dissection-aware tools below. ``triage`` is the
    # core/triage.triage_capabilities dict; ``dissection`` is the
    # core/dissector.dissect_packets dict.
    triage: Optional[Dict[str, Any]] = None
    dissection: Optional[Dict[str, Any]] = None

    def get_packet(self, index: int) -> Optional[PacketMetadata]:
        if 0 <= index < len(self.packets):
            return self.packets[index]
        return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _payload_bytes(pkt) -> bytes:
    return getattr(pkt, "payload", b"") or b""


def _md5(data: bytes) -> str:
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


# ---------------------------------------------------------------------------
# Tool 1: get_statistics
# ---------------------------------------------------------------------------
def tool_get_statistics(args: Dict[str, Any], ctx: ToolContext) -> Dict[str, Any]:
    if ctx.stats_engine is None:
        return {"error": "no stats engine attached"}
    return ctx.stats_engine.summary()


# ---------------------------------------------------------------------------
# Tool 2: get_alerts
# ---------------------------------------------------------------------------
def tool_get_alerts(args: Dict[str, Any], ctx: ToolContext) -> Dict[str, Any]:
    items = []
    for a in ctx.alerts:
        items.append({
            "rule": getattr(a, "rule_name", "?"),
            "severity": getattr(a, "severity", ""),
            "message": getattr(a, "message", ""),
            "metadata": getattr(a, "metadata", {}),
        })
    return {"count": len(items), "alerts": items[:50]}


# ---------------------------------------------------------------------------
# Tool 3: apply_display_filter
# ---------------------------------------------------------------------------
def tool_apply_display_filter(args: Dict[str, Any], ctx: ToolContext) -> Dict[str, Any]:
    expr = args.get("filter", "")
    if not expr:
        return {"error": "missing 'filter' argument"}
    from core.filter_engine import SimpleFilter, DisplayFilter
    # Try rich grammar first
    try:
        df = DisplayFilter(expr)
        matches = df.apply(ctx.packets)
    except Exception:
        sf = SimpleFilter(expr)
        matches = sf.apply(ctx.packets)
    return {"filter": expr, "match_count": len(matches),
            "packet_indices": [p.index for p in matches[:100]]}


# ---------------------------------------------------------------------------
# Tool 4: search_payloads
# ---------------------------------------------------------------------------
def tool_search_payloads(args: Dict[str, Any], ctx: ToolContext) -> Dict[str, Any]:
    pattern = args.get("regex", "")
    if not pattern:
        return {"error": "missing 'regex' argument"}
    case_insensitive = bool(args.get("ignore_case", True))
    try:
        flags = re.IGNORECASE if case_insensitive else 0
        rx = re.compile(pattern, flags)
    except re.error as exc:
        return {"error": f"bad regex: {exc}"}
    hits = []
    for pkt in ctx.packets:
        payload = _payload_bytes(pkt)
        m = rx.search(payload.decode("latin-1", "replace"))
        if m:
            hits.append({"pkt": pkt.index,
                         "match": m.group(0)[:200],
                         "context": payload[max(0, m.start()-40):m.end()+40]
                                     .decode("latin-1", "replace")[:200]})
            if len(hits) >= 50:
                break
    return {"pattern": pattern, "case_insensitive": case_insensitive,
            "hit_count": len(hits), "hits": hits}


# ---------------------------------------------------------------------------
# Tool 5: extract_strings
# ---------------------------------------------------------------------------
_PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")


def tool_extract_strings(args: Dict[str, Any], ctx: ToolContext) -> Dict[str, Any]:
    min_len = int(args.get("min_length", 6))
    rx = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    out = []
    for pkt in ctx.packets:
        payload = _payload_bytes(pkt)
        for m in rx.finditer(payload):
            s = m.group(0).decode("latin-1")
            out.append({"pkt": pkt.index, "s": s})
            if len(out) >= 200:
                return {"count": len(out), "strings": out}
    return {"count": len(out), "strings": out}


# ---------------------------------------------------------------------------
# Tool 6: extract_files (magic-byte file carving from TCP payloads)
# ---------------------------------------------------------------------------
_MAGIC = [
    (b"PK\x03\x04", "ZIP/DOCX"),
    (b"\xd0\xcf\x11\xe0", "OLE/DOC"),
    (b"%PDF",        "PDF"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"GIF87a", "GIF"),
    (b"GIF89a", "GIF"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"7z\xbc\xaf\x27\x1c", "7Z"),
    (b"\x1f\x8b", "GZIP"),
    (b"BZh", "BZIP2"),
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE/EXE"),
]


def tool_extract_files(args: Dict[str, Any], ctx: ToolContext) -> Dict[str, Any]:
    min_size = int(args.get("min_size", 64))
    out = []
    seen_md5 = set()
    for pkt in ctx.packets:
        payload = _payload_bytes(pkt)
        for magic, fmt in _MAGIC:
            idx = payload.find(magic)
            if idx < 0:
                continue
            blob = payload[idx:idx + 5_000_000]
            if len(blob) < min_size:
                continue
            md5 = _md5(blob)
            if md5 in seen_md5:
                continue
            seen_md5.add(md5)
            text_preview = ""
            # Try to peek docx xml preview
            if fmt == "ZIP/DOCX":
                text_preview = _peek_docx(blob)
            entry = {
                "pkt": pkt.index,
                "format": fmt,
                "size": len(blob),
                "md5": md5,
                "magic_hex": magic.hex(),
            }
            if text_preview:
                entry["text_preview"] = text_preview
            out.append(entry)
            if len(out) >= 50:
                return {"count": len(out), "files": out}
    return {"count": len(out), "files": out}


def _peek_docx(blob: bytes) -> str:
    """Best-effort text peek inside a ZIP/DOCX blob. Looks for
    word/document.xml and pulls <w:t>...</w:t> strings."""
    import zipfile, io
    try:
        z = zipfile.ZipFile(io.BytesIO(blob))
        for name in z.namelist():
            if name.endswith("document.xml"):
                xml = z.read(name).decode("utf-8", "replace")
                texts = re.findall(r"<w:t[^>]*>(.*?)</w:t>", xml, re.DOTALL)
                joined = " ".join(t for t in texts if t.strip())
                return joined[:1500]
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------------------
# Tool 7: follow_stream
# ---------------------------------------------------------------------------
def tool_follow_stream(args: Dict[str, Any], ctx: ToolContext) -> Dict[str, Any]:
    flow_id = args.get("flow_id")
    if flow_id is None:
        # Try first matching flow
        return {"error": "missing 'flow_id' argument (use list_flows to discover)"}
    try:
        idx = int(flow_id)
    except (TypeError, ValueError):
        return {"error": f"flow_id must be int, got {flow_id!r}"}
    if not (0 <= idx < len(ctx.flows)):
        return {"error": f"flow_id {idx} out of range (0..{len(ctx.flows)-1})"}
    flow = ctx.flows[idx]
    text = (getattr(flow, "payload_bytes", b"") or b"").decode("latin-1", "replace")
    return {"flow_id": idx,
            "src": f"{flow.src_ip}:{flow.src_port}",
            "dst": f"{flow.dst_ip}:{flow.dst_port}",
            "packet_count": flow.packet_count,
            "bytes": flow.total_bytes,
            "stream_text": text[:8000]}


# ---------------------------------------------------------------------------
# Tool 8: get_smtp_credentials
# ---------------------------------------------------------------------------
def tool_get_smtp_credentials(args: Dict[str, Any], ctx: ToolContext) -> Dict[str, Any]:
    """Walk every TCP stream, find base64 AUTH LOGIN / AUTH PLAIN exchanges,
    decode them. Delegates to the canonical parser in payload_analyzer so
    this stays in lockstep with offline / summarise outputs."""
    from ai.payload_analyzer import decode_smtp_auth_credentials
    packets = list(getattr(ctx, "packets", []) or [])
    if not packets and ctx.flows:
        # Re-derive packets from flow payloads as a fallback.
        packets = []
    decoded = decode_smtp_auth_credentials(packets) if packets else []
    auths = []
    for d in decoded:
        auths.append({
            "flow": d.get("flow", "?"),
            "method": d.get("method", "AUTH LOGIN"),
            "user": d.get("user", ""),
            "password": d.get("password", ""),
        })
    return {"count": len(auths), "credentials": auths}


# ---------------------------------------------------------------------------
# Tool 9: get_email_attachments
# ---------------------------------------------------------------------------
def tool_get_email_attachments(args: Dict[str, Any], ctx: ToolContext) -> Dict[str, Any]:
    """Walk SMTP DATA payloads, decode MIME parts, return attachment list.
    Delegates to the canonical parser in payload_analyzer so the tool
    stays in lockstep with offline / summarise outputs and exposes the
    embedded-media MD5s that the LLM otherwise cannot see."""
    from ai.payload_analyzer import parse_smtp_attachments
    packets = list(getattr(ctx, "packets", []) or [])
    parsed = parse_smtp_attachments(packets) if packets else []
    attachments = []
    for a in parsed:
        attachments.append({
            "flow": a.get("flow", "?"),
            "filename": a.get("filename", ""),
            "size": a.get("size", 0),
            "md5": a.get("md5", ""),
            "text": (a.get("text") or "")[:1000],
            "media_md5s": a.get("media_md5s", []) or [],
        })
        if len(attachments) >= 50:
            break
    # Also extract SMTP envelope (MAIL FROM / RCPT TO) for any flow that
    # had attachments, so the LLM can answer recipient/sender questions.
    envelope: Dict[str, Dict[str, str]] = {}
    if packets:
        from ai.payload_analyzer import _canonical_flow_key, _flow_key_of
        flows = {}
        for m in packets:
            k = _flow_key_of(m)
            if not k:
                continue
            ck = _canonical_flow_key(k)
            flows.setdefault(str(ck), b"")
            flows[str(ck)] += getattr(m, "payload", b"") or b""
        for fid, blob in flows.items():
            mail_from = re.search(rb"MAIL FROM:\s*<([^>\r\n]+)>", blob, re.IGNORECASE)
            rcpt_to = re.search(rb"RCPT TO:\s*<([^>\r\n]+)>", blob, re.IGNORECASE)
            if mail_from or rcpt_to:
                envelope[fid] = {
                    "mail_from": (mail_from.group(1).decode("utf-8", "replace")
                                  if mail_from else ""),
                    "rcpt_to": (rcpt_to.group(1).decode("utf-8", "replace")
                                if rcpt_to else ""),
                }
    return {"count": len(attachments),
            "attachments": attachments,
            "envelope": envelope}


# ---------------------------------------------------------------------------
# Tool 9b: extract_embedded_media — save embedded media from a .docx to disk
# ---------------------------------------------------------------------------
def tool_extract_embedded_media(args: Dict[str, Any], ctx: ToolContext) -> Dict[str, Any]:
    """Extract embedded media files (word/media/*) from a .docx SMTP
    attachment and write them to a host path the analyst chooses.

    Deterministic host-side capability — the docx bytes are re-carved from
    the capture, unzipped, and each media entry is written to ``output_dir``.
    This works regardless of the LLM/sandbox because the container cannot
    reach the host filesystem.

    Args:
        output_dir (required): absolute path to save the media files into.
        output_prefix (optional): prefix for saved filenames
            (default: original archive entry basename).
    """
    from ai.payload_analyzer import parse_smtp_attachments
    output_dir = (args.get("output_dir") or "").strip()
    if not output_dir:
        return {"error": "extract_embedded_media: 'output_dir' is required"}
    import os as _os
    from pathlib import Path as _Path
    try:
        out_root = _Path(output_dir).expanduser().resolve()
        out_root.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        return {"error": f"extract_embedded_media: cannot create output_dir: {exc}"}

    packets = list(getattr(ctx, "packets", []) or [])
    atts = parse_smtp_attachments(packets, include_data=True) if packets else []
    saved = []
    for a in atts:
        filename = a.get("filename", "")
        if not filename.lower().endswith(".docx"):
            continue
        body = a.get("data") or b""
        media_names = a.get("media_names") or []
        if not media_names:
            continue
        import zipfile, io
        try:
            zf = zipfile.ZipFile(io.BytesIO(body))
        except Exception:
            continue
        for name in media_names:
            try:
                raw = zf.read(name)
            except Exception:
                continue
            base = _os.path.basename(name) or "media.bin"
            prefix = (args.get("output_prefix") or "").strip()
            safe = prefix + base if not prefix.endswith(("/", "_")) else prefix + base
            target = out_root / safe
            try:
                target.write_bytes(raw)
            except Exception as exc:
                return {"error": f"extract_embedded_media: write failed {target}: {exc}"}
            saved.append({
                "archive_entry": name,
                "filename": safe,
                "path": str(target),
                "size": len(raw),
                "md5": _md5(raw),
            })
    if not saved:
        return {"error": "extract_embedded_media: no .docx attachments with "
                         "embedded media found in this capture"}
    return {"count": len(saved), "saved": saved,
            "output_dir": str(out_root)}


# ---------------------------------------------------------------------------
# Tool 10: get_packet_detail
# ---------------------------------------------------------------------------
def tool_get_packet_detail(args: Dict[str, Any], ctx: ToolContext) -> Dict[str, Any]:
    idx = args.get("index")
    if idx is None:
        return {"error": "missing 'index' argument"}
    try:
        idx = int(idx)
    except (TypeError, ValueError):
        return {"error": f"index must be int, got {idx!r}"}
    pkt = ctx.get_packet(idx)
    if pkt is None:
        return {"error": f"packet {idx} not in capture"}
    out = {
        "index": pkt.index,
        "timestamp": pkt.timestamp,
        "length": pkt.length,
        "src_ip": pkt.src_ip, "src_port": pkt.src_port,
        "dst_ip": pkt.dst_ip, "dst_port": pkt.dst_port,
        "protocol": pkt.protocol,
        "tcp_flags": pkt.tcp_flags,
        "ttl": pkt.ttl,
        "payload_size": pkt.payload_size,
    }
    if pkt.payload:
        out["payload_preview"] = pkt.payload[:200].decode("latin-1", "replace")
    return out


# ---------------------------------------------------------------------------
# Tool 11: list_flows
# ---------------------------------------------------------------------------
def tool_list_flows(args: Dict[str, Any], ctx: ToolContext) -> Dict[str, Any]:
    items = []
    for i, f in enumerate(ctx.flows):
        items.append({
            "flow_id": i,
            "protocol": getattr(f, "protocol", "?"),
            "src": f"{getattr(f, 'src_ip', '?')}:{getattr(f, 'src_port', '?')}",
            "dst": f"{getattr(f, 'dst_ip', '?')}:{getattr(f, 'dst_port', '?')}",
            "packet_count": getattr(f, "packet_count", 0),
            "total_bytes": getattr(f, "total_bytes", 0),
        })
    return {"count": len(items), "flows": items[:200]}


# ---------------------------------------------------------------------------
# Tool 12: python_eval (sandbox) — Phase 6 escape hatch for novel
# forensic questions that don't have a dedicated tool.
# ---------------------------------------------------------------------------
# Runs a short Python snippet over a frozen, read-only namespace of
# {packets, flows, alerts, stats, pcap}. 5s wall-clock timeout; 50 MB
# RSS cap; no network / file / subprocess.
_PY_EVAL_TIMEOUT_SEC = 5.0
_PY_EVAL_MEM_CAP_BYTES = 50 * 1024 * 1024

# "L3" gate (2026-08-06): python_eval executes LLM-written code. It is
# therefore OFF by default and only advertised to the model when the
# analyst opts in (EASYSHARK_ALLOW_PYTHON_EVAL=1). Every execution is
# audit-logged to ~/.easyshark/python_eval.log for post-hoc review.
PYTHON_EVAL_ENABLED = os.environ.get("EASYSHARK_ALLOW_PYTHON_EVAL", "0") == "1"

_PY_EVAL_LOG_PATH = None


def _log_python_eval(code: str, result: Dict[str, Any],
                     latency_ms: float, ctx: ToolContext) -> None:
    """Append one JSONL audit row per python_eval execution (best-effort,
    never raises). The analyst can review exactly what code the model ran
    and what it returned."""
    global _PY_EVAL_LOG_PATH
    try:
        import time as _time
        from pathlib import Path
        if _PY_EVAL_LOG_PATH is None:
            _dir = Path.home() / ".easyshark"
            _dir.mkdir(parents=True, exist_ok=True)
            _PY_EVAL_LOG_PATH = _dir / "python_eval.log"
        pcap = getattr(ctx, "pcap_path", None)
        result_preview = ""
        if isinstance(result, dict):
            rv = result.get("result", None)
            if rv is None:
                rv = result.get("error", "")
            result_preview = str(rv)[:200]
        row = {
            "ts": _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
            "pcap": str(pcap) if pcap else None,
            "code_preview": code[:300],
            "result_preview": result_preview,
            "latency_ms": int(latency_ms * 1000),
            "error": bool(result.get("error")),
        }
        with open(str(_PY_EVAL_LOG_PATH), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, default=str) + "\n")
    except Exception:
        pass

# Strict allowlist of safe builtins. Anything outside this list is
# removed from __builtins__ before the snippet runs.
_PY_EVAL_SAFE_BUILTINS = {
    "abs": abs, "all": all, "any": any, "ascii": ascii, "bin": bin,
    "bool": bool, "bytearray": bytearray, "bytes": bytes,
    "callable": callable, "chr": chr, "dict": dict, "divmod": divmod,
    "enumerate": enumerate, "filter": filter, "float": float,
    "format": format, "frozenset": frozenset, "getattr": getattr,
    "hasattr": hasattr, "setattr": setattr, "delattr": delattr,
    "dir": dir, "hash": hash, "hex": hex,
    "id": id, "int": int, "isinstance": isinstance, "issubclass": issubclass,
    "iter": iter, "len": len, "list": list, "map": map, "max": max,
    "min": min, "next": next, "object": object, "oct": oct, "ord": ord,
    "pow": pow, "print": print, "range": range, "repr": repr,
    "reversed": reversed, "round": round, "set": set, "slice": slice,
    "sorted": sorted, "str": str, "sum": sum, "tuple": tuple,
    "type": type, "vars": vars, "zip": zip,
    # Exception classes so snippets can guard with try/except (observed:
    # LLM-written zipfile readers use `except Exception as e`).
    "Exception": Exception, "ValueError": ValueError, "TypeError": TypeError,
    "KeyError": KeyError, "IndexError": IndexError, "RuntimeError": RuntimeError,
    "NameError": NameError, "AttributeError": AttributeError,
    "BadZipFile": __import__("zipfile").BadZipFile,
}
# Lightweight pure-Python modules safe to expose (read-only).
import collections as _collections
import math as _math
import re as _re_mod
import statistics as _statistics
_PY_EVAL_SAFE_BUILTINS["Counter"] = _collections.Counter
_PY_EVAL_SAFE_BUILTINS["defaultdict"] = _collections.defaultdict
_PY_EVAL_SAFE_BUILTINS["math"] = _math
_PY_EVAL_SAFE_BUILTINS["re"] = _re_mod
_PY_EVAL_SAFE_BUILTINS["statistics"] = _statistics

# Names we strip from the namespace before exec() — prevents trivial
# escapes via attribute lookups. We intentionally ALLOW ``import X``
# for the safe modules exposed in the namespace (math, re, collections,
# statistics) — Python rewrites those into ``__import__("X")`` which
# we replace with a whitelist-resolving helper.
_PY_EVAL_BANLIST = (
    "open", "exit", "quit", "compile", "eval", "exec",
    "globals", "locals", "input", "help", "memoryview",
    "system", "popen", "spawn", "fork", "execfile",
    "subprocess", "socket", "urllib", "http", "httplib", "ftplib",
    "telnetlib", "smtplib", "poplib", "imaplib", "nntplib",
    "ssl", "select", "asyncore", "asynchat",
    "ctypes", "cffi", "fcntl", "pwd", "grp", "resource",
    "win32api", "win32com", "win32con", "win32event",
)
# Modules the snippet may `import X` for. We rewrite imports at exec
# time so the underlying __import__ call goes through us, not Python's
# stock builtin. zipfile + io are read-only in-memory ops (unzip a
# carved blob), no filesystem/network reach — required for reading
# fragmented docx text via python_eval.
_PY_EVAL_SAFE_MODULES = {"math", "re", "collections", "statistics",
                         "zipfile", "io"}


# ---------------------------------------------------------------------------
# Phase 15 — dissection-aware tools (read deterministic load-time dissection)
# ---------------------------------------------------------------------------
def _dissection_of(ctx: ToolContext, section: str) -> Dict[str, Any]:
    d = ctx.dissection or {}
    return d.get(section, {}) if isinstance(d, dict) else {}


def tool_get_http_requests(args: Dict[str, Any], ctx: ToolContext) -> Dict[str, Any]:
    """HTTP requests/responses extracted at load time (method, uri, host,
    UA, response code, body preview)."""
    http = _dissection_of(ctx, "http")
    reqs = http.get("requests", [])
    return {"count": len(reqs), "requests": reqs[:50]}


def tool_get_dns_queries(args: Dict[str, Any], ctx: ToolContext) -> Dict[str, Any]:
    """DNS queries/responses, NXDOMAINs and suspicious long labels."""
    dns = _dissection_of(ctx, "dns")
    qs = dns.get("queries", [])
    return {
        "query_count": len(qs),
        "queries": qs[:50],
        "nx_domains": (dns.get("nx_domains") or [])[:20],
        "suspicious_long_labels": (dns.get("suspicious_long_labels") or [])[:10],
    }


def tool_get_credentials(args: Dict[str, Any], ctx: ToolContext) -> Dict[str, Any]:
    """All credentials found: SMTP AUTH, HTTP Basic, IMAP/POP3, FTP."""
    out: List[Dict[str, Any]] = []
    for c in _dissection_of(ctx, "smtp").get("credentials", []) or []:
        out.append(c)
    for c in _dissection_of(ctx, "http").get("credentials", []) or []:
        out.append(c)
    for sec in ("imap", "pop3"):
        for c in _dissection_of(ctx, sec).get("credentials", []) or []:
            out.append(c)
    ftp = _dissection_of(ctx, "ftp")
    if ftp.get("username"):
        out.append({"protocol": "ftp", "username": ftp.get("username"),
                    "password": ftp.get("password")})
    return {"count": len(out), "credentials": out}


def tool_get_transferred_files(args: Dict[str, Any], ctx: ToolContext) -> Dict[str, Any]:
    """Files recovered from the capture: HTTP downloads, SMTP MIME
    attachments (decoded on demand), and carved blobs — with MD5s."""
    entries: List[Dict[str, Any]] = []
    for f in _dissection_of(ctx, "http").get("transferred_files", []) or []:
        entries.append(f)
    try:
        from ai.payload_analyzer import parse_smtp_attachments, extract_transferred_files_blobs
        for a in parse_smtp_attachments(ctx.packets):
            entries.append({"filename": a.get("filename"),
                            "size_bytes": a.get("size", len(a.get("data", b""))),
                            "md5": a.get("md5", _md5(a.get("data", b""))),
                            "protocol": "smtp"})
        for b in extract_transferred_files_blobs(ctx.packets):
            entries.append({"filename": b.get("filename"),
                            "size_bytes": len(b.get("data", b"")),
                            "md5": b.get("md5", _md5(b.get("data", b""))),
                            "protocol": "carved"})
    except Exception:
        pass
    seen = set()
    uniq: List[Dict[str, Any]] = []
    for e in entries:
        key = e.get("md5")
        if key and key in seen:
            continue
        if key:
            seen.add(key)
        # Never ship raw payload bytes to the LLM — metadata only.
        e.pop("payload_b64", None)
        data = e.pop("data", None)
        # Give the model the docx text so it can correlate the carved file
        # to an SMTP/AIM transfer name (evidence01 'recipe.docx' case).
        if data and str(e.get("filename", "")).endswith(("docx", "zip_docx")):
            e["text_preview"] = _peek_docx(data)[:200]
        uniq.append(e)
    uniq.sort(key=lambda e: -(e.get("size_bytes") or 0))
    return {"count": len(uniq), "files": uniq[:15]}


def tool_get_tls_sessions(args: Dict[str, Any], ctx: ToolContext) -> Dict[str, Any]:
    """TLS handshakes with SNI, version and cipher suite."""
    tls = _dissection_of(ctx, "tls")
    hs = tls.get("handshakes", [])
    return {"count": len(hs), "handshakes": hs[:50]}


def tool_get_arp_table(args: Dict[str, Any], ctx: ToolContext) -> Dict[str, Any]:
    """ARP requests/replies and the observed MAC->IP mapping."""
    arp = _dissection_of(ctx, "arp")
    return {
        "request_count": len(arp.get("requests", [])),
        "requests": arp.get("requests", [])[:30],
        "gratuitous": (arp.get("gratuitous") or [])[:10],
        "mac_ip_map": arp.get("mac_ip_map", {}),
    }


def tool_get_smtp_sessions(args: Dict[str, Any], ctx: ToolContext) -> Dict[str, Any]:
    """SMTP sessions: sender/recipient, subject, AUTH credentials, body."""
    smtp = _dissection_of(ctx, "smtp")
    sess = []
    for s in smtp.get("sessions", []) or []:
        sess.append({k: v for k, v in s.items() if not k.startswith("_")})
    return {"count": len(sess), "sessions": sess[:20]}


def tool_get_protocol_summary(args: Dict[str, Any], ctx: ToolContext) -> Dict[str, Any]:
    """What the deterministic dissector found per protocol in this capture.
    Always available — the top-level answer to 'what is in this pcap?'."""
    d = ctx.dissection or {}
    summary: Dict[str, Any] = {}
    if isinstance(d, dict):
        summary = {
            "http_requests": len(d.get("http", {}).get("requests", [])),
            "dns_queries": len(d.get("dns", {}).get("queries", [])),
            "dns_nxdomains": len(d.get("dns", {}).get("nx_domains", [])),
            "smtp_sessions": len(d.get("smtp", {}).get("sessions", [])),
            "tls_handshakes": len(d.get("tls", {}).get("handshakes", [])),
            "dhcp_leases": len(d.get("dhcp", {}).get("leases", [])),
            "ssh_sessions": len(d.get("ssh", {}).get("sessions", [])),
            "arp_requests": len(d.get("arp", {}).get("requests", [])),
            "icmp_echo_pairs": len(d.get("icmp", {}).get("echo_pairs", [])),
            "unknown_ports": d.get("raw", {}).get("unknown_ports", {}),
            "skipped_packets": d.get("skipped", 0),
        }
    return summary


def tool_get_dhcp_leases(args: Dict[str, Any], ctx: ToolContext) -> Dict[str, Any]:
    """DHCP offers/acks: assigned IP, MAC, hostname, vendor class."""
    dhcp = _dissection_of(ctx, "dhcp")
    leases = dhcp.get("leases", [])
    return {"count": len(leases), "leases": leases[:30]}


def tool_get_ssh_sessions(args: Dict[str, Any], ctx: ToolContext) -> Dict[str, Any]:
    """SSH sessions (identified by banner exchange)."""
    ssh = _dissection_of(ctx, "ssh")
    sess = ssh.get("sessions", [])
    return {"count": len(sess), "sessions": sess[:20]}


# --------------------------------------------------------------------------- #
# Phase 15 — triage-gated tool visibility.
#
# Each dissection-aware tool is advertised to the LLM ONLY when the capture
# actually contains the relevant protocol (reduces prompt tokens AND prevents
# the model from inventing evidence for absent protocols). Tools without an
# entry here are always available. The filter is applied in
# llm_client.query_with_tools when context.triage is set; when it is not
# (investigator, dag, sandbox paths) the full schema list is kept.
# --------------------------------------------------------------------------- #
def _dissection_gate_passes(name: str,
                            triage: Optional[Dict[str, Any]],
                            dissection: Optional[Dict[str, Any]]) -> bool:
    if name == "get_transferred_files":
        # Files may come from dissection (HTTP), SMTP MIME, or the carve
        # path (docx/other blobs). Any of those makes the tool useful.
        if dissection and dissection.get("http", {}).get("transferred_files"):
            return True
        if triage and any(triage.get(k) for k in ("http", "smtp", "docx_carved")):
            return True
        return False
    if not dissection:
        return True  # no dissection data -> don't hide tools
    if name == "get_dns_queries":
        return bool(dissection.get("dns", {}).get("queries"))
    if name == "get_credentials":
        for sec in ("smtp", "http", "imap", "pop3"):
            if dissection.get(sec, {}).get("credentials"):
                return True
        return bool(dissection.get("ftp", {}).get("username"))
    if name == "get_arp_table":
        return bool(dissection.get("arp", {}).get("requests"))
    if name == "get_dhcp_leases":
        return bool(dissection.get("dhcp", {}).get("leases"))
    if name == "get_ssh_sessions":
        return bool(dissection.get("ssh", {}).get("sessions"))
    return True


def filter_tool_schemas(triage: Optional[Dict[str, Any]],
                        dissection: Optional[Dict[str, Any]],
                        schemas: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """Return the subset of tool schemas the capture supports.

    Protocol-gated tools are dropped when the corresponding triage flag is
    falsy or (for dissection-only signals) when the dissector found nothing.
    Tools not in the gate map are always kept. When ``triage`` is None, the
    full list is returned (backward compatible for non-explainer callers).
    """
    full = list(schemas if schemas is not None else TOOL_SCHEMAS)
    if not triage:
        return full
    keep = []
    for schema in full:
        fn = (schema.get("function") or {})
        name = fn.get("name")
        # L3 gate — python_eval runs LLM-written code. Only advertised when
        # the analyst opts in (EASYSHARK_ALLOW_PYTHON_EVAL=1). create_tool
        # mints NEW sandboxed tools, so it is gated identically.
        if name in ("python_eval", "create_tool") and not PYTHON_EVAL_ENABLED:
            continue
        if name in _TOOL_TRIAGE_KEYS:
            flag = _TOOL_TRIAGE_KEYS[name]
            if flag and not triage.get(flag):
                continue
            if not _dissection_gate_passes(name, triage, dissection):
                continue
        keep.append(schema)
    return keep


# Tools listed here are advertised only when their protocol is present.
# key -> required triage flag (None = gate via dissection only).
_TOOL_TRIAGE_KEYS: Dict[str, Optional[str]] = {
    "get_http_requests":     "http",
    "get_dns_queries":       None,
    "get_credentials":       None,
    "get_transferred_files": None,
    "get_tls_sessions":      "tls",
    "get_arp_table":         None,
    "get_smtp_sessions":     "smtp",
    "get_dhcp_leases":       None,
    "get_ssh_sessions":      None,
    # get_protocol_summary is always available (no gate).
}


def _safe_import(name, *args, **kwargs):
    """Replacement for __import__ that only resolves whitelisted modules."""
    if name in _PY_EVAL_SAFE_MODULES:
        return __import__(name, *args, **kwargs)
    raise ImportError(
        f"python_eval: '{name}' is not in the safe-module whitelist "
        f"(allowed: {sorted(_PY_EVAL_SAFE_MODULES)})"
    )


def _build_py_eval_globals(ctx: ToolContext) -> Dict[str, Any]:
    """Build the frozen namespace for a python_eval call. Read-only —
    the model can't mutate the packets list (we hand it a shallow
    view; packets themselves are frozen dataclasses anyway)."""
    pcap_path = getattr(ctx, "pcap_path", None)
    frozen: Dict[str, Any] = {
        "__builtins__": {**_PY_EVAL_SAFE_BUILTINS,
                          "__import__": _safe_import},
        "packets": list(getattr(ctx, "packets", []) or []),
        "flows":   list(getattr(ctx, "flows",   []) or []),
        "alerts":  list(getattr(ctx, "alerts",  []) or []),
    }
    # Add stats via the stats_engine's summary() — already a plain dict.
    se = getattr(ctx, "stats_engine", None)
    if se is not None and hasattr(se, "summary"):
        try:
            frozen["stats"] = se.summary()
        except Exception as exc:
            frozen["stats"] = {"error": f"stats.summary() raised: {exc}"}
    else:
        frozen["stats"] = {}
    if pcap_path:
        frozen["pcap"] = str(pcap_path)
    return frozen


class _PyEvalTimeout(Exception):
    pass


def _py_eval_alarm(_signum, _frame):
    raise _PyEvalTimeout("python_eval exceeded wall-clock timeout")


def tool_python_eval(args: Dict[str, Any], ctx: ToolContext) -> Dict[str, Any]:
    """Tool-calling wrapper around run_python_eval. Kept in the registry
    for the (opt-in) LLM loop; the sandbox itself is run_python_eval."""
    code = args.get("code", "")
    if not isinstance(code, str) or not code.strip():
        return {"error": "missing 'code' argument (must be a non-empty Python snippet)"}
    return run_python_eval(code, ctx)


def run_python_eval(code: str, ctx: ToolContext,
                    extra_globals: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Run a short Python snippet over a read-only namespace of
    {packets, flows, alerts, stats, pcap}. 5s wall-clock timeout;
    50 MB RSS cap; no network / file / subprocess.

    Use this when the question is novel and no dedicated tool fits
    (e.g. "How many DNS queries had entropy > 3.5 bits?"). The code
    MUST set a local variable named ``result`` (string or number) —
    that value is what gets returned to the LLM.

    ``extra_globals`` (optional) merges extra names into the frozen
    namespace — used by ``create_tool`` so an LLM-written tool body can
    read its call arguments from a plain ``args`` dict.

    Audit: every run is appended to ~/.easyshark/python_eval.log.
    """
    if not isinstance(code, str) or not code.strip():
        return {"error": "missing 'code' argument (must be a non-empty Python snippet)"}
    if len(code) > 4000:
        return {"error": f"code too long ({len(code)} chars; max 4000)"}

    # Reject obvious sandbox-escape attempts before either execution mode.
    for bad in _PY_EVAL_BANLIST:
        if re.search(rf"\b{re.escape(bad)}\b", code):
            return {"error": f"python_eval: '{bad}' is not allowed in the sandbox"}

    if os.environ.get("EASYSHARK_PROCESS_SANDBOX", "0") == "1":
        from ai.sandbox import run as run_isolated
        se = getattr(ctx, "stats_engine", None)
        variables = {
            "packets": list(getattr(ctx, "packets", []) or []),
            "flows": list(getattr(ctx, "flows", []) or []),
            "alerts": list(getattr(ctx, "alerts", []) or []),
            "stats": se.summary() if se is not None and hasattr(se, "summary") else {},
            "pcap": getattr(ctx, "pcap_path", None),
        }
        if extra_globals:
            variables.update(extra_globals)
        _eval_start = _perf_counter()
        result = run_isolated(code, variables, timeout=_PY_EVAL_TIMEOUT_SEC)
        _log_python_eval(code, result,
                         (_perf_counter() - _eval_start) * 1000, ctx)
        return result

    start = _perf_counter()

    frozen = _build_py_eval_globals(ctx)
    if extra_globals:
        for _k, _v in extra_globals.items():
            if isinstance(_k, str) and _k.isidentifier() and not _k.startswith("__"):
                frozen[_k] = _v

    use_alarm = sys.platform != "win32"
    previous_handler = None
    if use_alarm:
        try:
            previous_handler = signal.signal(
                signal.SIGALRM, _py_eval_alarm)
            signal.setitimer(signal.ITIMER_REAL, _PY_EVAL_TIMEOUT_SEC)
        except (ValueError, OSError):
            use_alarm = False

    timer = None
    timed_out = [False]
    if not use_alarm:
        def _raise():
            timed_out[0] = True
        timer = threading.Timer(_PY_EVAL_TIMEOUT_SEC, _raise)
        timer.daemon = True
        timer.start()

    try:
        # 50 MB RSS cap (best-effort; POSIX-only).
        # IMPORTANT: only lower the SOFT limit; leave the hard limit alone.
        # Lowering the hard limit would make the subsequent restore back to
        # the original value fail with EPERM (raising a hard limit needs
        # CAP_SYS_RESOURCE), leaking a 50 MB address-space cap into the
        # whole shell process.
        prev_as_limit = None
        if sys.platform != "win32":
            try:
                import resource as _res
                prev_as_limit = _res.getrlimit(_res.RLIMIT_AS)
                # The 50 MB budget is a per-snippet ALLOWANCE, not an absolute
                # cap: the host shell (scapy + flow engine + this module) is
                # already hundreds of MB of virtual address space, so setting
                # RLIMIT_AS to a flat 50 MB makes every real allocation in the
                # snippet fail immediately (observed on the docx-unzip path:
                # `zipfile.ZipFile` raised MemoryError). Measure current VMSize
                # and grant the snippet its budget ON TOP of that.
                _budget = _PY_EVAL_MEM_CAP_BYTES
                try:
                    with open("/proc/self/statm") as _statm:
                        _vmsize_pages = int(_statm.read().split()[0])
                    _cur_vm = (_vmsize_pages * os.sysconf("SC_PAGE_SIZE"))
                    _budget += _cur_vm
                except (OSError, ValueError):
                    pass
                new_soft = (_budget
                            if prev_as_limit[1] == _res.RLIM_INFINITY
                            else min(_budget, prev_as_limit[1]))
                _res.setrlimit(_res.RLIMIT_AS,
                               (new_soft, prev_as_limit[1]))
            except (ImportError, ValueError, OSError):
                prev_as_limit = None
        exec(compile(code, "<python_eval>", "exec"), frozen, frozen)
        result = frozen.get("result", None)
    except _PyEvalTimeout as exc:
        result = {"error": f"python_eval timeout: {exc}"}
    except MemoryError:
        result = {"error": "python_eval exceeded 50 MB memory cap"}
    except SyntaxError as exc:
        result = {"error": f"python_eval syntax error: {exc}"}
    except Exception as exc:
        result = {"error": f"python_eval raised {type(exc).__name__}: {exc}"}
    finally:
        # Restore the original memory limit so subsequent python_eval calls
        # and the rest of the shell aren't stuck under the 50 MB cap.
        if prev_as_limit is not None:
            try:
                import resource as _res
                _res.setrlimit(_res.RLIMIT_AS, prev_as_limit)
            except Exception:
                pass
        if use_alarm and previous_handler is not None:
            try:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, previous_handler)
            except Exception:
                pass
        if timer is not None:
            timer.cancel()

    if timed_out[0]:
        result = {"error": f"python_eval timeout after {_PY_EVAL_TIMEOUT_SEC}s"}

    out = result if isinstance(result, dict) else {
        "result": result if not callable(result) else repr(result),
        "type":   type(result).__name__,
    }
    try:
        _log_python_eval(code, out, _perf_counter() - start, ctx)
    except Exception:
        pass
    return out


# ---------------------------------------------------------------------------
# Tool 13b: create_tool — LLM-driven sandboxed tool creation ("L4").
#
# When no fixed tool (or compute_packets / python_eval snippet) can express
# the computation, the model may define a NEW named tool at runtime:
#
#     create_tool({
#         "name": "count_http_methods",
#         "description": "Count HTTP methods observed across payloads",
#         "parameters": {"type": "object",
#                        "properties": {"pattern": {"type": "string"}}},
#         "code": "from collections import Counter\n"
#                 "result = dict(Counter(...))"
#     })
#
# The body runs in the SAME python_eval sandbox (5s timeout, 50 MB cap,
# banlist, audit log) with the tool's call ``args`` injected as a plain
# dict named ``args``; it must set ``result``. On success the tool is
# registered via register_tool() and becomes callable by name in later
# loop steps (the loop refreshes its schema list each step).
# ---------------------------------------------------------------------------

# name -> {"description", "parameters", "code"}
_CREATED_TOOLS: Dict[str, Dict[str, Any]] = {}
_MAX_CREATED_TOOLS = 8


def is_sandboxed_tool(name: str) -> bool:
    """True when ``name`` is python_eval or an LLM-created tool whose
    executor runs sandboxed Python (must be excluded from the parallel
    executor pool — see llm_client query_with_tools)."""
    if name == "python_eval":
        return True
    return name in _CREATED_TOOLS


def list_created_tools() -> List[str]:
    return sorted(_CREATED_TOOLS)


def create_runtime_tool(name: str,
                        description: str,
                        parameters: Dict[str, Any],
                        code: str,
                        ctx: ToolContext) -> Dict[str, Any]:
    """Validate, dry-run and register an LLM-written sandboxed tool.

    Returns {"created": name, ...} on success or {"error": ...}. The body
    is executed once in the sandbox with an empty args dict as a dry-run
    proof-of-life before the tool is registered.
    """
    if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_]{1,63}", name):
        return {"error": "create_tool: 'name' must be a lowercase "
                         "snake_case identifier (2-64 chars)"}
    if name in TOOL_EXECUTORS:
        return {"error": f"create_tool: '{name}' already exists"}
    if len(_CREATED_TOOLS) >= _MAX_CREATED_TOOLS:
        return {"error": f"create_tool: limit of {_MAX_CREATED_TOOLS} "
                         "created tools reached"}
    if not isinstance(description, str) or not description.strip():
        return {"error": "create_tool: 'description' is required"}
    if not isinstance(code, str) or not code.strip():
        return {"error": "create_tool: 'code' is required"}
    if len(code) > 4000:
        return {"error": f"create_tool: 'code' too long "
                         f"({len(code)} chars; max 4000)"}
    if not isinstance(parameters, dict) or not isinstance(
            parameters.get("properties", {}), dict):
        return {"error": "create_tool: 'parameters' must be an object "
                         "schema with a 'properties' object"}

    # Banlist check against the source before any execution.
    for bad in _PY_EVAL_BANLIST:
        if re.search(rf"\b{re.escape(bad)}\b", code):
            return {"error": f"create_tool: '{bad}' is not allowed in the sandbox"}

    # Dry-run proof-of-life: run the body once with empty args.
    probe = run_python_eval(code, ctx, extra_globals={"args": {}})
    if isinstance(probe, dict) and probe.get("error"):
        return {"error": f"create_tool: dry-run failed: {probe['error']}"}

    def _executor(args: Dict[str, Any], tool_ctx: ToolContext) -> Dict[str, Any]:
        return run_python_eval(code, tool_ctx, extra_globals={"args": args or {}})

    schema = {
        "type": "function",
        "function": {
            "name": name,
            "description": description[:500],
            "parameters": parameters,
        },
    }
    register_tool(name, schema["function"], _executor)
    _CREATED_TOOLS[name] = {
        "description": description,
        "parameters": parameters,
        "code": code,
    }
    logger.info("create_tool: registered sandboxed tool '%s'", name)
    return {"created": name,
            "created_tools": sorted(_CREATED_TOOLS),
            "hint": f"Now call {name} with the arguments you need."}


def tool_create_tool(args: Dict[str, Any], ctx: ToolContext) -> Dict[str, Any]:
    """Tool-calling wrapper around create_runtime_tool (gated with
    python_eval behind EASYSHARK_ALLOW_PYTHON_EVAL=1)."""
    return create_runtime_tool(
        name=args.get("name", ""),
        description=args.get("description", ""),
        parameters=args.get("parameters", {}) or {},
        code=args.get("code", ""),
        ctx=ctx,
    )


# ---------------------------------------------------------------------------
# Tool 14: compute_packets (structured query DSL — "L2" 2026-08-06).
# The safer middle layer between the fixed tools and free-form python_eval:
# group / aggregate / filter over PacketMetadata with arguments only — no
# code, no eval. Fully deterministic and sandboxed by construction.
# ---------------------------------------------------------------------------
_COMPUTE_FIELDS = {
    "src_ip": "src_ip", "dst_ip": "dst_ip", "protocol": "protocol",
    "src_port": "src_port", "dst_port": "dst_port",
    "src_mac": "src_mac", "dst_mac": "dst_mac",
    "tcp_flags": "tcp_flags", "ip_proto": "ip_proto",
    "length": "length", "payload_size": "payload_size",
    "ttl": "ttl", "timestamp": "timestamp",
}
_NUMERIC_FIELDS = {"length", "payload_size", "ttl", "timestamp",
                   "src_port", "dst_port", "ip_proto"}


def _compute_where(expr: str):
    """Parse a tiny, safe filter DSL and return a packet->bool predicate.

    Grammar: terms joined by && / and (AND) and || / or (OR).
    term := <field> <op> <value>   with op in == != >= <= > <
    Values are integers, floats, or single/double-quoted strings. Field
    names are validated against _COMPUTE_FIELDS — unknown fields raise
    ValueError. No eval() is ever used.
    """
    if not expr or not expr.strip():
        return lambda p: True

    def parse_term(term):
        term = term.strip()
        m = re.match(r"^(\w+)\s*(==|!=|>=|<=|>|<)\s*(.+)$", term)
        if not m:
            raise ValueError(f"bad filter term: {term!r}")
        field, op, raw = m.group(1), m.group(2), m.group(3).strip()
        if field not in _COMPUTE_FIELDS:
            raise ValueError(
                f"unknown filter field {field!r}; allowed: "
                f"{sorted(_COMPUTE_FIELDS)}")
        if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ("'", '"'):
            value = raw[1:-1]
        elif re.fullmatch(r"[+-]?\d+", raw):
            value = int(raw)
        elif re.fullmatch(r"[+-]?\d+(\.\d+)?([eE][+-]?\d+)?", raw):
            value = float(raw)
        else:
            raise ValueError(
                f"bad filter value {raw!r} for field {field!r}; "
                f"use a quoted string or a number")
        attr = _COMPUTE_FIELDS[field]

        def pred(p, _op=op, _attr=attr, _value=value):
            actual = getattr(p, _attr, None)
            if actual is None:
                return False
            if isinstance(_value, str):
                actual = str(actual)
            elif isinstance(_value, float):
                try:
                    actual = float(actual)
                except (TypeError, ValueError):
                    return False
            else:
                try:
                    actual = int(actual)
                except (TypeError, ValueError):
                    return False
            if _op == "==":
                return actual == _value
            if _op == "!=":
                return actual != _value
            if _op == ">":
                return actual > _value
            if _op == ">=":
                return actual >= _value
            if _op == "<":
                return actual < _value
            return actual <= _value

        return pred

    or_parts = re.split(r"\s*\|\|\s*|\s+or\s+", expr)
    or_preds = []
    for part in or_parts:
        and_terms = re.split(r"\s*&&\s*|\s+and\s+", part)
        and_preds = [parse_term(t) for t in and_terms if t.strip()]
        or_preds.append(lambda p, ands=and_preds: all(f(p) for f in ands))

    def combined(p):
        return any(f(p) for f in or_preds)

    return combined


def _aggregate_values(group, aggregate: str, on: Optional[str]):
    if aggregate == "count":
        return len(group)
    if not on:
        raise ValueError(f"{aggregate} requires an 'on' field")
    if aggregate == "count_distinct":
        return len({getattr(p, _COMPUTE_FIELDS[on]) for p in group
                    if getattr(p, _COMPUTE_FIELDS[on]) is not None})
    vals = [getattr(p, _COMPUTE_FIELDS[on]) for p in group]
    vals = [v for v in vals if isinstance(v, (int, float))]
    if not vals:
        return None
    if aggregate == "sum":
        return sum(vals)
    if aggregate == "avg":
        return round(sum(vals) / len(vals), 4)
    if aggregate == "min":
        return min(vals)
    return max(vals)


def tool_compute_packets(args: Dict[str, Any], ctx: ToolContext) -> Dict[str, Any]:
    """Structured aggregation over PacketMetadata.

    Supports count / count_distinct / sum / avg / min / max, optionally
    grouped by a packet field and filtered by a small where-clause. No
    code is executed — the DSL is parsed and validated before any work.
    """
    group_by = args.get("group_by") or ""
    aggregate = (args.get("aggregate") or "count").lower()
    on = args.get("on") or ""
    where = args.get("where") or ""
    try:
        limit = max(1, min(int(args.get("limit") or 10), 50))
    except (TypeError, ValueError):
        limit = 10

    if group_by and group_by not in _COMPUTE_FIELDS:
        return {"error": f"unknown group_by field {group_by!r}; "
                         f"allowed: {sorted(_COMPUTE_FIELDS)}"}
    if on and on not in _COMPUTE_FIELDS:
        return {"error": f"unknown 'on' field {on!r}; allowed: "
                         f"{sorted(_COMPUTE_FIELDS)}"}
    valid_aggs = {"count", "count_distinct", "sum", "avg", "min", "max"}
    if aggregate not in valid_aggs:
        return {"error": f"unknown aggregate {aggregate!r}; allowed: "
                         f"{sorted(valid_aggs)}"}
    if aggregate in ("sum", "avg", "min", "max") and on and on not in _NUMERIC_FIELDS:
        return {"error": f"aggregate {aggregate} needs a numeric 'on' field; "
                         f"{on!r} is not numeric"}
    try:
        pred = _compute_where(where)
    except ValueError as exc:
        return {"error": f"bad 'where' clause: {exc}"}

    matched = [p for p in ctx.packets if pred(p)]

    if not group_by:
        try:
            result = _aggregate_values(matched, aggregate, on)
        except ValueError as exc:
            return {"error": str(exc)}
        return {"matched": len(matched), "result": result,
                "type": type(result).__name__ if result is not None else "none"}

    buckets: Dict[Any, List[Any]] = {}
    for p in matched:
        key = getattr(p, _COMPUTE_FIELDS[group_by])
        buckets.setdefault(key, []).append(p)
    rows = []
    for key, group in buckets.items():
        try:
            value = _aggregate_values(group, aggregate, on)
        except ValueError as exc:
            return {"error": str(exc)}
        rows.append({"key": key, "value": value})
    # Sort by value descending (None last), stable.
    rows.sort(key=lambda r: (
        1 if r["value"] is None else 0,
        -(r["value"] if isinstance(r["value"], (int, float)) else 0),
        str(r["key"])))
    return {"matched": len(matched), "group_by": group_by,
            "aggregate": aggregate, "on": on, "rows": rows[:limit]}


# ---------------------------------------------------------------------------
# Registry: schema + executor
# ---------------------------------------------------------------------------
TOOL_EXECUTORS: Dict[str, Callable[[Dict[str, Any], ToolContext], Dict[str, Any]]] = {
    "get_statistics":       tool_get_statistics,
    "get_alerts":           tool_get_alerts,
    "apply_display_filter": tool_apply_display_filter,
    "search_payloads":      tool_search_payloads,
    "extract_strings":      tool_extract_strings,
    "extract_files":        tool_extract_files,
    "follow_stream":        tool_follow_stream,
    "get_smtp_credentials": tool_get_smtp_credentials,
    "get_email_attachments": tool_get_email_attachments,
    "get_packet_detail":    tool_get_packet_detail,
    "list_flows":           tool_list_flows,
    "python_eval":          tool_python_eval,
    "create_tool":          tool_create_tool,
    "compute_packets":      tool_compute_packets,
    "extract_embedded_media": tool_extract_embedded_media,
    # Phase 15 — dissection-aware tools.
    "get_http_requests":    tool_get_http_requests,
    "get_dns_queries":      tool_get_dns_queries,
    "get_credentials":      tool_get_credentials,
    "get_transferred_files": tool_get_transferred_files,
    "get_tls_sessions":     tool_get_tls_sessions,
    "get_arp_table":        tool_get_arp_table,
    "get_smtp_sessions":    tool_get_smtp_sessions,
    "get_protocol_summary": tool_get_protocol_summary,
    "get_dhcp_leases":      tool_get_dhcp_leases,
    "get_ssh_sessions":     tool_get_ssh_sessions,
}


TOOL_SCHEMAS: List[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "get_statistics",
            "description": (
                "Return total packet/flow/alert counts plus top protocols, IPs, "
                "and ports. Use this FIRST when you need a high-level overview of "
                "what is in the capture. "
                "Examples:\n"
                "  -> get_statistics()\n"
                "  -> 'how many packets total?' -> get_statistics()\n"
                "  -> 'what protocols are present?' -> get_statistics()"
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_alerts",
            "description": (
                "List triggered alerts (rule, severity, message). Use AFTER "
                "get_statistics if you want to know what was flagged. "
                "Examples:\n"
                "  -> get_alerts()\n"
                "  -> 'are there any port scan alerts?' -> get_alerts()\n"
                "  -> 'what triggered the beaconing alert?' -> get_alerts()"
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "apply_display_filter",
            "description": (
                "Filter packets by a Wireshark-like display filter and return "
                "matching packet indices. Examples:\n"
                "  -> apply_display_filter({\"filter\": \"ip.addr == 192.168.1.158\"})\n"
                "  -> apply_display_filter({\"filter\": \"tcp.port == 443\"})\n"
                "  -> apply_display_filter({\"filter\": \"protocol == TCP and dst_port == 80\"})\n"
                "Use this when you need a packet-list subset (e.g. 'all TCP to "
                "port 80'). NOT for payload content — use search_payloads."
            ),
            "parameters": {
                "type": "object",
                "properties": {"filter": {"type": "string",
                                           "description": "Wireshark display filter expression."}},
                "required": ["filter"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_payloads",
            "description": (
                "Regex search over TCP/UDP payload bytes. The 'regex' argument "
                "MUST be a Python regex string (NOT a Wireshark display filter). "
                "ignore_case defaults to true; pass a boolean (true/false), NOT "
                "'true'/'false' strings. "
                "Examples:\n"
                "  -> search_payloads({\"regex\": \"secret|recipe|confidential\"})\n"
                "  -> search_payloads({\"regex\": \"sneakyg33k\"})\n"
                "  -> search_payloads({\"regex\": \"\\\\.docx\"})"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "regex": {"type": "string",
                              "description": "Python regex, e.g. 'username|user_id' or 'recipe\\.docx'."},
                    "ignore_case": {"type": "boolean", "default": True,
                                     "description": "Pass a boolean (true/false), not a string."},
                },
                "required": ["regex"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "extract_strings",
            "description": (
                "Pull printable ASCII strings from TCP/UDP payloads. min_length "
                "defaults to 6. Use for usernames, chat messages, URLs, file "
                "names — anything embedded as plaintext. "
                "Examples:\n"
                "  -> extract_strings()\n"
                "  -> extract_strings({\"min_length\": 10})\n"
                "  -> 'find AIM screen names' -> extract_strings({\"min_length\": 5})"
            ),
            "parameters": {
                "type": "object",
                "properties": {"min_length": {"type": "integer", "default": 6}},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "extract_files",
            "description": (
                "Carve files from TCP payloads by magic-byte detection. "
                "Returns format, size, md5 per file; for .docx blobs also a "
                "text_preview (already-parsed document text). "
                "Examples:\n"
                "  -> extract_files()\n"
                "  -> extract_files({\"min_size\": 1024})\n"
                "  -> 'what files were transferred?' -> extract_files()\n"
                "  -> 'find the docx' -> extract_files({\"min_size\": 4096})"
            ),
            "parameters": {
                "type": "object",
                "properties": {"min_size": {"type": "integer", "default": 64}},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "follow_stream",
            "description": (
                "Return the reassembled ASCII stream for a flow. flow_id is "
                "an INTEGER index from list_flows (NOT a fabricated number). "
                "If you do not know the flow_id, call list_flows FIRST. "
                "Examples:\n"
                "  -> follow_stream({\"flow_id\": 0})\n"
                "  -> follow_stream({\"flow_id\": 3})\n"
                "Step 1: list_flows() -> Step 2: follow_stream({\"flow_id\": <from step 1>})"
            ),
            "parameters": {
                "type": "object",
                "properties": {"flow_id": {"type": "integer",
                                           "description": "Integer flow index from list_flows()."}},
                "required": ["flow_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_smtp_credentials",
            "description": (
                "Walk all TCP streams and decode SMTP AUTH LOGIN / AUTH PLAIN "
                "exchanges. Returns user, password, method, flow. "
                "Examples:\n"
                "  -> get_smtp_credentials()\n"
                "  -> 'what SMTP creds were used?' -> get_smtp_credentials()\n"
                "  -> 'who logged in to send mail?' -> get_smtp_credentials()"
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_email_attachments",
            "description": (
                "Decode MIME parts in SMTP DATA payloads; returns attachment "
                "metadata (filename, size, md5) plus text preview for txt / "
                "html / xml / docx parts and embedded-media MD5s inside docx. "
                "Also returns the SMTP envelope (MAIL FROM / RCPT TO) per flow. "
                "Examples:\n"
                "  -> get_email_attachments()\n"
                "  -> 'what was the email attachment?' -> get_email_attachments()\n"
                "  -> 'recipient of the docx email?' -> get_email_attachments()"
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "extract_embedded_media",
            "description": (
                "Extract embedded media files (word/media/*) from a .docx "
                "email attachment and SAVE them to a host path the analyst "
                "chooses. Deterministic host-side capability — the docx bytes "
                "are re-carved from the capture and unzipped; each media file "
                "is written to output_dir. Use ONLY when the analyst asks to "
                "save/extract the image (or embedded file) from a docx to a "
                "path. Output is the saved filenames, md5s and full paths.\n"
                "Examples:\n"
                "  -> extract_embedded_media({\"output_dir\": \"/tmp/extracted\"})\n"
                "  -> 'extract the image from the docx to /mnt/d/output/' "
                "    -> extract_embedded_media({\"output_dir\": \"/mnt/d/output\"})"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "output_dir": {"type": "string",
                                   "description": "Absolute host path to save "
                                                  "the extracted media into."},
                    "output_prefix": {"type": "string",
                                      "description": "Optional filename prefix."},
                },
                "required": ["output_dir"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_packet_detail",
            "description": (
                "Return full metadata for a single packet by index. "
                "Examples:\n"
                "  -> get_packet_detail({\"index\": 0})\n"
                "  -> get_packet_detail({\"index\": 42})\n"
                "Use AFTER apply_display_filter / search_payloads to drill "
                "down on a specific hit."
            ),
            "parameters": {
                "type": "object",
                "properties": {"index": {"type": "integer",
                                          "description": "0-based packet index."}},
                "required": ["index"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_flows",
            "description": (
                "List active TCP/UDP flows with packet counts and byte totals. "
                "Returns up to 200 flows, each with a flow_id you can pass to "
                "follow_stream. Examples:\n"
                "  -> list_flows()\n"
                "  -> 'what flows are present?' -> list_flows()\n"
                "  -> 'biggest flows by bytes?' -> list_flows()"
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "compute_packets",
            "description": (
                "Structured aggregation over packet metadata — count, "
                "count_distinct, sum, avg, min, max — optionally grouped by "
                "a field and filtered by a small where-clause. No code is "
                "executed; the DSL is parsed and validated safely. "
                "group_by/on fields: src_ip, dst_ip, protocol, src_port, "
                "dst_port, src_mac, dst_mac, tcp_flags, ip_proto, length, "
                "payload_size, ttl, timestamp. "
                "where: terms like field==value or field>=123 joined by && "
                "(and) and || (or); string values in single/double quotes.\n"
                "Examples:\n"
                "  -> compute_packets({\"group_by\": \"protocol\", "
                "\"aggregate\": \"count\"})\n"
                "  -> 'how many packets to port 443 by 192.168.1.158?' -> "
                "compute_packets({\"aggregate\": \"count\", \"where\": "
                "\"dst_port == 443 && src_ip == '192.168.1.158'\"})\n"
                "  -> 'how many distinct dst IPs?' -> compute_packets({"
                "\"aggregate\": \"count_distinct\", \"on\": \"dst_ip\"})\n"
                "  -> 'avg packet length per protocol?' -> compute_packets({"
                "\"group_by\": \"protocol\", \"aggregate\": \"avg\", "
                "\"on\": \"length\"})\n"
                "  -> 'total bytes per dst port for TCP' -> compute_packets({"
                "\"group_by\": \"dst_port\", \"aggregate\": \"sum\", "
                "\"on\": \"length\", \"where\": \"protocol == 'TCP'\"})"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "group_by": {"type": "string",
                                 "description": "Field to bucket results by "
                                                "(optional; omit for a single "
                                                "aggregate value)"},
                    "aggregate": {"type": "string",
                                  "enum": ["count", "count_distinct", "sum",
                                           "avg", "min", "max"],
                                  "description": "Aggregation to apply. "
                                                 "Default: count."},
                    "on": {"type": "string",
                           "description": "Field to aggregate over "
                                          "(required for count_distinct/sum/"
                                          "avg/min/max)"},
                    "where": {"type": "string",
                              "description": "Optional filter, e.g. "
                                             "\"dst_port == 443 && "
                                             "protocol == 'TCP'\""},
                    "limit": {"type": "integer",
                              "description": "Max rows to return (1-50, "
                                             "default 10)"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "python_eval",
            "description": (
                "Run a short Python snippet over a frozen, read-only context "
                "of {packets, flows, alerts, stats, pcap}. 5-second wall-clock "
                "timeout; 50 MB RSS cap. NO network / file / subprocess. "
                "Available in scope: math, re, statistics, collections "
                "(Counter, defaultdict). "
                "Examples:\n"
                "  -> python_eval({\"code\": \"result = len(packets)\"})\n"
                "  -> python_eval({\"code\": \"import math; from collections import Counter; "
                "def e(s):\\n    freq = Counter(s.encode()); n = len(s); "
                "return -sum((c/n) * math.log2(c/n) for c in freq.values()) "
                "if n else 0.0\\nhi = sum(1 for p in packets if getattr(p,'dst_port',None)==53 "
                "and e(p.payload[:32]) > 3.5)\\nresult = f'{hi} high-entropy DNS queries'\"})\n"
                "  -> python_eval({\"code\": \"result = sorted(Counter(p.dst_ip for p in packets).items(), key=lambda kv: -kv[1])[:5]\"})\n"
                "Always assign the variable `result` (string/number/list). "
                "LAST RESORT ONLY — use compute_packets first for group/count/"
                "filter/aggregate questions (it is deterministic and needs no "
                "code); fall back to python_eval only when compute_packets "
                "cannot express the computation."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {"type": "string",
                             "description": "Python snippet; must set `result`. Max 4000 chars."},
                },
                "required": ["code"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "create_tool",
            "description": (
                "Define a NEW sandboxed tool at runtime when NO existing "
                "tool can express the computation. Provide a unique lowercase "
                "snake_case name, a description, a JSON parameter schema, and "
                "a Python body. The body runs in the same read-only sandbox "
                "as python_eval (5s timeout, 50MB cap, no network/file/"
                "subprocess) with your call arguments injected as a plain "
                "dict named `args`; it MUST set `result`. After it is "
                "created you can call it by name in later steps.\n"
                "Examples:\n"
                "  -> create_tool({\"name\": \"count_smtp_verbs\", "
                "\"description\": \"Count SMTP command verbs across all "
                "streams\", \"parameters\": {\"type\": \"object\", "
                "\"properties\": {}}, \"code\": \"from collections import "
                "Counter\\nverbs = Counter()\\nfor p in packets:\\n    pl = "
                "(getattr(p, 'payload', b'') or b'').decode('latin-1', "
                "'replace')\\n    for v in ('EHLO', 'MAIL', 'RCPT', 'DATA', "
                "'QUIT'):\\n        verbs[v] += pl.count(v)\\nresult = "
                "dict(verbs)\"})\n"
                "Use this ONLY when compute_packets / python_eval / the "
                "fixed tools cannot answer — prefer existing tools first."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string",
                             "description": "Lowercase snake_case identifier "
                                            "for the new tool (2-64 chars)."},
                    "description": {"type": "string",
                                    "description": "What the tool computes, "
                                                   "for the LLM's schema."},
                    "parameters": {"type": "object",
                                   "description": "JSON schema for the tool's "
                                                  "call arguments, e.g. "
                                                  "{\"type\": \"object\", "
                                                  "\"properties\": {\"x\": "
                                                  "{\"type\": \"integer\"}}}."},
                    "code": {"type": "string",
                             "description": "Python body; `args` dict and "
                                            "packets/flows/alerts/stats are in "
                                            "scope. Must set `result`. Max "
                                            "4000 chars."},
                },
                "required": ["name", "description", "parameters", "code"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_protocol_summary",
            "description": (
                "Deterministic per-protocol dissection summary: how many HTTP "
                "requests, DNS queries, SMTP sessions, TLS handshakes, DHCP "
                "leases, ARP requests, unknown ports and skipped packets. "
                "Always available. Use FIRST for 'what is in this pcap?' "
                "before deciding which dissection tool to call.\n"
                "  -> get_protocol_summary()"
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_http_requests",
            "description": (
                "HTTP requests and responses extracted at load time: method, "
                "uri, host, user-agent, response code, content-type, body "
                "preview. Available only when the capture contains HTTP. "
                "Examples:\n"
                "  -> get_http_requests()\n"
                "  -> 'what did the browser request?' -> get_http_requests()"
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_dns_queries",
            "description": (
                "DNS queries (name, qtype, src ip), responses, NXDOMAINs and "
                "suspicious long subdomain labels (possible tunneling). "
                "Available only when DNS traffic is present. "
                "Examples:\n"
                "  -> get_dns_queries()\n"
                "  -> 'what domains were resolved?' -> get_dns_queries()"
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_credentials",
            "description": (
                "All credentials found in the capture: SMTP AUTH (user/pass), "
                "HTTP Basic, IMAP/POP3 login, FTP USER/PASS. "
                "Examples:\n"
                "  -> get_credentials()\n"
                "  -> 'what username/password pairs were used?' -> get_credentials()"
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_transferred_files",
            "description": (
                "Files recovered from the capture: HTTP downloads, SMTP MIME "
                "attachments, and carved blobs, each with filename, size and "
                "MD5. Available only when a file transfer is present. "
                "Examples:\n"
                "  -> get_transferred_files()\n"
                "  -> 'what files were transferred?' -> get_transferred_files()"
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_tls_sessions",
            "description": (
                "TLS ClientHello handshakes: SNI, protocol version, cipher "
                "suite. Available only when TLS is present. "
                "Examples:\n"
                "  -> get_tls_sessions()\n"
                "  -> 'what TLS servers were contacted?' -> get_tls_sessions()"
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_arp_table",
            "description": (
                "ARP requests, gratuitous announcements and the observed "
                "MAC->IP mapping. Available only when ARP traffic is present. "
                "Examples:\n"
                "  -> get_arp_table()\n"
                "  -> 'what MAC/IP pairs exist?' -> get_arp_table()"
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_smtp_sessions",
            "description": (
                "SMTP sessions: sender (MAIL FROM), recipients (RCPT TO), "
                "subject, AUTH username/password, body preview. Available "
                "only when SMTP is present. "
                "Examples:\n"
                "  -> get_smtp_sessions()\n"
                "  -> 'who emailed whom?' -> get_smtp_sessions()"
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_dhcp_leases",
            "description": (
                "DHCP offers/acks: assigned IP, client MAC, hostname, vendor "
                "class. Available only when DHCP traffic is present. "
                "Examples:\n"
                "  -> get_dhcp_leases()\n"
                "  -> 'what IPs were assigned?' -> get_dhcp_leases()"
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_ssh_sessions",
            "description": (
                "SSH sessions identified by banner exchange (src, dst, "
                "software string). Available only when SSH is present. "
                "Examples:\n"
                "  -> get_ssh_sessions()\n"
                "  -> 'any SSH traffic?' -> get_ssh_sessions()"
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
]


def execute_tool(name: str, args: Dict[str, Any], ctx: ToolContext) -> Dict[str, Any]:
    """Single dispatch entry point used by the LLM tool-calling loop.

    Phase 10.3: deterministic results are cached in the session-scoped
    ai.tool_cache (keyed by tool name + args + pcap_hash). Cache hits
    short-circuit the executor; error results are never cached.
    """
    from ai import tool_cache
    pcap_hash = None
    pcap_path = getattr(ctx, "pcap_path", None)
    if pcap_path:
        from core.memory import pcap_hash as _pcap_hash
        pcap_hash = _pcap_hash(str(pcap_path))
    cached = tool_cache.get(name, args, pcap_hash)
    if cached is not None:
        return cached
    fn = TOOL_EXECUTORS.get(name)
    if fn is None:
        return {"error": f"unknown tool: {name}"}
    try:
        result = fn(args or {}, ctx)
    except Exception as exc:
        logger.error("tool %s raised: %s", name, exc)
        result = {"error": str(exc)}
    if "error" not in result:
        tool_cache.set(name, args, pcap_hash, result)
    return result


def register_tool(name: str,
                  schema: Dict[str, Any],
                  fn: Callable[[Dict[str, Any], ToolContext], Dict[str, Any]]) -> None:
    """Extension hook — add a new tool at runtime."""
    TOOL_EXECUTORS[name] = fn
    TOOL_SCHEMAS.append({"type": "function", "function": schema})
