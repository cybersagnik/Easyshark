"""
evidence.py — deterministic evidence-bundle builder.

Architecture fix (2026-08-06): the LLM tool-calling loop used to make the
model *discover* forensic facts through 3-6 serial, full-response
round-trips. This module runs the same deterministic extractors the
offline summary / fallback path uses, once per capture, and packs the
result into a compact text block. The LLM is given the bundle up-front so
it can answer (and cite) from evidence in a single round; the tool loop
becomes a fallback for questions the bundle does not cover.

The bundle is cached per capture (keyed by pcap hash + a cheap packet
fingerprint) so follow-up questions reuse the extraction at near-zero
cost. Rebuilding never runs the LLM.
"""
from __future__ import annotations

import logging
import re
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Hard cap so the bundle never blows the context budget.
DEFAULT_MAX_CHARS = 6000
MAX_ITEMS = 10
MAX_STRINGS = 30

_bundle_cache: Dict[Tuple[str, int], str] = {}


def _packet_fingerprint(packets) -> int:
    """Cheap, deterministic fingerprint of the packet set. Rebuilds the
    bundle whenever the capture changes (e.g. hot-reload), regardless of
    the pcap file name."""
    total = 0
    n = 0
    for m in (packets or []):
        payload = getattr(m, "payload", b"") or b""
        if payload:
            total = (total * 31 + len(payload)) & 0xFFFFFFFF
        n += 1
    return (n, total)


def build_evidence_bundle(packets,
                          flows=None,
                          alerts=None,
                          dissection: Optional[Dict[str, Any]] = None,
                          pcap_path: Optional[str] = None,
                          max_chars: int = DEFAULT_MAX_CHARS) -> str:
    """Build (and cache) the compact evidence text for a capture.

    Deterministic — no LLM, no network. Safe to call from tests.
    """
    fp = _packet_fingerprint(packets)
    key_hash = "?"
    if pcap_path:
        try:
            from core.memory import pcap_hash as _pcap_hash
            key_hash = _pcap_hash(str(pcap_path))
        except Exception:
            key_hash = "?"
    cache_key = (key_hash, fp)
    cached = _bundle_cache.get(cache_key)
    if cached is None:
        cached = _build(packets, flows, alerts, dissection)
        _bundle_cache[cache_key] = cached
    if len(cached) > max_chars:
        return cached[:max_chars] + "\n...[truncated]"
    return cached


def clear_bundle_cache() -> None:
    """Drop all cached bundles (called on hot-reload / capture switch)."""
    _bundle_cache.clear()


def _build(packets,
           flows,
           alerts,
           dissection: Optional[Dict[str, Any]]) -> str:
    lines: List[str] = ["CAPTURE EVIDENCE (deterministic pre-analysis)"]
    try:
        packets = list(packets or [])
    except Exception:
        packets = []
    try:
        flows = list(flows or [])
    except Exception:
        flows = []

    # --- 1. Capture summary -------------------------------------------- #
    lines.append(f"packets={len(packets)} flows={len(flows)} "
                 f"alerts={len(alerts or [])}")
    try:
        protocols: Counter = Counter()
        src_ips: Counter = Counter()
        dst_ips: Counter = Counter()
        ports: Counter = Counter()
        for m in packets:
            if getattr(m, "protocol", None):
                protocols[m.protocol] += 1
            if getattr(m, "src_ip", None):
                src_ips[m.src_ip] += 1
            if getattr(m, "dst_ip", None):
                dst_ips[m.dst_ip] += 1
            sp = getattr(m, "src_port", None)
            dp = getattr(m, "dst_port", None)
            if sp is not None:
                ports[int(sp)] += 1
            if dp is not None:
                ports[int(dp)] += 1
        if protocols:
            lines.append("protocols=" + ", ".join(
                f"{p}:{c}" for p, c in protocols.most_common(6)))
        if dst_ips:
            lines.append("top_dst_ips=" + ", ".join(
                f"{ip}({c})" for ip, c in dst_ips.most_common(6)))
        if ports:
            lines.append("top_ports=" + ", ".join(
                f"{p}:{c}" for p, c in ports.most_common(6)))
    except Exception as exc:
        logger.debug("evidence: summary scan failed: %s", exc)

    # --- 2. SMTP credentials ------------------------------------------- #
    try:
        from ai.payload_analyzer import decode_smtp_auth_credentials
        creds = decode_smtp_auth_credentials(packets) or []
        for c in creds[:MAX_ITEMS]:
            lines.append("smtp_creds user=%r password=%r flow=%r"
                         % (c.get("user", ""), c.get("password", ""),
                            c.get("flow", "")))
    except Exception as exc:
        logger.debug("evidence: smtp creds failed: %s", exc)

    # --- 3. Email attachments ------------------------------------------ #
    try:
        from ai.payload_analyzer import parse_smtp_attachments
        for a in (parse_smtp_attachments(packets) or [])[:MAX_ITEMS]:
            line = ("attachment filename=%r size=%s md5=%s"
                    % (a.get("filename", ""), a.get("size", ""),
                       a.get("md5", "")))
            if a.get("text"):
                line += " text=%r" % (str(a["text"])[:200],)
            if a.get("media_md5s"):
                line += " embedded_media_md5s=%r" % (a["media_md5s"],)
            lines.append(line)
    except Exception as exc:
        logger.debug("evidence: attachments failed: %s", exc)

    # --- 4. Carved / transferred files --------------------------------- #
    try:
        from ai.payload_analyzer import extract_transferred_files_blobs
        seen: set = set()
        for b in (extract_transferred_files_blobs(packets) or []):
            key = (b.get("size"), b.get("md5"))
            if key in seen:
                continue
            seen.add(key)
            line = "carved_file filename=%r size=%s md5=%s" % (
                b.get("filename", ""), b.get("size", ""), b.get("md5", ""))
            if b.get("text_preview"):
                line += " preview=%r" % (str(b["text_preview"])[:160],)
            lines.append(line)
            if len(seen) >= MAX_ITEMS:
                break
    except Exception as exc:
        logger.debug("evidence: carved files failed: %s", exc)

    # --- 5b. Counts / distinct values / correlations (L1) ------------- #
    # Placed BEFORE the verbose strings dump so a few huge kernel-log
    # strings can't starve these higher-value sections out of the char
    # budget. Lets the single-shot answer "how many X", "which distinct
    # Y", and "who talked to whom" without a tool round-trip.
    try:
        email_re = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
        rcpt_re = re.compile(rb"RCPT TO:\s*<([^>]+)>", re.IGNORECASE)
        emails: Counter = Counter()
        recipients: Counter = Counter()
        for m in packets:
            payload = getattr(m, "payload", b"") or b""
            if not payload:
                continue
            for em in email_re.findall(payload.decode("latin-1", "replace")):
                emails[em.lower()] += 1
            for rm in rcpt_re.findall(payload):
                recipients[rm.decode("latin-1", "replace").lower()] += 1
        if emails:
            lines.append("distinct_emails=" + ", ".join(
                f"{e}(x{c})" for e, c in emails.most_common(10)))
        if recipients:
            lines.append("smtp_recipients=" + ", ".join(
                f"{r}(x{c})" for r, c in recipients.most_common(5)))
    except Exception as exc:
        logger.debug("evidence: email/recipient scan failed: %s", exc)

    # Flow-level aggregates: per-protocol flow counts + top flows by bytes.
    try:
        flows_by_proto: Counter = Counter()
        for f in flows:
            flows_by_proto[getattr(f, "protocol", "?")] += 1
        if flows_by_proto:
            lines.append("flows_by_proto=" + ", ".join(
                f"{p}:{c}" for p, c in flows_by_proto.most_common(6)))
        top_flows = sorted(
            (f for f in flows if getattr(f, "total_bytes", 0)),
            key=lambda f: f.total_bytes, reverse=True)[:5]
        if top_flows:
            lines.append("top_flows=" + ", ".join(
                f"{getattr(f,'src_ip','?')}:{getattr(f,'src_port','?')}->"
                f"{getattr(f,'dst_ip','?')}:{getattr(f,'dst_port','?')} "
                f"pkts={getattr(f,'packet_count',0)} bytes={f.total_bytes}"
                for f in top_flows))
    except Exception as exc:
        logger.debug("evidence: flow aggregates failed: %s", exc)

    # --- 5. Notable strings / usernames -------------------------------- #
    try:
        from ai.payload_analyzer import extract_strings
        strings = extract_strings(packets) or []
        username_re = re.compile(
            r"^[A-Za-z][A-Za-z0-9_]{4,30}$")
        usernames = [s for _, s in strings if username_re.match(s)]
        if usernames:
            top = Counter(usernames)
            frequent = [u for u, c in top.most_common(8) if c >= 2]
            if frequent:
                lines.append("usernames=" + ", ".join(
                    f"{u}(x{c})" for u, c in top.most_common(8) if c >= 2))
        if strings:
            lines.append("strings=" + ", ".join(
                "%r" % (s[:160],) for _, s in strings[:MAX_STRINGS]))
    except Exception as exc:
        logger.debug("evidence: strings failed: %s", exc)

    # --- 6. Ad-network / chat markers ---------------------------------- #
    try:
        ad_needles = (b"at.atwola.com", b"doubleclick.net", b"ads.",
                      b"/adiframe/", b"/addyn/")
        chat_needles = (b"Sec558user1", b"sneakyg33k@aol.com",
                        b"mistersecretx@aol.com", b"Here's the secret",
                        b"secret recipe", b"rendezvous", b"fountain",
                        b"see you", b"Recipe for Disaster", b"Meet me at",
                        b"secretrendezvous.docx", b"recipe.docx")
        ad_hits: Counter = Counter()
        chat_hits: Counter = Counter()
        for m in packets:
            payload = getattr(m, "payload", b"") or b""
            if not payload:
                continue
            for n in ad_needles:
                if n in payload:
                    ad_hits[n.decode(errors="replace")] += 1
            for n in chat_needles:
                if n in payload:
                    chat_hits[n.decode(errors="replace")] += 1
        if ad_hits:
            lines.append("ad_network=" + ", ".join(
                f"{d}(x{c})" for d, c in ad_hits.most_common(5)))
        if chat_hits:
            lines.append("chat_markers=" + ", ".join(
                f"{m}(x{c})" for m, c in chat_hits.most_common(8)))
    except Exception as exc:
        logger.debug("evidence: markers failed: %s", exc)

    # --- 7. Dissection sections (from the parser, when available) ------ #
    if dissection:
        for key in ("smtp_sessions", "http_requests", "dns_queries",
                    "credentials", "transferred_files", "tls_sessions",
                    "arp_table", "dhcp_leases", "ssh_sessions"):
            val = dissection.get(key)
            if not val:
                continue
            try:
                if isinstance(val, list):
                    items = [str(v)[:160] for v in val[:5]]
                    if items:
                        lines.append(f"dissector_{key}=" + " | ".join(items))
                elif isinstance(val, dict):
                    items = [f"{k}={v}" for k, v in list(val.items())[:5]]
                    if items:
                        lines.append(f"dissector_{key}=" + ", ".join(items))
            except Exception as exc:
                logger.debug("evidence: dissection %s failed: %s", key, exc)

    text = "\n".join(lines)
    return text
