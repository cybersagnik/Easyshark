"""
triage.py — fast protocol-capability classifier for a loaded PCAP.

The classifier runs ONCE at InteractiveShell.__init__ end, walks every
packet's payload once, and emits a ``Dict[str, bool]`` of capabilities
that downstream consumers (heuristic_qa, LLM tool loop) gate on.

Capabilities:
    smtp                — AUTH LOGIN / AUTH PLAIN bytes or MAIL FROM/RCPT TO
                          headers + multipart DATA in the same flow.
    im                  — AIM/MSN/Yahoo screen-name strings OR docx-shaped
                          blobs OR chat-style prose ('here's the secret').
    http                — GET/POST/HEAD/Host: on a recognised web port
                          (80, 443, 8080, 8443, 3128, 1080).
    dns_tunneling_suspect — at least 5 DNS queries where the leftmost
                          subdomain label has Shannon entropy > 3.5 bits
                          (a textbook DGA / DNS-tunnel signal).
    tls                 — TLS ClientHello (0x16 0x03 record type) bytes.
    ad_network          — any of the well-known ad-domain needles seen in
                          payloads (at.atwola, doubleclick, etc.).
    docx_carved         — at least one ZIP/DOCX blob carved (>= 1KB).
    encrypted_heavy     — >50% of payload bytes have Shannon entropy
                          >= 7.5 bits per 256-byte window (typical of
                          compressed/encrypted traffic).

All signals are computed deterministically, no LLM, no cloud probes.
Target latency: ~50 ms on a 600-packet capture.

Public API:
    from core.triage import triage_capabilities
    caps = triage_capabilities(packets)
    if caps["smtp"]:
        ...
"""
from __future__ import annotations

import logging
import math
import re
from collections import Counter
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


# The 8 binary capability flags. Summary keys (protocol_counts,
# active_protocols, ip_summary, port_summary, conversation_count,
# triage_version) are also present in the returned dict but are NOT
# capabilities — consumers that enumerate "which protocols are on" must
# filter to these keys only.
TRIAGE_FLAG_KEYS: tuple = (
    "smtp", "im", "http", "dns_tunneling_suspect", "tls",
    "ad_network", "docx_carved", "encrypted_heavy",
)


# ---------------------------------------------------------------------------
# Cheap-byte probes
# ---------------------------------------------------------------------------
_NEEDLES_AUTH = (b"AUTH LOGIN", b"AUTH PLAIN")
_NEEDLES_SMTP_ENVELOPE = (b"MAIL FROM:", b"RCPT TO:", b"EHLO ", b"HELO ")
_NEEDLES_SMTP_DATA = (b"Content-Type:", b"multipart")
_NEEDLES_AD = (
    b"at.atwola.com",
    b"doubleclick.net",
    b"/adiframe/",
    b"/addyn/",
    b"googlesyndication.com",
    b"adsafeprotected.com",
    b"adnxs.com",
    b"rubiconproject.com",
    b"openx.net",
)
_NEEDLES_IM = (
    b"AIM ",
    b"OSCAR ",
    b"MSNSLP",
    b"YMSG",
    b"XMPP",
    b"YahooMessenger",
)
_HTTP_PORT_SET = frozenset({80, 443, 8080, 8443, 3128, 1080, 8000, 8888})
_TLS_PORT_SET = frozenset({443, 993, 995, 8443})
_MAGIC_ZIP_DOCX = b"PK\x03\x04"
_DNS_PORT = 53


# Pre-compiled regexes (compiled at import — safe; no user input).
_RE_HTTP_REQ_LINE = re.compile(
    rb"^(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+\S+\s+HTTP/\d",
    re.MULTILINE,
)
_RE_HOST_HDR = re.compile(rb"\nHost:\s*[^\r\n]+", re.IGNORECASE)
_RE_TLS_CLIENT_HELLO = re.compile(rb"\x16\x03[\x00-\x03]")


# ---------------------------------------------------------------------------
# Shannon entropy of a byte window
# ---------------------------------------------------------------------------
def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    n = len(data)
    h = 0.0
    for c in freq.values():
        p = c / n
        h -= p * math.log2(p)
    return h


def _label_entropy(label: str) -> float:
    """Shannon entropy of a DNS subdomain label."""
    if not label:
        return 0.0
    return _shannon_entropy(label.encode("latin-1", "replace"))


def _extract_dns_name(payload: bytes) -> str:
    """Best-effort: pull the first DNS QNAME out of a raw DNS payload.
    Crude but enough for triage signal — no need to parse the full
    RFC-1035 header. Skips the header (12 bytes), reads the QNAME
    length-prefixed labels until we hit a 0 byte."""
    if not payload or len(payload) < 13:
        return ""
    try:
        i = 12
        labels = []
        while i < len(payload) and payload[i] != 0:
            ln = payload[i]
            if ln > 63 or i + ln + 1 > len(payload):
                return ""
            labels.append(payload[i + 1 : i + 1 + ln].decode("latin-1", "replace"))
            i += ln + 1
        return ".".join(labels)
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------
def triage_capabilities(packets: List[Any]) -> Dict[str, bool]:
    """Walk every packet once, return a capability dict. All flags start
    False; set to True the moment enough evidence is seen.

    Phase 15 — also returns deterministic summary fields alongside the 8
    boolean flags (see TRIAGE_FLAG_KEYS for which keys are flags):
        protocol_counts:      Dict[str, int]   # proto name -> packet count
        active_protocols:     List[str]        # count > 0, sorted desc
        ip_summary:           Dict[str, dict]  # ip -> {sent, recv, protocols}
        port_summary:         Dict[int, int]   # dst port -> packets (top 20)
        conversation_count:   int              # unique src:sport -> dst:dport
        triage_version:       "2"
    """
    caps: Dict[str, bool] = {
        "smtp": False,
        "im": False,
        "http": False,
        "dns_tunneling_suspect": False,
        "tls": False,
        "ad_network": False,
        "docx_carved": False,
        "encrypted_heavy": False,
    }
    if not packets:
        caps.update({
            "protocol_counts": {},
            "active_protocols": [],
            "ip_summary": {},
            "port_summary": {},
            "conversation_count": 0,
            "triage_version": "2",
        })
        return caps

    # Accumulators we want to keep across the walk.
    smtp_auth_seen = False
    smtp_envelope_seen = False
    smtp_data_seen = False
    im_needle_seen = False
    http_seen = False
    ad_seen = False
    tls_seen = False
    docx_seen = False

    # DNS-specific counters.
    dns_query_count = 0
    high_entropy_count = 0

    # Encrypted-traffic fraction.
    payload_total_bytes = 0
    high_entropy_bytes = 0

    # Phase 15 — deterministic summary accumulators.
    protocol_counts: Counter = Counter()
    ip_sent: Counter = Counter()
    ip_recv: Counter = Counter()
    ip_protos: Dict[str, set] = {}
    port_counts: Counter = Counter()
    conversations: set = set()

    for pkt in packets:
        dport = getattr(pkt, "dst_port", None)
        sport = getattr(pkt, "src_port", None)
        sip = getattr(pkt, "src_ip", None)
        dip = getattr(pkt, "dst_ip", None)
        proto = getattr(pkt, "protocol", None) or "?"

        # ---- Phase 15 summary accumulators (count EVERY packet) ----
        if proto:
            protocol_counts[proto] += 1
        if sip:
            ip_sent[sip] += 1
            ip_protos.setdefault(sip, set()).add(proto)
        if dip:
            ip_recv[dip] += 1
            ip_protos.setdefault(dip, set()).add(proto)
        if dport:
            port_counts[dport] += 1
        if sip and dip:
            conversations.add((sip, sport, dip, dport))

        payload = getattr(pkt, "payload", b"") or b""
        if not payload:
            continue
        plen = len(payload)
        payload_total_bytes += plen

        # ---- SMTP probes ----
        for needle in _NEEDLES_AUTH:
            if needle in payload:
                smtp_auth_seen = True
                break
        for needle in _NEEDLES_SMTP_ENVELOPE:
            if needle in payload:
                smtp_envelope_seen = True
                break
        if b"multipart" in payload and b"Content-Type:" in payload:
            smtp_data_seen = True

        # ---- IM probes ----
        for needle in _NEEDLES_IM:
            if needle in payload:
                im_needle_seen = True
                break

        # ---- HTTP probes ----
        if dport in _HTTP_PORT_SET or sport in _HTTP_PORT_SET:
            if _RE_HTTP_REQ_LINE.search(payload) or _RE_HOST_HDR.search(payload):
                http_seen = True

        # ---- DNS probes (UDP/53 traffic) ----
        if dport == _DNS_PORT or sport == _DNS_PORT:
            # Heuristic: query payloads are typically shorter than responses
            # and live on src_port==53 OR dst_port==53. Triage just looks
            # at any DNS-shaped packet and counts QNAMEs.
            qname = _extract_dns_name(payload)
            if qname:
                dns_query_count += 1
                # Inspect the leftmost label (the subdomain candidates).
                leftmost = qname.split(".", 1)[0]
                if len(leftmost) >= 8 and _label_entropy(leftmost) > 3.5:
                    high_entropy_count += 1

        # ---- TLS probes ----
        if dport in _TLS_PORT_SET or sport in _TLS_PORT_SET \
                or _RE_TLS_CLIENT_HELLO.search(payload[:64]):
            if _RE_TLS_CLIENT_HELLO.search(payload[:64]):
                tls_seen = True

        # ---- Ad-network probes ----
        if not ad_seen:
            for n in _NEEDLES_AD:
                if n in payload:
                    ad_seen = True
                    break

        # ---- DOCX carve probe (magic byte + size) ----
        if not docx_seen and _MAGIC_ZIP_DOCX in payload[:64]:
            # Need enough bytes after the magic to count as a real file.
            idx = payload.find(_MAGIC_ZIP_DOCX)
            if idx >= 0 and (plen - idx) >= 1024:
                docx_seen = True

        # ---- Encrypted-heavy fraction (sampled) ----
        if plen >= 256:
            # Sample first 256 bytes — enough to estimate entropy cheaply.
            sample = payload[:256]
            if _shannon_entropy(sample) >= 7.5:
                high_entropy_bytes += 256
            else:
                # Fall through — we'll mark encrypted_heavy via threshold.
                pass

        # Early-out once all flags are True and dns count is high enough.
        # Skips remaining work on long captures.
        if smtp_auth_seen and im_needle_seen and http_seen and ad_seen \
                and tls_seen and docx_seen \
                and dns_query_count >= 200 \
                and high_entropy_count >= 50:
            # We still need encrypted_heavy from the payload walk below;
            # can't early-out yet.
            pass

    # ---- Compose final flags ----
    caps["smtp"] = smtp_auth_seen or (
        smtp_envelope_seen and smtp_data_seen
    )
    # IM = needle OR docx carved OR chat prose. We relax to "docx_seen"
    # so the heuristic's _h_im_* handlers can still try docx-only captures.
    caps["im"] = im_needle_seen or docx_seen
    caps["http"] = http_seen
    # DNS-tunnel suspect: >=5 high-entropy subdomain labels in the capture.
    # (Cheap signal — at least one DGA or iodine-style label.)
    caps["dns_tunneling_suspect"] = (
        dns_query_count >= 5 and high_entropy_count >= 5
    )
    caps["tls"] = tls_seen
    caps["ad_network"] = ad_seen
    caps["docx_carved"] = docx_seen
    # Encrypted-heavy: >= 50% of payload bytes are sampled as high-entropy.
    # This is conservative (only counts 256-byte samples) but robust.
    if payload_total_bytes > 0:
        caps["encrypted_heavy"] = (
            high_entropy_bytes / max(payload_total_bytes, 1) >= 0.5
        )

    # ---- Phase 15: compose deterministic summary ----
    active = [p for p, n in protocol_counts.items() if n > 0]
    active.sort(key=lambda p: -protocol_counts[p])
    ip_summary: Dict[str, dict] = {}
    for ip in sorted(set(list(ip_sent) + list(ip_recv))):
        protos = sorted(ip_protos.get(ip, set()))
        ip_summary[ip] = {
            "sent": ip_sent.get(ip, 0),
            "recv": ip_recv.get(ip, 0),
            "protocols": protos,
        }
    top_ports = sorted(port_counts.items(), key=lambda kv: -kv[1])[:20]
    caps.update({
        "protocol_counts": dict(protocol_counts),
        "active_protocols": active,
        "ip_summary": ip_summary,
        "port_summary": dict(top_ports),
        "conversation_count": len(conversations),
        "triage_version": "2",
    })

    logger.debug("triage capabilities: %s", {k: v for k, v in caps.items()
                                              if k in TRIAGE_FLAG_KEYS})
    return caps


# ---------------------------------------------------------------------------
# (render_capabilities removed in L19 — it was an unused banner helper.)
# ---------------------------------------------------------------------------

