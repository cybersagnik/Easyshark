"""
narrative.py — Layer 2 of the auto-analyst pipeline (context.md §14.4).

Turns (packets, flows, alerts, anomalies) into a structured text block
that fits in the LLM context window (~3,500 tokens regardless of capture
size). Consumed by ``ai.auto_analyst.analyze``.

Public API:
    build(packets, flows, alerts, anomalies, max_chars=14000) -> str

Output sections (in this order, see §14.4):

    EVIDENCE FACTS        — SMTP creds, attachments, carved files, usernames
    CAPTURE SUMMARY       — duration, packets, hosts, external contacts
    HOST PROFILES         — only hosts with anomaly involvement or top-3 traffic
    BEHAVIORAL EVENTS     — chronological, significant transitions only
    ANOMALIES RANKED      — sorted by score desc, capped at 10

Compression rules:
    - If total > max_chars (≈ 3,500 tokens at 4 chars/token):
        1. Trim BEHAVIORAL EVENTS first
        2. Trim low-score ANOMALIES second
        3. Truncate HOST PROFILE detail last
    - No tiktoken dependency: 1 token ≈ 4 chars approximation.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from core.detectors import Anomaly


# --------------------------------------------------------------------------- #
# Constants                                                                   #
# --------------------------------------------------------------------------- #
MAX_CHARS_DEFAULT = 14_000          # ≈ 3,500 tokens at 4 chars/token
MAX_ANOMALIES     = 10
MAX_TIMELINE      = 20              # cap events regardless of size


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #
def _is_internal(ip: str) -> bool:
    if not ip or ip.count(".") != 3:
        return False
    try:
        a, b, *_ = [int(p) for p in ip.split(".")]
    except ValueError:
        return False
    if a == 10: return True
    if a == 172 and 16 <= b <= 31: return True
    if a == 192 and b == 168: return True
    return False


def _ts_str(ts: float) -> str:
    """epoch seconds -> 'HH:MM:SS' (local-tz convention is fine for triage)."""
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S")
    except Exception:
        return "?"


def _fmt_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds/60:.1f}m"
    return f"{seconds/3600:.1f}h"


# --------------------------------------------------------------------------- #
# Section builders                                                            #
# --------------------------------------------------------------------------- #
def _evidence_facts(packets) -> str:
    """Pull the deterministic facts the heuristic QA already extracts.

    These are pre-extracted so the LLM can cite them in the IOC list
    instead of inventing values. Mirrors the helpers in
    ``ai.payload_analyzer`` without forcing the auto_analyst to know
    about that module.
    """
    lines = ["EVIDENCE FACTS  (extracted deterministically — cite these as IOCs)"]

    # ----- SMTP creds -------------------------------------------------- #
    from ai.payload_analyzer import (
        decode_smtp_auth_credentials,
        parse_smtp_attachments,
        extract_transferred_files_blobs,
        extract_strings,
        _canonical_flow_key,
        _flow_key_of,
    )
    creds = decode_smtp_auth_credentials(packets)
    if creds:
        for c in creds[:3]:
            lines.append(
                f"  SMTP AUTH ({c.get('method','?')}): "
                f"user={c.get('user','')!r}  password={c.get('password','')!r}"
            )
    else:
        lines.append("  SMTP AUTH: (none)")

    # ----- SMTP envelope (MAIL FROM / RCPT TO) ------------------------ #
    flows_blob: Dict[str, bytes] = {}
    for m in packets:
        k = _flow_key_of(m)
        if not k:
            continue
        ck = _canonical_flow_key(k)
        flows_blob.setdefault(str(ck), b"")
        flows_blob[str(ck)] += getattr(m, "payload", b"") or b""
    envelope_lines: List[str] = []
    for fid, blob in flows_blob.items():
        mail_from = re.search(rb"MAIL FROM:\s*<([^>\r\n]+)>", blob, re.IGNORECASE)
        rcpt_to = re.search(rb"RCPT TO:\s*<([^>\r\n]+)>", blob, re.IGNORECASE)
        if mail_from:
            envelope_lines.append(
                f"MAIL FROM: <{mail_from.group(1).decode('utf-8', 'replace')}>")
        if rcpt_to:
            envelope_lines.append(
                f"RCPT TO: <{rcpt_to.group(1).decode('utf-8', 'replace')}>")
    if envelope_lines:
        # Show distinct values only — many flows duplicate the same envelope.
        seen_env: set = set()
        unique_env = []
        for ln in envelope_lines:
            if ln not in seen_env:
                seen_env.add(ln)
                unique_env.append(ln)
        lines.append("  SMTP ENVELOPE:")
        for ln in unique_env[:6]:
            lines.append(f"    {ln}")
    else:
        lines.append("  SMTP ENVELOPE: (none)")

    # ----- Email attachments ------------------------------------------- #
    atts = parse_smtp_attachments(packets)
    if atts:
        for a in atts[:3]:
            line = (
                f"  SMTP ATTACHMENT: filename={a.get('filename','')!r}  "
                f"md5={a.get('md5','')}  size={a.get('size',0)}"
            )
            if a.get("text"):
                line += f"\n    text: {a['text'][:200]}"
            if a.get("media_md5s"):
                line += f"\n    embedded_media_md5s={a['media_md5s']}"
            lines.append(line)
    else:
        lines.append("  SMTP ATTACHMENTS: (none)")

    # ----- Carved files ------------------------------------------------- #
    blobs = extract_transferred_files_blobs(packets)
    if blobs:
        seen: set = set()
        for b in blobs[:5]:
            key = (b["size"], b["md5"])
            if key in seen:
                continue
            seen.add(key)
            line = (
                f"  CARVED FILE: filename={b.get('filename','')!r}  "
                f"format={b.get('format','')}  size={b.get('size',0)}  "
                f"md5={b.get('md5','')}"
            )
            if b.get("text_preview"):
                line += f"\n    preview: {b['text_preview'][:200]}"
            lines.append(line)
    else:
        lines.append("  CARVED FILES: (none)")

    # ----- Top usernames ----------------------------------------------- #
    strs = extract_strings(packets)
    usernames: Counter = Counter()
    for _, s in strs:
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{4,30}", s):
            usernames[s] += 1
    if usernames:
        top_users = [u for u, _ in usernames.most_common(5)]
        lines.append(f"  Top usernames: {', '.join(top_users)}")
    else:
        lines.append("  Top usernames: (none)")

    # ----- Top external destinations ---------------------------------- #
    ext_dst: Counter = Counter()
    for m in packets:
        if m.dst_ip and not _is_internal(m.dst_ip):
            ext_dst[m.dst_ip] += 1
    if ext_dst:
        top_dsts = [f"{ip} ({c}pkt)" for ip, c in ext_dst.most_common(5)]
        lines.append(f"  Top external destinations: {', '.join(top_dsts)}")

    lines.append("")
    return "\n".join(lines)



def _capture_summary(packets, flows, alerts, anomalies) -> str:
    n_packets = len(packets)
    if n_packets == 0:
        return "CAPTURE SUMMARY\n  (empty capture)\n"
    ts_min = min(p.timestamp for p in packets)
    ts_max = max(p.timestamp for p in packets)
    duration = ts_max - ts_min

    hosts = {p.src_ip for p in packets if p.src_ip} | {p.dst_ip for p in packets if p.dst_ip}
    external_hosts = {h for h in hosts if not _is_internal(h)}
    protos = {p.protocol for p in packets if p.protocol}

    return (
        "CAPTURE SUMMARY\n"
        f"  Duration: {_fmt_duration(duration)} | "
        f"Packets: {n_packets:,} | "
        f"Hosts: {len(hosts)} | "
        f"External contacts: {len(external_hosts)} IPs/domains\n"
        f"  Protocols detected: {', '.join(sorted(p for p in protos if p))}\n"
        f"  Flows: {len(flows)} | Alerts: {len(alerts)} | "
        f"Anomalies: {len(anomalies)}\n"
    )


def _host_profiles(packets, flows, anomalies) -> str:
    """Emit only hosts with anomaly involvement or top-3 by packet count.

    Flagged hosts (anomaly_hosts ∪ top-3 traffic) get an enriched profile:
      - Top-5 external IPs (with port + bytes attributed to that remote)
      - Top-5 queried domains (DNS, with query count)
      - Protocol breakdown (HTTP×N, DNS×N, SMTP×N, ...)
      - First / last packet time relative to capture start
      - Outbound vs inbound connection counts

    Unflagged hosts get a one-liner (saves tokens).
    """
    # Per-host aggregates.
    sent_bytes: Counter = Counter()
    recv_bytes: Counter = Counter()
    pkt_count: Counter = Counter()
    ext_dst_count: Counter = Counter()  # external destinations
    by_host: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {
            "connections": 0,
            "external_dsts": set(),
            "ports": set(),
            "outbound": 0,
            "inbound": 0,
            "ext_remote_bytes": Counter(),       # (remote_ip, port) -> bytes from this host
            "dns_queries": Counter(),            # queried domain -> count
            "protocol_counts": Counter(),        # protocol name -> packet count
            "first_ts": None,
            "last_ts": None,
        }
    )

    # Capture start (earliest timestamp seen).
    cap_start = min((m.timestamp for m in packets if m.timestamp), default=0.0)

    for m in packets:
        if not m.src_ip:
            continue
        pkt_count[m.src_ip] += 1
        sent_bytes[m.src_ip] += m.length
        h = by_host[m.src_ip]
        # Protocol breakdown (from src perspective).
        proto = m.protocol or "?"
        h["protocol_counts"][proto] += 1
        # First/last ts.
        if m.timestamp:
            if h["first_ts"] is None or m.timestamp < h["first_ts"]:
                h["first_ts"] = m.timestamp
            if h["last_ts"] is None or m.timestamp > h["last_ts"]:
                h["last_ts"] = m.timestamp
        if m.dst_ip:
            recv_bytes[m.dst_ip] += m.length
            h["external_dsts"].add(m.dst_ip)
            if m.dst_port:
                h["ports"].add(m.dst_port)
            if _is_internal(m.dst_ip):
                h["outbound"] += 1
            else:
                h["inbound"] += 1
                # Bytes attributed to (remote, port).
                key = (m.dst_ip, m.dst_port)
                h["ext_remote_bytes"][key] += m.length
            if not _is_internal(m.dst_ip):
                ext_dst_count[m.src_ip] += 1

        # DNS queries from this host.
        if m.protocol == "DNS" and m.dst_port == 53:
            name = _extract_dns_qname(m)
            if name:
                h["dns_queries"][name] += 1

    # Hosts touched by anomalies.
    anomaly_hosts = {h for a in anomalies for h in a.hosts if h}
    top_by_traffic = {ip for ip, _ in pkt_count.most_common(3)}

    flagged_hosts = anomaly_hosts | top_by_traffic
    if not flagged_hosts:
        return "HOST PROFILES\n  (no hosts to profile)\n"

    lines = ["HOST PROFILES"]
    median_packets = sorted(pkt_count.values())[len(pkt_count) // 2] if pkt_count else 0

    # Sort: anomaly hosts first, then by traffic volume.
    selected_hosts = sorted(
        flagged_hosts,
        key=lambda h: (0 if h in anomaly_hosts else 1, -pkt_count.get(h, 0)),
    )

    for host in selected_hosts:
        is_anom = host in anomaly_hosts
        up = sent_bytes.get(host, 0)
        down = recv_bytes.get(host, 0)
        pkts = pkt_count.get(host, 0)
        h = by_host[host]
        ext_dsts = h["external_dsts"]
        ext_external = {d for d in ext_dsts if not _is_internal(d)}
        ratio = (up / max(down, 1)) if down or up else 0
        ratio_str = f"{ratio:.0f}×" if ratio >= 10 else ""

        # Per-host anomaly evidence.
        host_anoms = [a for a in anomalies if host in a.hosts]

        tag = "[SUSPECT]" if is_anom else "[NORMAL ]"
        lines.append(f"  {host}  {tag}")
        lines.append(
            f"    Packets: {pkts} (capture median: {median_packets}) | "
            f"Up: {_fmt_bytes(up)} | Down: {_fmt_bytes(down)}"
            + (f"  [EXFIL RATIO: {ratio_str}]" if ratio_str else "")
        )
        if ext_external:
            ext_sample = sorted(ext_external)[:5]
            lines.append(f"    External destinations: {', '.join(ext_sample)}")
        for a in host_anoms[:4]:
            lines.append(f"    [{a.type}] score={a.score:.2f}  {a.evidence}")

        # --- ENRICHMENT for flagged hosts (anomaly OR top-3 traffic) ---
        # Top-5 external remotes by bytes.
        if h["ext_remote_bytes"]:
            top_remotes = h["ext_remote_bytes"].most_common(5)
            remotes_str = ", ".join(
                f"{ip}:{port or '?'} ({_fmt_bytes(b)})"
                for (ip, port), b in top_remotes
            )
            lines.append(f"    Top external (ip:port, bytes): {remotes_str}")
        # Top-5 queried DNS domains.
        if h["dns_queries"]:
            top_domains = h["dns_queries"].most_common(5)
            dom_str = ", ".join(f"{d}×{n}" for d, n in top_domains)
            lines.append(f"    Top DNS queries: {dom_str}")
        # Protocol breakdown.
        if h["protocol_counts"]:
            proto_str = ", ".join(
                f"{p}×{n}" for p, n in h["protocol_counts"].most_common()
            )
            lines.append(f"    Protocols: {proto_str}")
        # Outbound vs inbound connection counts.
        lines.append(
            f"    Connections: {h['outbound']} outbound / {h['inbound']} inbound"
        )
        # First / last packet relative to capture start.
        if h["first_ts"] is not None and h["last_ts"] is not None:
            first_rel = h["first_ts"] - cap_start
            last_rel = h["last_ts"] - cap_start
            lines.append(
                f"    Time in capture: {_fmt_duration(first_rel)} → {_fmt_duration(last_rel)}"
            )

    lines.append("")
    return "\n".join(lines)


def _extract_dns_qname(m) -> Optional[str]:
    """Best-effort extraction of queried DNS name from a DNS packet metadata.

    Returns None if payload isn't shaped like a DNS query or the name
    can't be decoded.
    """
    payload = getattr(m, "payload", b"") or b""
    if len(payload) < 12 or m.protocol != "DNS":
        return None
    try:
        off = 12  # skip DNS header
        labels = []
        while off < len(payload):
            ln = payload[off]
            if ln == 0:
                break
            if ln & 0xC0:  # compression pointer
                return None
            off += 1
            labels.append(payload[off:off + ln].decode("latin-1", "replace"))
            off += ln
        return ".".join(labels) if labels else None
    except Exception:
        return None


def _fmt_bytes(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n / (1024*1024):.1f}MB"
    if n >= 1024:
        return f"{n / 1024:.1f}KB"
    return f"{n}B"


def _behavioral_events(packets, anomalies) -> str:
    """Emit the chronologically significant transitions only.

    We pick events that are either (a) the first packet of an anomalous
    flow, or (b) the first occurrence of a recognised pattern. Output is
    capped at MAX_TIMELINE entries.
    """
    events: List[Tuple[float, str]] = []
    seen_kinds: set = set()

    # 1) First packet of each anomaly type (first packet index in evidence).
    for a in anomalies[:10]:
        if a.packets:
            first_idx = a.packets[0]
            if first_idx < len(packets):
                m = packets[first_idx]
                events.append((
                    m.timestamp,
                    f"[{a.type.upper():20s}] {m.src_ip or '?'} -> "
                    f"{m.dst_ip or '?'}:{m.dst_port or '?'}  {a.evidence}"
                ))

    # 2) First SMTP AUTH LOGIN (always significant if present).
    for m in packets:
        if m.payload and b"AUTH LOGIN" in m.payload:
            ts = m.timestamp
            events.append((
                ts,
                f"[SMTP AUTH           ] {m.src_ip or '?'} -> "
                f"{m.dst_ip or '?'}:{m.dst_port or '?'}  AUTH LOGIN handshake"
            ))
            seen_kinds.add("smtp_auth")
            break

    # 3) First HTTP GET / POST.
    for m in packets:
        if m.payload and (m.payload.startswith(b"GET ") or m.payload.startswith(b"POST ")):
            head = m.payload[:60].decode("latin-1", "replace").replace("\r\n", " ")
            events.append((
                m.timestamp,
                f"[HTTP                ] {m.src_ip or '?'} -> "
                f"{m.dst_ip or '?'}:{m.dst_port or '?'}  {head}"
            ))
            seen_kinds.add("http")
            break

    # 4) First TLS ClientHello.
    for m in packets:
        if m.payload and len(m.payload) > 5 and m.payload[0] == 0x16:
            events.append((
                m.timestamp,
                f"[TLS HANDSHAKE       ] {m.src_ip or '?'} -> "
                f"{m.dst_ip or '?'}:{m.dst_port or '?'}  ClientHello"
            ))
            seen_kinds.add("tls")
            break

    # 5) First beacon packet (highest-scoring beacon anomaly).
    beacon_anoms = [a for a in anomalies if a.type == "beaconing"]
    if beacon_anoms:
        a = beacon_anoms[0]
        if a.packets and a.packets[0] < len(packets):
            m = packets[a.packets[0]]
            events.append((
                m.timestamp,
                f"[BEACON              ] {m.src_ip or '?'} -> "
                f"{m.dst_ip or '?'}:{m.dst_port or '?'}  {a.evidence}"
            ))

    # 6) ARP scan start (if applicable).
    arp_anoms = [a for a in anomalies if a.type == "arp_scan"]
    if arp_anoms:
        a = arp_anoms[0]
        if a.packets and a.packets[0] < len(packets):
            m = packets[a.packets[0]]
            events.append((
                m.timestamp,
                f"[ARP SCAN            ] {m.src_ip or '?'} -> "
                f"{a.remote}  {a.evidence}"
            ))

    # 7) First DNS NXDOMAIN (if any).
    for m in packets:
        if m.protocol != "UDP" or not m.payload or len(m.payload) < 12:
            continue
        if (m.dst_port == 53 or m.src_port == 53) and (m.payload[2] & 0x80) and (m.payload[2] & 0x0F) == 3:
            events.append((
                m.timestamp,
                f"[DNS NXDOMAIN        ] {m.src_ip or '?'}  NXDOMAIN response"
            ))
            break

    # 8) First SMTP DATA (attachment transfer).
    for m in packets:
        if m.payload and b"DATA\r\n" in m.payload:
            events.append((
                m.timestamp,
                f"[SMTP DATA           ] {m.src_ip or '?'} -> "
                f"{m.dst_ip or '?'}:{m.dst_port or '?'}  message body transfer"
            ))
            break

    if not events:
        return "BEHAVIORAL EVENTS\n  (none)\n"

    events.sort(key=lambda e: e[0])
    events = events[:MAX_TIMELINE]

    lines = ["BEHAVIORAL EVENTS  (chronological, significant transitions only)"]
    for ts, body in events:
        lines.append(f"  {_ts_str(ts)}  {body}")
    lines.append("")
    return "\n".join(lines)


def _anomaly_ranked(anomalies) -> str:
    ranked = sorted(anomalies, key=lambda a: a.score, reverse=True)[:MAX_ANOMALIES]
    if not ranked:
        return "ANOMALIES RANKED BY SUSPICION\n  (none detected)\n"
    lines = ["ANOMALIES RANKED BY SUSPICION"]
    for i, a in enumerate(ranked, 1):
        lines.append(
            f"  {i:>2}. [{a.score:.2f}] {a.type:<22s}  "
            f"{','.join(a.hosts) or '?':>15s} -> {a.remote:<32s}  "
            f"{a.evidence}"
        )
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Top-level builder                                                           #
# --------------------------------------------------------------------------- #
def build(packets,
          flows,
          alerts,
          anomalies,
          max_chars: int = MAX_CHARS_DEFAULT) -> str:
    """Assemble the five sections, then enforce the char budget."""
    facts = _evidence_facts(packets)
    summary = _capture_summary(packets, flows, alerts, anomalies)
    profiles = _host_profiles(packets, flows, anomalies)
    events = _behavioral_events(packets, anomalies)
    ranked = _anomaly_ranked(anomalies)

    out = facts + "\n" + summary + "\n" + profiles + "\n" + events + "\n" + ranked

    if len(out) <= max_chars:
        return out

    # ---- Budget enforcement ---------------------------------------- #
    # 1. Trim BEHAVIORAL EVENTS (drop 2 lines at a time).
    lines = out.split("\n")
    try:
        events_start = next(i for i, ln in enumerate(lines)
                            if ln.startswith("BEHAVIORAL EVENTS"))
    except StopIteration:
        events_start = -1
    try:
        ranked_start = next(i for i, ln in enumerate(lines)
                            if ln.startswith("ANOMALIES RANKED"))
    except StopIteration:
        ranked_start = len(lines)
    try:
        profiles_start = next(i for i, ln in enumerate(lines)
                              if ln.startswith("HOST PROFILES"))
    except StopIteration:
        profiles_start = -1
    try:
        summary_start = next(i for i, ln in enumerate(lines)
                             if ln.startswith("CAPTURE SUMMARY"))
    except StopIteration:
        summary_start = -1

    # Drop from the tail of events (least-significant last entries).
    while len("\n".join(lines)) > max_chars and events_start >= 0:
        # Find a non-essential event line (indented with two spaces, not header).
        for j in range(ranked_start - 1, events_start, -1):
            ln = lines[j]
            if ln.startswith("  ") and len(ln.strip()) > 0:
                lines.pop(j)
                break
        else:
            break  # nothing more to drop from events

    # 2. Trim low-score ANOMALIES (drop tail of ranked list).
    if len("\n".join(lines)) > max_chars:
        try:
            ranked_idx = next(i for i, ln in enumerate(lines)
                              if ln.startswith("ANOMALIES RANKED"))
        except StopIteration:
            ranked_idx = -1
        while len("\n".join(lines)) > max_chars and ranked_idx >= 0:
            # find last numbered anomaly line "  N. [...]"
            for j in range(len(lines) - 1, ranked_idx, -1):
                ln = lines[j]
                if ln.lstrip().startswith(tuple(f"{n}." for n in range(1, 100))):
                    lines.pop(j)
                    break
            else:
                break

# 3. Truncate HOST PROFILE detail (drop non-essential sub-bullets).
    if len("\n".join(lines)) > max_chars and profiles_start >= 0:
        events_idx = events_start if events_start >= 0 else ranked_start
        while len("\n".join(lines)) > max_chars and profiles_start >= 0:
            # Drop the last sub-detail line (4-space indent, not header).
            for j in range(events_idx - 1, profiles_start, -1):
                ln = lines[j]
                if ln.startswith("    ") and len(ln.strip()) > 0:
                    lines.pop(j)
                    break
            else:
                break

    # 4. Drop low-priority EVIDENCE FACTS entries (carved files > usernames > ext dsts).
    if len("\n".join(lines)) > max_chars and summary_start >= 0:
        # Identify facts section start.
        facts_idx = next((i for i, ln in enumerate(lines)
                          if ln.startswith("EVIDENCE FACTS")), -1)
        while len("\n".join(lines)) > max_chars and facts_idx >= 0:
            # Drop the last indented fact line before CAPTURE SUMMARY.
            for j in range(summary_start - 1, facts_idx, -1):
                ln = lines[j]
                if ln.startswith("  ") and len(ln.strip()) > 0:
                    lines.pop(j)
                    break
            else:
                break

    return "\n".join(lines)
