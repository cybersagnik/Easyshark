"""
dissector.py — deep per-protocol field extraction (Phase 15).

Runs ONCE at InteractiveShell load time (after triage, before the shell
prompt). Walks every PacketMetadata once and produces a structured
``Dict[str, Any]`` stored as ``InteractiveShell.dissection``. This is the
data layer that feeds the LLM tool loop and the deterministic
``protocols``/``ips``/``flows``/``files``/``dns``/``creds``/``summary``
commands.

Design rules:
  * Deterministic, no LLM, no network. Target < 1 s on 600 packets.
  * Degrade gracefully — malformed/unknown payloads are skipped and
    counted in ``skipped``; nothing raises.
  * TLS/encrypted payloads are opaque: handshakes are parsed, bodies are
    never decoded.
  * Payload blobs are capped (per-file and per-capture) so a 90 MB pcap
    cannot balloon memory.

Public API:
    from core.dissector import dissect_packets
    d = dissect_packets(packets)
"""
from __future__ import annotations

import base64
import binascii
import logging
import re
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Port / protocol tables
# ---------------------------------------------------------------------------
_HTTP_PORTS = frozenset({80, 8080, 8000, 8888, 3128, 1080})
_SMTP_PORTS = frozenset({25, 587, 465, 2525})
_FTP_PORTS = frozenset({20, 21})
_SSH_PORTS = frozenset({22})
_DNS_PORT = 53
_DHCP_PORTS = frozenset({67, 68})
_NBNS_PORTS = frozenset({137, 138})
_SMB_PORTS = frozenset({139, 445})
_IMAP_PORTS = frozenset({143, 993})
_POP3_PORTS = frozenset({110, 995})
_IRC_PORTS = frozenset({6667, 6697})
_TLS_PORTS = frozenset({443, 993, 995, 465, 8443, 6697})
_AIM_PORTS = frozenset({5190, 1271, 1272, 1273})

# Any port not in this set is "unknown" for the raw-port report.
_KNOWN_PORTS = (_HTTP_PORTS | _SMTP_PORTS | _FTP_PORTS | _SSH_PORTS
                | {_DNS_PORT} | _DHCP_PORTS | _NBNS_PORTS | _SMB_PORTS
                | _IMAP_PORTS | _POP3_PORTS | _IRC_PORTS | _TLS_PORTS
                | _AIM_PORTS | {53, 80, 123, 161, 179, 500, 1900, 5222, 5223})

# Per-file payload cap (bytes) — protects memory on file-heavy captures.
_MAX_PAYLOAD_SAVE = 1024 * 1024
# Cap on how many transferred files we keep payload bytes for.
_MAX_FILES_WITH_PAYLOAD = 50

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _dec(data: bytes) -> str:
    """Decode payload bytes for text scanning (never fails)."""
    try:
        return data.decode("latin-1", "replace")
    except Exception:
        return ""


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _shannon_entropy(data: bytes) -> float:
    import math
    if not data:
        return 0.0
    n = len(data)
    if n < 2:
        return 0.0
    freq: Counter = Counter(data)
    h = 0.0
    for c in freq.values():
        p = c / n
        h -= p * math.log2(p)
    return h


def _split_header_body(payload: bytes) -> Tuple[str, bytes]:
    """Split an ASCII protocol message into (header, body) at the first
    CRLFCRLF (or LFLF). Returns header text and raw body bytes."""
    text = _dec(payload)
    for sep in ("\r\n\r\n", "\n\n"):
        idx = text.find(sep)
        if idx >= 0:
            return text[:idx], payload[idx + len(sep):]
    return text, b""


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
_RE_HTTP_REQLINE = re.compile(
    r"^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+(\S+)\s+HTTP/[\d.]+",
    re.IGNORECASE)
_RE_HTTP_RESLINE = re.compile(r"^HTTP/[\d.]+\s+(\d{3})\s*", re.IGNORECASE)
_RE_HDR = re.compile(r"(?im)^([A-Za-z][A-Za-z0-9-]*):\s*(.*)$")
_RE_CD_FILENAME = re.compile(r'filename\s*=\s*"?([^";\r\n]+)"?', re.IGNORECASE)
_RE_BASIC_AUTH = re.compile(r"Basic\s+([A-Za-z0-9+/=]+)", re.IGNORECASE)

_TEXT_TYPES = ("text/", "application/json", "application/xml",
               "application/javascript", "application/x-www-form-urlencoded")


def _dissect_http(payload: bytes, src: str, dst: str,
                  dport: int, files_carrier: List[Dict[str, Any]],
                  creds_carrier: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    header, body = _split_header_body(payload)
    req_m = _RE_HTTP_REQLINE.match(header.strip())
    res_m = _RE_HTTP_RESLINE.match(header.strip())
    if not req_m and not res_m:
        return None
    headers: Dict[str, str] = {}
    for m in _RE_HDR.finditer(header):
        headers[m.group(1).lower()] = m.group(2).strip()

    entry: Dict[str, Any] = {"src": src, "dst": dst}
    if req_m:
        entry["method"] = req_m.group(1).upper()
        entry["uri"] = req_m.group(2)[:500]
        entry["host"] = headers.get("host", "")
        entry["user_agent"] = headers.get("user-agent", "")
        entry["content_type"] = headers.get("content-type", "")
        entry["response_code"] = None
        auth = headers.get("authorization", "")
        if _RE_BASIC_AUTH.search(auth):
            try:
                up = base64.b64decode(_RE_BASIC_AUTH.search(auth).group(1))
                if b":" in up:
                    u, p = up.split(b":", 1)
                    creds_carrier.append({
                        "type": "Basic", "username": _dec(u),
                        "password": _dec(p), "protocol": "http",
                    })
            except Exception:
                pass
    else:
        entry["method"] = None
        entry["uri"] = None
        entry["host"] = ""
        entry["user_agent"] = ""
        entry["content_type"] = headers.get("content-type", "")
        entry["response_code"] = int(res_m.group(1))

    # Response body preview + file transfer.
    body_preview = ""
    ct = entry.get("content_type") or ""
    if body and (ct.startswith(_TEXT_TYPES) or not res_m):
        body_preview = _dec(body[:200])
    entry["response_body_preview"] = body_preview

    cd = headers.get("content-disposition", "")
    fname = None
    if cd:
        fm = _RE_CD_FILENAME.search(cd)
        if fm:
            fname = fm.group(1)
    if res_m and body and fname and len(files_carrier) < _MAX_FILES_WITH_PAYLOAD:
        files_carrier.append({
            "filename": fname,
            "content_type": ct or "application/octet-stream",
            "size_bytes": len(body),
            "protocol": "http",
            "payload_b64": _b64(body[:_MAX_PAYLOAD_SAVE]) if len(body) <= _MAX_PAYLOAD_SAVE else "",
            "direction": "download",
        })
    return entry


# ---------------------------------------------------------------------------
# SMTP
# ---------------------------------------------------------------------------
_RE_SMTP_CMD = re.compile(r"(?im)^([A-Z]{4})\s?(.*)$")
_B64_RE = re.compile(r"^[A-Za-z0-9+/=]+$")


def _b64_dec(s: str) -> str:
    try:
        return _dec(base64.b64decode(s))
    except Exception:
        return s


def _dissect_smtp(payload: bytes, src: str, dst: str,
                  session: Dict[str, Any]) -> None:
    header, body = _split_header_body(payload)
    # Reuse a per-conversation SMTP session object passed in.
    if not header and not body:
        return
    data_section = False
    for line in header.splitlines():
        up = line.upper()
        if up.startswith("MAIL FROM:"):
            session["mail_from"] = line.split(":", 1)[1].strip()[:200]
        elif up.startswith("RCPT TO:"):
            session.setdefault("rcpt_to", []).append(
                line.split(":", 1)[1].strip()[:200])
        elif up.startswith("SUBJECT:"):
            session["subject"] = line.split(":", 1)[1].strip()[:300]
        elif up.startswith("AUTH LOGIN"):
            session["_auth_mode"] = "login"
        elif up.startswith("AUTH PLAIN"):
            session["_auth_mode"] = "plain"
        elif session.get("_auth_mode") == "login":
            line_s = line.strip()
            if session.get("_auth_step") is None:
                session["_auth_step"] = 0
            if session["_auth_step"] == 0 and _B64_RE.match(line_s):
                session["auth_username"] = _b64_dec(line_s)
                session["_auth_step"] = 1
            elif session["_auth_step"] == 1 and _B64_RE.match(line_s):
                session["auth_password"] = _b64_dec(line_s)
                session["_auth_step"] = 2
        elif up.startswith("DATA"):
            data_section = True
        elif up.startswith("USER "):
            session["auth_username"] = line.split(" ", 1)[1].strip()
        elif up.startswith("PASS "):
            session["auth_password"] = line.split(" ", 1)[1].strip()
    # Body after DATA (headers + message). Just preview the text.
    if body and not session.get("body_preview"):
        text = _dec(body).strip()
        if text:
            session["body_preview"] = text[:300]


# ---------------------------------------------------------------------------
# FTP
# ---------------------------------------------------------------------------
_RE_FTP_CMD = re.compile(r"(?im)^([A-Z]{3,4})\s?(.*)$")


def _dissect_ftp(payload: bytes, ftp: Dict[str, Any]) -> None:
    text = _dec(payload)
    for line in text.splitlines():
        m = _RE_FTP_CMD.match(line)
        if not m:
            continue
        cmd = m.group(1).upper()
        arg = m.group(2).strip()
        ftp["commands"].append(cmd)
        if cmd == "USER":
            ftp["username"] = arg
        elif cmd == "PASS":
            ftp["password"] = arg
        elif cmd in ("RETR", "STOR") and arg:
            ftp["transferred_files"].append({
                "filename": arg,
                "direction": "download" if cmd == "RETR" else "upload",
                "size_bytes": None,
            })


def _scapy(pkt, layer):
    """Return the scapy layer from the metadata's raw_packet, or None.

    PacketMetadata keeps the original scapy packet on ``raw_packet``;
    layer lookups must go through that object."""
    raw = getattr(pkt, "raw_packet", None)
    if raw is None:
        return None
    try:
        return raw.getlayer(layer)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# DNS (scapy layers)
# ---------------------------------------------------------------------------
def _dissect_dns_packet(pkt, dns: Dict[str, Any], src_ip: str) -> None:
    try:
        from scapy.all import DNS
    except Exception:
        return
    layer = _scapy(pkt, DNS)
    if layer is None:
        return
    qd = layer.qd
    if qd is not None:
        name = getattr(qd, "qname", b"").decode("latin-1", "replace").rstrip(".")
        qtype = getattr(qd, "qtype", 0)
        if name and not name.startswith("."):
            dns["queries"].append({"name": name, "qtype": qtype, "src_ip": src_ip})
            dns["unique_queried_domains"].append(name)
            leftmost = name.split(".", 1)[0] if "." in name else name
            if len(leftmost) > 40:
                dns["suspicious_long_labels"].append(name)
    an = layer.an
    if an is not None:
        for rr in an if isinstance(an, list) else [an]:
            try:
                rname = getattr(rr, "rrname", b"").decode("latin-1", "replace").rstrip(".")
                qtype = getattr(rr, "type", 0)
                rdata = getattr(rr, "rdata", None)
                ttl = getattr(rr, "ttl", 0)
                rdata_s = rdata.decode("latin-1", "replace") if isinstance(rdata, bytes) else str(rdata)
                dns["responses"].append({"name": rname, "qtype": qtype,
                                         "rdata": rdata_s, "ttl": ttl})
                if qtype == 3:  # NXDOMAIN
                    dns["nx_domains"].append(rname)
            except Exception:
                continue


# ---------------------------------------------------------------------------
# TLS ClientHello (SNI / version / cipher)
# ---------------------------------------------------------------------------
def _dissect_tls_hello(payload: bytes, src: str, dst: str,
                       tls: Dict[str, Any]) -> bool:
    # Handshake: 1 byte type(0x16 = handshake) + 2 bytes version.
    if len(payload) < 6 or payload[0] != 0x16:
        return False
    version_map = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
                   0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
    ver = int.from_bytes(payload[1:3], "big")
    # Skip record header; handshake header: type(1)+len(3).
    if len(payload) < 9 or payload[5] != 0x01:  # 0x01 = ClientHello
        return False
    try:
        body = payload[9:]
        # client_version (2) + random (32)
        idx = 2 + 32
        sid_len = body[idx]
        idx += 1 + sid_len
        cs_len = int.from_bytes(body[idx:idx + 2], "big")
        idx += 2
        cipher_suites = list(body[idx:idx + cs_len])
        offered = f"0x{int.from_bytes(body[idx:idx+2], 'big'):04x}" if cs_len >= 2 else ""
        idx += cs_len
        cm_len = body[idx]
        idx += 1 + cm_len
        ext_total = int.from_bytes(body[idx:idx + 2], "big")
        idx += 2
        end = idx + ext_total
        sni = ""
        while idx + 4 <= end:
            etype = int.from_bytes(body[idx:idx + 2], "big")
            elen = int.from_bytes(body[idx + 2:idx + 4], "big")
            idx += 4
            if etype == 0 and elen >= 5 and idx + elen <= end:
                # server_name_list: list_len(2) + type(1) + name_len(2) + name
                inner = body[idx:idx + elen]
                name_type = inner[2] if len(inner) > 2 else 0
                if name_type == 0:
                    nl = int.from_bytes(inner[3:5], "big")
                    sni = _dec(inner[5:5 + nl])
            idx += elen
        hs = {
            "src": src, "dst": dst,
            "sni": sni, "version": version_map.get(ver, f"0x{ver:04x}"),
            "cipher_suite": offered or None,
            "cipher_count": len(cipher_suites),
        }
        tls["handshakes"].append(hs)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# DHCP (scapy BOOTP/DHCP)
# ---------------------------------------------------------------------------
def _dissect_dhcp(pkt, dhcp: Dict[str, Any]) -> None:
    try:
        from scapy.all import BOOTP, DHCP
    except Exception:
        return
    bootp = _scapy(pkt, BOOTP)
    if bootp is None:
        return
    opts: Dict[int, Any] = {}
    dhcp_layer = _scapy(pkt, DHCP)
    for o in dhcp_layer.options if dhcp_layer else []:
        if isinstance(o, tuple) and len(o) >= 2:
            opts[o[0]] = o[1]
    # 53 = message type (1 discover, 3 request, 2 offer, 5 ack)
    if opts.get(53) in (2, 5):  # offer/ack -> assigned IP in yiaddr
        lease = {
            "mac": getattr(bootp, "chaddr", "")[:17] or "",
            "ip": getattr(bootp, "yiaddr", "") or "",
            "hostname": opts.get(12, ""),
            "vendor_class": opts.get(60, ""),
        }
        if isinstance(lease["hostname"], bytes):
            lease["hostname"] = _dec(lease["hostname"])
        if isinstance(lease["vendor_class"], bytes):
            lease["vendor_class"] = _dec(lease["vendor_class"])
        dhcp["leases"].append(lease)


# ---------------------------------------------------------------------------
# ARP / ICMP (scapy layers)
# ---------------------------------------------------------------------------
def _dissect_arp(pkt, arp: Dict[str, Any]) -> None:
    try:
        from scapy.all import ARP
    except Exception:
        return
    a = _scapy(pkt, ARP)
    if a is None:
        return
    op = int(a.op)
    if op == 1:  # who-has
        arp["requests"].append({"src_mac": a.hwsrc, "src_ip": a.psrc,
                                "target_ip": a.pdst})
        arp["mac_ip_map"].setdefault(a.hwsrc, a.psrc)
        if a.psrc == a.pdst:
            arp["gratuitous"].append(a.psrc)
    elif op == 2:  # is-at
        arp["mac_ip_map"].setdefault(a.hwsrc, a.psrc)


def _dissect_icmp(pkt, src: str, dst: str, icmp: Dict[str, Any]) -> None:
    try:
        from scapy.all import ICMP
    except Exception:
        return
    i = _scapy(pkt, ICMP)
    if i is None:
        return
    t = int(i.type)
    if t == 8:  # echo request
        icmp["echo_pairs"].append({"src": src, "dst": dst,
                                   "seq": int(i.seq), "type": "request"})
    elif t == 0:  # echo reply
        icmp["echo_pairs"].append({"src": src, "dst": dst,
                                   "seq": int(i.seq), "type": "reply"})
    elif t == 3:  # unreachable
        icmp["unreachables"].append({"src": src, "dst": dst,
                                     "code": int(i.code)})


# ---------------------------------------------------------------------------
# SSH / IRC / IMAP / POP3 (lightweight text parsing)
# ---------------------------------------------------------------------------
_SSH_BANNER_RE = re.compile(rb"SSH-[\d.]*-[\w.-]+")


def _dissect_ssh(payload: bytes, src: str, dst: str,
                 ssh_sessions: Dict[Tuple[str, str], Dict[str, Any]]) -> None:
    m = _SSH_BANNER_RE.search(payload)
    if not m:
        return
    key = (src, dst)
    s = ssh_sessions.setdefault(key, {
        "src": src, "dst": dst, "duration_s": None, "bytes_transferred": 0,
        "key_exchange_algo": None,
    })
    s["key_exchange_algo"] = _dec(m.group(0))


def _dissect_irc(payload: bytes, irc: Dict[str, Any]) -> None:
    text = _dec(payload)
    for line in text.splitlines():
        m = re.match(r"^:(\S+)\s+(NICK)\s+(\S+)", line)
        if m:
            irc["nick"] = m.group(3)
            continue
        m = re.match(r"^:\S+\s+(JOIN)\s+(#\S+)", line)
        if m:
            irc["channels_joined"].append(m.group(2))
            continue
        m = re.match(r"^:\S+\s+(PRIVMSG)\s+#\S+\s+:(.+)$", line)
        if m:
            if len(irc["messages_preview"]) < 10:
                irc["messages_preview"].append(m.group(2)[:200])


def _dissect_mail_protocol(payload: bytes, proto: str,
                           carrier: Dict[str, Any]) -> None:
    text = _dec(payload)
    for line in text.splitlines():
        up = line.upper()
        if up.startswith("USER ") or up.startswith("LOGIN "):
            carrier.setdefault("credentials", []).append(
                {"protocol": proto, "username": line.split(" ", 1)[1].strip(),
                 "password": None})
        elif up.startswith("PASS "):
            creds = carrier.get("credentials")
            if creds:
                creds[-1]["password"] = line.split(" ", 1)[1].strip()


# ---------------------------------------------------------------------------
# SMB / NBNS (lightweight header parsing)
# ---------------------------------------------------------------------------
_SMB_CMD_NAMES = {
    0x72: "SMB_COM_NEGOTIATE", 0x73: "SMB_COM_SESSION_SETUP_ANDX",
    0x75: "SMB_COM_TREE_CONNECT_ANDX", 0x76: "SMB_COM_TREE_DISCONNECT",
    0x25: "SMB_COM_READ_ANDX", 0x2F: "SMB_COM_WRITE_ANDX",
    0x2E: "SMB_COM_OPEN_ANDX", 0x06: "SMB_COM_DELETE",
    0x32: "SMB_COM_RENAME", 0x2A: "SMB_COM_CLOSE",
    0xA0: "SMB_COM_CREATE_DIRECTORY", 0xA4: "SMB_COM_TRANSACTION",
    0x2D: "SMB_COM_QUERY_INFORMATION", 0x04: "SMB_COM_LOCKING_ANDX",
    0x2B: "SMB_COM_ECHO",
}


def _dissect_smb(payload: bytes, src: str, dst: str,
                 smb: Dict[str, Any]) -> None:
    if len(payload) < 4 or payload[:4] != b"\xffSMB":
        return
    cmd = payload[4]
    name = _SMB_CMD_NAMES.get(cmd, f"0x{cmd:02x}")
    # Best-effort share/UNC from ASCII runs in the payload.
    share = ""
    for m in re.finditer(rb"[\\/]?[A-Za-z0-9_.\- ]{3,40}", payload[8:]):
        s = _dec(m.group(0))
        if s.startswith(("\\", "/", "*")) or ":" in s or s.startswith("IPC"):
            share = s
            break
    smb["commands"].append({"src": src, "dst": dst, "command": name,
                            "filename": share or None, "share": share or None})


_NBNS_NAME_CHARS = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 -!$%&'()*+,-./:;<=>?@[]^_`{|}~"


def _dissect_nbns(payload: bytes, src_ip: str, nbns: Dict[str, Any]) -> None:
    if len(payload) < 13:
        return
    name_field = payload[13:45]
    if len(name_field) != 32:
        return
    try:
        raw = binascii.unhexlify(name_field)
        name = "".join(chr(c) if 32 <= c < 127 else "." for c in raw).rstrip("\x00 .")
    except Exception:
        name = ""
    if not name:
        return
    # NetBIOS name service messages: opcode in first byte (0x10=registration
    # query, 0x11=name query, 0x00=query, 0x20=registration response).
    op = payload[0]
    if op in (0x10, 0x01, 0x00):
        nbns["queries"].append({"name": name, "src_ip": src_ip})
    elif op == 0x11:
        nbns["registrations"].append({"name": name, "ip": src_ip})


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------
def dissect_packets(packets: List[Any]) -> Dict[str, Any]:
    """Walk every PacketMetadata once and return the full dissection dict.

    Keys: http, smtp, ftp, dns, tls, dhcp, arp, icmp, ssh, smb, nbns,
    imap, pop3, irc, raw, skipped.
    """
    d: Dict[str, Any] = {
        "http": {"requests": [], "transferred_files": [], "credentials": []},
        "smtp": {"sessions": [], "attachments": [], "credentials": []},
        "ftp": {"username": None, "password": None, "commands": [],
                "transferred_files": []},
        "dns": {"queries": [], "responses": [], "nx_domains": [],
                "unique_queried_domains": [], "suspicious_long_labels": []},
        "tls": {"handshakes": [], "certificates": [], "self_signed": []},
        "dhcp": {"leases": []},
        "arp": {"requests": [], "gratuitous": [], "mac_ip_map": {}},
        "icmp": {"echo_pairs": [], "unreachables": [], "large_payloads": []},
        "ssh": {"sessions": []},
        "smb": {"commands": [], "shares_accessed": []},
        "nbns": {"registrations": [], "queries": []},
        "imap": {"credentials": [], "email_count": 0},
        "pop3": {"credentials": [], "email_count": 0},
        "irc": {"nick": None, "channels_joined": [], "messages_preview": []},
        "raw": {"unknown_ports": {}, "payload_entropies": []},
        "skipped": 0,
    }
    if not packets:
        return d

    # Per-conversation SMTP session builder (merge segments into one).
    smtp_conv: Dict[Tuple[str, str], Dict[str, Any]] = {}
    # Per-flow SSH session builder.
    ssh_flows: Dict[Tuple[str, str], Dict[str, Any]] = {}
    entropy_accum: Dict[int, List[float]] = defaultdict(list)

    for pkt in packets:
        payload = getattr(pkt, "payload", b"") or b""
        src = getattr(pkt, "src_ip", None) or "?"
        dst = getattr(pkt, "dst_ip", None) or "?"
        sport = getattr(pkt, "src_port", None)
        dport = getattr(pkt, "dst_port", None)
        proto = (getattr(pkt, "protocol", None) or "").upper()
        plen = len(payload)

        try:
            # ---- ARP / ICMP (scapy layers) ----
            if proto == "ARP":
                _dissect_arp(pkt, d["arp"])
                continue
            if proto == "ICMP":
                _dissect_icmp(pkt, src, dst, d["icmp"])
                if plen > 64:
                    d["icmp"]["large_payloads"].append(
                        f"{src} -> {dst} payload {plen}B")
                continue

            # ---- UDP services ----
            if proto == "UDP":
                if dport == _DNS_PORT or sport == _DNS_PORT:
                    _dissect_dns_packet(pkt, d["dns"], src)
                elif dport in _DHCP_PORTS or sport in _DHCP_PORTS:
                    _dissect_dhcp(pkt, d["dhcp"])
                elif dport in _NBNS_PORTS or sport in _NBNS_PORTS:
                    _dissect_nbns(payload, src, d["nbns"])
                elif not payload:
                    continue
                else:
                    if dport and dport not in _KNOWN_PORTS:
                        d["raw"]["unknown_ports"][dport] = \
                            d["raw"]["unknown_ports"].get(dport, 0) + 1
                        entropy_accum[dport].append(_shannon_entropy(payload))
                continue

            # ---- TCP services ----
            if proto != "TCP":
                if payload and dport and dport not in _KNOWN_PORTS:
                    d["raw"]["unknown_ports"][dport] = \
                        d["raw"]["unknown_ports"].get(dport, 0) + 1
                    entropy_accum[dport].append(_shannon_entropy(payload))
                continue
            if not payload:
                continue

            # TLS detection first (443 etc.) — opaque body.
            if (dport in _TLS_PORTS or sport in _TLS_PORTS) \
                    and payload[0] == 0x16:
                if _dissect_tls_hello(payload, src, dst, d["tls"]):
                    continue  # handshake consumed

            if dport in _HTTP_PORTS or sport in _HTTP_PORTS:
                entry = _dissect_http(payload, src, dst, dport or 0,
                                      d["http"]["transferred_files"],
                                      d["http"]["credentials"])
                if entry:
                    d["http"]["requests"].append(entry)
                    continue
            if dport in _SMTP_PORTS or sport in _SMTP_PORTS:
                key = (min(src, dst), max(src, dst))
                sess = smtp_conv.setdefault(key, {
                    "src": src, "dst": dst, "mail_from": None, "rcpt_to": [],
                    "subject": None, "auth_username": None,
                    "auth_password": None, "attachments": [],
                    "body_preview": None, "_auth_mode": None,
                    "_auth_step": None,
                })
                _dissect_smtp(payload, src, dst, sess)
                continue
            if dport in _FTP_PORTS or sport in _FTP_PORTS:
                _dissect_ftp(payload, d["ftp"])
                continue
            if dport in _SSH_PORTS or sport in _SSH_PORTS:
                _dissect_ssh(payload, src, dst, ssh_flows)
                continue
            if dport in _IRC_PORTS or sport in _IRC_PORTS:
                _dissect_irc(payload, d["irc"])
                continue
            if dport in _IMAP_PORTS or sport in _IMAP_PORTS:
                _dissect_mail_protocol(payload, "imap", d["imap"])
                continue
            if dport in _POP3_PORTS or sport in _POP3_PORTS:
                _dissect_mail_protocol(payload, "pop3", d["pop3"])
                continue
            if dport in _SMB_PORTS or sport in _SMB_PORTS:
                _dissect_smb(payload, src, dst, d["smb"])
                continue
            if dport in _AIM_PORTS or sport in _AIM_PORTS:
                continue  # OSCAR/AIM is binary; covered by im flag, no fields

            # Unknown TCP port.
            if dport and dport not in _KNOWN_PORTS:
                d["raw"]["unknown_ports"][dport] = \
                    d["raw"]["unknown_ports"].get(dport, 0) + 1
                entropy_accum[dport].append(_shannon_entropy(payload))
        except Exception:
            d["skipped"] += 1
            continue

    # ---- Finalise ----
    for key, sess in smtp_conv.items():
        for k in ("_auth_mode", "_auth_step"):
            sess.pop(k, None)
        d["smtp"]["sessions"].append(sess)
        if sess.get("auth_username"):
            d["smtp"]["credentials"].append({
                "username": sess["auth_username"],
                "password": sess.get("auth_password"),
                "protocol": "smtp",
            })
        for a in sess.get("attachments") or []:
            d["smtp"]["attachments"].append(a)

    d["smtp"]["sessions"].sort(key=lambda s: (s.get("src") or "", s.get("dst") or ""))
    for s in ssh_flows.values():
        d["ssh"]["sessions"].append(s)
    d["ssh"]["sessions"].sort(key=lambda s: (s.get("src") or "", s.get("dst") or ""))

    d["dns"]["unique_queried_domains"] = list(dict.fromkeys(
        d["dns"]["unique_queried_domains"]))
    d["dns"]["suspicious_long_labels"] = list(dict.fromkeys(
        d["dns"]["suspicious_long_labels"]))
    d["dns"]["nx_domains"] = list(dict.fromkeys(d["dns"]["nx_domains"]))

    d["smb"]["shares_accessed"] = list(dict.fromkeys(
        c["share"] for c in d["smb"]["commands"] if c.get("share")))

    d["arp"]["mac_ip_map"] = dict(d["arp"]["mac_ip_map"])

    # Payload entropies for unknown ports (high avg = encrypted/compressed).
    for port, vals in sorted(entropy_accum.items()):
        if vals:
            d["raw"]["payload_entropies"].append({
                "port": port, "avg_entropy": round(
                    sum(vals) / len(vals), 3),
            })

    d["imap"]["email_count"] = len(d["imap"]["credentials"])
    d["pop3"]["email_count"] = len(d["pop3"]["credentials"])

    return d


__all__ = ["dissect_packets"]
