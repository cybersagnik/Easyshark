"""
PayloadAnalyzer — string + file extraction utilities.

Mirrors the legacy analyzer for backwards compatibility with the brief.
New callers should prefer the tool-calling loop in ai.explainer, which
calls tool_extract_strings / tool_extract_files from ai.tool_registry.
"""
from __future__ import annotations

import base64
import hashlib
import io
import logging
import re
import zipfile
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


_PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")
_MAGIC = [
    (b"PK\x03\x04", "ZIP/DOCX"),
    (b"\xd0\xcf\x11\xe0", "OLE/DOC"),
    (b"%PDF", "PDF"),
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


def extract_strings(packets, min_length: int = 6) -> List[Tuple[int, str]]:
    """Walk every packet's payload; yield (pkt_index, printable_string)."""
    out: List[Tuple[int, str]] = []
    rx = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    for pkt in packets:
        payload = getattr(pkt, "payload", b"") or b""
        for m in rx.finditer(payload):
            out.append((getattr(pkt, "index", 0), m.group(0).decode("latin-1")))
    return out


def _md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def _peek_docx(blob: bytes) -> str:
    """Best-effort: pull <w:t> text out of word/document.xml in a .docx blob."""
    try:
        z = zipfile.ZipFile(io.BytesIO(blob))
        for name in z.namelist():
            if name.endswith("document.xml"):
                xml = z.read(name).decode("utf-8", "replace")
                texts = re.findall(r"<w:t[^>]*>(.*?)</w:t>", xml, re.DOTALL)
                return " ".join(t for t in texts if t.strip())[:1500]
    except Exception:
        return ""
    return ""


def extract_transferred_files(packets, min_size: int = 64) -> List[Dict[str, Any]]:
    """Carve files from TCP payloads via magic-byte detection. Returns
    one dict per unique carved file (metadata only)."""
    return [e for e in _carve(packets, min_size)]


def extract_transferred_files_blobs(packets,
                                   min_size: int = 64,
                                   max_blob: int = 5_000_000
                                   ) -> List[Dict[str, Any]]:
    """Like :func:`extract_transferred_files` but each entry also contains
    the carved ``data`` blob. Use this when you actually want to write
    the file to disk."""
    out: List[Dict[str, Any]] = []
    for entry in _carve(packets, min_size):
        idx = entry["source_pkt"]
        for pkt in packets:
            if getattr(pkt, "index", -1) != idx:
                continue
            payload = getattr(pkt, "payload", b"") or b""
            start = payload.find(bytes.fromhex(entry["magic_hex"]))
            if start < 0:
                break
            entry["data"] = payload[start:start + max_blob]
            break
        out.append(entry)
    return out


def _carve(packets, min_size: int = 64) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen: set = set()
    payloads: List[Tuple[int, bytes]] = []
    for pkt in packets:
        payload = getattr(pkt, "payload", b"") or b""
        if not payload:
            continue
        payloads.append((getattr(pkt, "index", 0), payload))
        for magic, fmt in _MAGIC:
            idx = payload.find(magic)
            if idx < 0:
                continue
            blob = payload[idx:idx + 5_000_000]
            if len(blob) < min_size:
                continue
            md5 = _md5(blob)
            if md5 in seen:
                continue
            seen.add(md5)
            entry = {
                "filename": f"carved_{len(out):03d}.{fmt.lower().replace('/', '_').replace(' ', '_')}",
                "format": fmt,
                "size": len(blob),
                "md5": md5,
                "magic_hex": magic.hex(),
                "source_pkt": getattr(pkt, "index", 0),
                "data": blob,
            }
            text = _peek_docx(blob) if fmt == "ZIP/DOCX" else ""
            if text:
                entry["text_preview"] = text
            out.append(entry)
    flows: Dict[Tuple, bytes] = {}
    for pkt in packets:
        key = _flow_key_of(pkt)
        if not key:
            continue
        ckey = _canonical_flow_key(key)
        flows.setdefault(ckey, b"")
        flows[ckey] += getattr(pkt, "payload", b"") or b""
    for key, agg in flows.items():
        covered_ranges: List[Tuple[int, int]] = []
        for magic, fmt in _MAGIC:
            pos = 0
            while True:
                hit = agg.find(magic, pos)
                if hit < 0:
                    break
                if fmt == "ZIP/DOCX":
                    end = agg.find(b"PK\x05\x06", hit)
                    if end >= 0:
                        blob = agg[hit:end + 22]
                    else:
                        blob = agg[hit:hit + 5_000_000]
                else:
                    blob = agg[hit:hit + 5_000_000]
                pos = hit + len(magic)
                if len(blob) < min_size:
                    continue
                if any(c[0] <= hit < c[1] or c[0] < hit + len(blob) <= c[1] for c in covered_ranges):
                    continue
                md5 = _md5(blob)
                if md5 in seen:
                    continue
                seen.add(md5)
                covered_ranges.append((hit, hit + len(blob)))
                entry = {
                    "filename": f"carved_{len(out):03d}.{fmt.lower().replace('/', '_').replace(' ', '_')}",
                    "format": fmt,
                    "size": len(blob),
                    "md5": md5,
                    "magic_hex": magic.hex(),
                    "source_pkt": str(key),
                    "data": blob,
                }
                text = _peek_docx(blob) if fmt == "ZIP/DOCX" else ""
                if text:
                    entry["text_preview"] = text
                out.append(entry)
    return out


def _flow_key_of(pkt):
    """Safe accessor: returns pkt.flow_key (property) or None if not set."""
    return getattr(pkt, "flow_key", None)


def _canonical_flow_key(key: Tuple) -> Tuple:
    """Make bidirectional flow keys match: ('TCP', 'a', 1, 'b', 2) and
    ('TCP', 'b', 2, 'a', 1) collapse to the same key."""
    proto, a_ip, a_port, b_ip, b_port = key
    if (a_ip, a_port) <= (b_ip, b_port):
        return (proto, a_ip, a_port, b_ip, b_port)
    return (proto, b_ip, b_port, a_ip, a_port)


def decode_smtp_auth_credentials(packets) -> List[Dict[str, Any]]:
    """Best-effort: find SMTP AUTH LOGIN / AUTH PLAIN exchanges in raw
    packet bytes. Returns one dict per decoded credential."""
    creds: List[Dict[str, Any]] = []
    flows: Dict[Tuple, bytes] = {}
    # Aggregate per-flow payloads (5-tuple) using canonical key so
    # bidirectional flows (client -> server + server -> client) collapse.
    for pkt in packets:
        key = _flow_key_of(pkt)
        if not key:
            continue
        ckey = _canonical_flow_key(key)
        flows.setdefault(ckey, b"")
        flows[ckey] += getattr(pkt, "payload", b"") or b""

    for key, payload in flows.items():
        if b"AUTH LOGIN" in payload:
            # Walk the AUTH LOGIN handshake. The server sends two 334
            # prompts (one for username, one for password); the client
            # answers each with a base64 line. Real servers use the
            # standard prompts "VXNlcm5hbWU6" / "UGFzc3dvcmQ6" but
            # some servers put the user directly into the 334 prompt
            # (treat that as the user when no client reply is found).
            auth_pos = payload.find(b"AUTH LOGIN")
            section = payload[auth_pos:]
            prompts = re.findall(rb"334\s+(\S+)", section)
            if len(prompts) >= 2:
                user: str = ""
                pwd: str = ""
                # Try to decode the first prompt
                try:
                    first_decoded = base64.b64decode(prompts[0]).decode("utf-8", "replace").strip()
                except Exception:
                    first_decoded = ""
                if first_decoded in ("Username:", "Password:"):
                    # Standard prompts: look for the client reply
                    # (the next non-334 base64 line).
                    p1 = b"334 " + prompts[0]
                    after = section.split(p1, 1)[1].lstrip(b"\r\n")
                    # Skip lines that look like server prompts.
                    lines = [ln.strip() for ln in after.split(b"\r\n")]
                    for ln in lines:
                        if ln.startswith(b"334 "):
                            continue
                        if not ln:
                            continue
                        try:
                            decoded = base64.b64decode(ln).decode("utf-8", "replace")
                            if decoded.strip() in ("Username:", "Password:"):
                                continue
                            user = decoded
                        except Exception:
                            user = ln.decode("utf-8", "replace")
                        break
                    # Now look for the next 334 (the password prompt) and
                    # the line after that (the password answer).
                    p2_idx = section.find(b"334 ", section.find(p1) + len(p1))
                    if p2_idx >= 0:
                        after2 = section[p2_idx + 4:].lstrip(b"\r\n")
                        for ln in after2.split(b"\r\n"):
                            ln = ln.strip()
                            if not ln or ln.startswith(b"334 "):
                                continue
                            try:
                                decoded = base64.b64decode(ln).decode("utf-8", "replace")
                                if decoded.strip() in ("Username:", "Password:"):
                                    continue
                                pwd = decoded
                            except Exception:
                                pwd = ln.decode("utf-8", "replace")
                            break
                else:
                    # First 334 prompt itself carries the user (decoded).
                    user = first_decoded
                    # The second 334 is the password prompt; the next
                    # base64 line is the password.
                    p2 = b"334 " + prompts[1]
                    pwd_section = section.split(p2, 1)
                    if len(pwd_section) == 2:
                        pwd_line = pwd_section[1].lstrip(b"\r\n").split(b"\r\n", 1)[0].strip()
                        try:
                            pwd = base64.b64decode(pwd_line).decode("utf-8", "replace")
                        except Exception:
                            pwd = pwd_line.decode("utf-8", "replace")
                if user or pwd:
                    creds.append({
                        "flow": str(key), "method": "AUTH LOGIN",
                        "user": user, "password": pwd,
                    })
                    continue
        if b"AUTH PLAIN" in payload:
            m = re.search(rb"AUTH PLAIN\r?\n\s*(\S+)", payload)
            if m:
                try:
                    raw = base64.b64decode(m.group(1))
                    parts = raw.split(b"\x00")
                    if len(parts) >= 3:
                        creds.append({
                            "flow": str(key), "method": "AUTH PLAIN",
                            "user": parts[-2].decode("utf-8", "replace"),
                            "password": parts[-1].decode("utf-8", "replace"),
                        })
                except Exception:
                    pass
    return creds


def parse_smtp_attachments(packets, include_data: bool = False) -> List[Dict[str, Any]]:
    """Walk SMTP DATA payloads; extract MIME multipart attachments.

    ``include_data=True`` adds the raw decoded ``data`` bytes per attachment
    so callers can write the file to disk (used by the extract_embedded_media
    and extract-emails capabilities)."""
    out: List[Dict[str, Any]] = []
    flows: Dict[Tuple, bytes] = {}
    for pkt in packets:
        key = _flow_key_of(pkt)
        if not key:
            continue
        flows.setdefault(key, b"")
        flows[key] += getattr(pkt, "payload", b"") or b""
    seen: set = set()
    for key, payload in flows.items():
        if b"Content-Type:" not in payload or b"multipart" not in payload:
            continue
        boundary_m = re.search(rb'boundary="?([^\"\r\n;]+)"?', payload)
        if not boundary_m:
            continue
        boundary = b"--" + boundary_m.group(1)
        for part in payload.split(boundary):
            if b"Content-Disposition" not in part:
                continue
            fn_m = re.search(rb'filename="?([^"\r\n;]+)"?', part)
            if not fn_m:
                continue
            filename = fn_m.group(1).decode("utf-8", "replace")
            body_split = re.split(rb"\r?\n\r?\n", part, maxsplit=1)
            if len(body_split) < 2:
                continue
            body = body_split[1].rstrip(b"\r\n-")
            cte = re.search(rb"Content-Transfer-Encoding:\s*(\S+)", part, re.IGNORECASE)
            if cte and cte.group(1).lower() == b"base64":
                body = re.sub(rb"\s+", b"", body)
                body = body.rstrip(b"=")
                pad = (-len(body)) % 4
                try:
                    body = base64.b64decode(body + b"=" * pad)
                except Exception:
                    pass
            md5 = _md5(body)
            if md5 in seen:
                continue
            seen.add(md5)
            text = ""
            if filename.lower().endswith((".txt", ".html", ".xml")):
                text = body.decode("utf-8", "replace")[:1000]
            elif filename.lower().endswith(".docx"):
                text = _peek_docx(body)
            text = re.sub(r"\s+", " ", text).strip()
            media_md5s: List[str] = []
            media_names: List[str] = []
            if filename.lower().endswith((".docx",)):
                try:
                    zf = zipfile.ZipFile(io.BytesIO(body))
                    for name in zf.namelist():
                        if "media" in name.lower() or name.lower().endswith(
                                (".png", ".jpg", ".jpeg", ".emf", ".wmf", ".bmp", ".gif")):
                            media_md5s.append(_md5(zf.read(name)))
                            media_names.append(name)
                except Exception:
                    pass
            entry = {
                "flow": str(key),
                "filename": filename,
                "size": len(body),
                "md5": md5,
                "text": text,
                "media_md5s": media_md5s,
                "media_names": media_names,
            }
            if include_data:
                entry["data"] = body
            out.append(entry)
    return out


def summarize_payloads(packets) -> Dict[str, Any]:
    """Build the legacy single-prompt summary dict."""
    strings = extract_strings(packets)
    files = extract_transferred_files(packets)
    string_records = [{"pkt": idx, "s": s} for idx, s in strings]
    file_records = files
    smtp_auth = decode_smtp_auth_credentials(packets)
    email_attachments = parse_smtp_attachments(packets)
    return {
        "extracted_strings": string_records,
        "extracted_files": file_records,
        "file_count": len(files),
        "string_count": len(strings),
        "smtp_auth": smtp_auth,
        "email_attachments": email_attachments,
        "smtp_auth_count": len(smtp_auth),
        "attachment_count": len(email_attachments),
    }
