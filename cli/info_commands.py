"""
info_commands.py — deterministic capture-introspection verbs (Phase 15, Task 3).
"""
from __future__ import annotations

import logging
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

from main import RESET, BOLD, DIM, CYAN, BRIGHT_CYAN, WHITE

logger = logging.getLogger(__name__)


def _md5(data: bytes) -> str:
    import hashlib
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


# Colour helpers for TUI tables
def header(*cols: str) -> str:
    """Table header row: BOLD + BRIGHT_CYAN, columns separated by │."""
    sep = CYAN + " │ " + RESET
    return BOLD + BRIGHT_CYAN + sep.join(cols) + RESET


def row(*cols: str, widths: Optional[List[int]] = None) -> str:
    """Table data row: columns separated by │.

    When ``widths`` is given the cells are padded to those widths so rows
    line up with the header (L20 — `session info`/`sessions` tables).
    """
    sep = CYAN + " │ " + RESET
    if widths is not None:
        padded = []
        for cell, width in zip(cols, widths):
            visible = len(str(cell))
            padded.append(str(cell) + " " * max(0, width - visible))
        return WHITE + sep.join(padded) + RESET
    return WHITE + sep.join(cols) + RESET


def _align(cells, widths) -> str:
    """Join cells into one row, padded to widths and separated by │,
    matching the header style (L15 — rows use the same separators as the
    header so the table reads as a grid)."""
    sep = CYAN + " │ " + RESET
    padded = []
    for cell, width in zip(cells, widths):
        visible = len(str(cell))
        padded.append(str(cell) + " " * max(0, width - visible))
    return sep.join(padded)


def _table(headers: List[str], data, max_rows: int = 20,
           cap_label: str = "…") -> str:
    """Render an aligned table (header + rows) with │ separators.

    - Column widths are computed from the header and all rows so every
      column lines up.
    - Rows beyond `max_rows` are dropped and a cap note appended
      (L15 — `ips`/`creds` rows were unbounded).
    """
    rows = list(data)
    truncated = len(rows) > max_rows
    rows = rows[:max_rows]
    widths = [len(h) for h in headers]
    for r in rows:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(str(cell)))
    lines = [header(*headers)]
    for i, r in enumerate(rows):
        c = WHITE if i % 2 == 0 else DIM
        lines.append(c + "  " + _align(r, widths) + RESET)
    if truncated:
        lines.append(DIM + f"  {cap_label} {len(rows)}+ more rows "
                            f"(use a capture filter to narrow)" + RESET)
    return "\n".join(lines)


def section(title: str) -> str:
    """Section header: BRIGHT_CYAN + BOLD."""
    return BOLD + BRIGHT_CYAN + f"── {title} ──" + RESET


def error(msg: str) -> str:
    from main import YELLOW
    return YELLOW + "⚠ " + msg + RESET


# --------------------------------------------------------------------------- #
# Handler                                                                     #
# --------------------------------------------------------------------------- #
class InfoCommandHandler:

    def __init__(self, shell):
        self.shell = shell

    def handle(self, line: str) -> Optional[str]:
        line = line.strip()
        if not line:
            return None
        parts = line.split(None, 1)
        verb = parts[0].lower()
        arg = (parts[1] if len(parts) > 1 else "").strip()
        table = {
            "protocols": self.cmd_protocols,
            "ips":       self.cmd_ips,
            "flows":     self.cmd_flows,
            "dns":       self.cmd_dns,
            "creds":     self.cmd_creds,
            "summary":   self.cmd_summary,
            "extract":   self.cmd_extract,
            "files":     self.cmd_extract,
        }
        fn = table.get(verb)
        if fn is None:
            return error(f"unknown info command: {verb}")
        try:
            return fn(arg)
        except Exception as exc:
            logger.error("info %s failed: %s", verb, exc, exc_info=True)
            return error(str(exc))

    def _triage(self) -> Dict[str, Any]:
        return getattr(self.shell, "triage", {}) or {}

    def _dissection(self) -> Dict[str, Any]:
        return getattr(self.shell, "dissection", {}) or {}

    def cmd_protocols(self, arg: str) -> str:
        t = self._triage()
        d = self._dissection()
        counts = t.get("protocol_counts") or {}
        active = t.get("active_protocols") or []
        if not counts:
            return "(no protocol data)"

        details: Dict[str, str] = {}
        if d:
            details["HTTP"] = f"{len(d.get('http', {}).get('requests', []))} requests"
            details["DNS"] = f"{len(d.get('dns', {}).get('queries', []))} queries"
            details["SMTP"] = f"{len(d.get('smtp', {}).get('sessions', []))} sessions"
            details["TLS"] = f"{len(d.get('tls', {}).get('handshakes', []))} handshakes"
            details["DHCP"] = f"{len(d.get('dhcp', {}).get('leases', []))} leases"
            details["SSH"] = f"{len(d.get('ssh', {}).get('sessions', []))} sessions"
            details["ARP"] = f"{len(d.get('arp', {}).get('requests', []))} requests"
            details["IRC"] = f"{len(d.get('irc', {}).get('messages_preview', []))} messages"

        lines = [section(f"Protocols — {self.shell.pcap_file}"), ""]
        data = []
        for proto in active:
            n = counts[proto]
            det = details.get(proto, "")
            data.append((proto, str(n), det))
        for proto in sorted(set(counts) - set(active)):
            data.append((proto, str(counts[proto]), ""))
        lines.append(_table(("Protocol", "Packets", "Detail"), data, max_rows=30))
        return "\n".join(lines)

    def cmd_ips(self, arg: str) -> str:
        t = self._triage()
        summary = t.get("ip_summary") or {}
        if not summary:
            return "(no IP summary)"
        rows = sorted(summary.items(),
                      key=lambda kv: -(kv[1].get("sent", 0) + kv[1].get("recv", 0)))
        lines = [section(f"IP Summary — {self.shell.pcap_file}"), ""]
        data = [(ip, str(info.get("sent", 0)), str(info.get("recv", 0)),
                 ", ".join(info.get("protocols", []))[:20])
                for ip, info in rows]
        lines.append(_table(("IP", "Sent", "Recv", "Protocols"), data,
                            max_rows=20))
        return "\n".join(lines)

    def cmd_flows(self, arg: str) -> str:
        t = self._triage()
        flows = self.shell.flow_engine.get_all_flows()
        conv = t.get("conversation_count", len(flows))
        rows = sorted(flows, key=lambda f: -getattr(f, "packet_count", 0))[:20]
        lines = [section(f"Flows — {self.shell.pcap_file}"), ""]
        lines.append(f"  Conversations: {conv} | Engine flows: {len(flows)}")
        lines.append("")
        data = [(f"{f.src_ip}:{f.src_port}", f"{f.dst_ip}:{f.dst_port}",
                 f.protocol, str(getattr(f, "packet_count", "?")))
                for f in rows]
        lines.append(_table(("Source", "Destination", "Proto", "Packets"), data))
        return "\n".join(lines)

    def cmd_dns(self, arg: str) -> str:
        d = self._dissection().get("dns", {})
        queries = d.get("queries", [])
        if not queries:
            return "(no DNS queries found)"
        lines = [section(f"DNS — {self.shell.pcap_file}"), ""]
        lines.append(f"  Queries: {len(queries)} | Responses: {len(d.get('responses', []))} | "
                     f"NXDOMAIN: {len(d.get('nx_domains', []))}")
        lines.append("")
        from core.sanitise import sanitise
        top = Counter()
        for q in queries:
            top[q["name"]] += 1
        data = [(f"{n}x", sanitise(name)) for name, n in top.most_common(15)]
        lines.append(_table(("Count", "Domain"), data, max_rows=15))
        if d.get("suspicious_long_labels"):
            lines.append("")
            lines.append(DIM + "  Suspicious long labels (possible tunneling):" + RESET)
            for name in d["suspicious_long_labels"][:10]:
                lines.append(DIM + f"    {sanitise(name)}" + RESET)
        return "\n".join(lines)

    def cmd_creds(self, arg: str) -> str:
        d = self._dissection()
        creds: List[Dict[str, Any]] = []
        for c in d.get("smtp", {}).get("credentials", []) or []:
            creds.append(c)
        for c in d.get("http", {}).get("credentials", []) or []:
            creds.append(c)
        for c in d.get("imap", {}).get("credentials", []) or []:
            creds.append(c)
        for c in d.get("pop3", {}).get("credentials", []) or []:
            creds.append(c)
        ftp = d.get("ftp", {})
        if ftp.get("username"):
            creds.append({"protocol": "ftp",
                          "username": ftp.get("username"),
                          "password": ftp.get("password")})
        if not creds:
            return "(no credentials found)"
        lines = [section(f"Credentials — {self.shell.pcap_file}"), ""]
        from core.sanitise import sanitise
        data = []
        for c in creds:
            proto = c.get("protocol", "?")
            user = sanitise(c.get("username", "?"))
            pw = sanitise(c.get("password") or "(none)")
            data.append((proto, user, pw))
        lines.append(_table(("Protocol", "Username", "Password"), data,
                            max_rows=20))
        return "\n".join(lines)

    def cmd_summary(self, arg: str) -> str:
        t = self._triage()
        d = self._dissection()
        pkts = self.shell.index.packets
        n = len(pkts)
        start = getattr(pkts[0], "timestamp", 0) if pkts else 0
        end = getattr(pkts[-1], "timestamp", start) if pkts else start
        duration = max(0.0, float(end - start))
        hosts = set()
        for p in pkts:
            if getattr(p, "src_ip", None):
                hosts.add(p.src_ip)
            if getattr(p, "dst_ip", None):
                hosts.add(p.dst_ip)
        counts = t.get("protocol_counts") or {}
        protocols = ", ".join(t.get("active_protocols") or list(counts))
        smtp_s = d.get("smtp", {}).get("sessions", [])
        files = d.get("http", {}).get("transferred_files", [])
        creds = d.get("smtp", {}).get("credentials", [])
        flags = {k: v for k, v in t.items()
                 if k in ("smtp", "im", "http", "tls", "dns_tunneling_suspect",
                          "ad_network", "docx_carved", "encrypted_heavy")}
        on = ", ".join(sorted(k for k, v in flags.items() if v))

        lines = [section(f"Capture Summary — {self.shell.pcap_file}"), ""]
        items = [
            ("Packets", str(n)),
            ("Duration", f"{duration:.1f}s"),
            ("Hosts", str(len(hosts))),
            ("Conversations", str(t.get("conversation_count", 0))),
            ("Protocols", protocols or "(none)"),
            ("SMTP sessions", f"{len(smtp_s)} (creds: {len(creds)})"),
            ("HTTP requests", str(len(d.get('http', {}).get('requests', [])))),
            ("HTTP files", str(len(files))),
            ("DNS queries", str(len(d.get('dns', {}).get('queries', [])))),
            ("TLS handshakes", str(len(d.get('tls', {}).get('handshakes', [])))),
            ("ARP requests", str(len(d.get('arp', {}).get('requests', [])))),
            ("Detected", on or "(none)"),
        ]
        lines.append(_table(("Field", "Value"), items, max_rows=30))
        return "\n".join(lines)

    def cmd_extract(self, arg: str) -> str:
        from ai.payload_analyzer import extract_transferred_files_blobs
        entries = extract_transferred_files_blobs(self.shell.get_packets())
        if not entries:
            return "(no file blobs to extract)"
        out_dir = Path.home() / ".easyshark" / "extracted"
        out_dir.mkdir(parents=True, exist_ok=True)
        saved = []
        seen_names = set()
        for entry in entries:
            data = entry.get("data", b"")
            if not data:
                continue
            raw = entry["filename"]
            name = Path(raw).name
            if not name or name in (".", "..") or "/" in name or "\\" in name:
                name = f"sanitised_{len(saved):03d}"
            base = name
            n = 1
            while name in seen_names or (out_dir / name).exists():
                stem, dot, ext = base.rpartition(".")
                if dot and len(ext) <= 8:
                    name = f"{stem}_{n}{dot}{ext}"
                else:
                    name = f"{base}_{n}"
                n += 1
            seen_names.add(name)
            target = out_dir / name
            target.write_bytes(data)
            saved.append(f"  {name}  ({len(data)} bytes, md5={entry['md5']})")
        if not saved:
            return "(no file blobs recovered)"
        return (f"Extracted {len(saved)} file(s) to {out_dir}:\n"
                + "\n".join(saved))
