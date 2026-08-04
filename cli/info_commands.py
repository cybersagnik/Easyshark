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
    return hashlib.md5(data).hexdigest()


# Colour helpers for TUI tables
def header(*cols: str) -> str:
    """Table header row: BOLD + BRIGHT_CYAN, columns separated by │."""
    sep = CYAN + " │ " + RESET
    return BOLD + BRIGHT_CYAN + sep.join(cols) + RESET


def row(*cols: str) -> str:
    """Table data row: columns separated by │."""
    sep = CYAN + " │ " + RESET
    return WHITE + sep.join(cols) + RESET


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
        lines.append(header("Protocol", "Packets", "Detail"))
        for i, proto in enumerate(active):
            n = counts[proto]
            det = details.get(proto, "")
            c = WHITE if i % 2 == 0 else DIM
            lines.append(c + f"  {proto:<10} {n:>6}      {det}" + RESET)
        for i, proto in enumerate(sorted(set(counts) - set(active))):
            c = WHITE if (len(active) + i) % 2 == 0 else DIM
            lines.append(c + f"  {proto:<10} {counts[proto]:>6}" + RESET)
        return "\n".join(lines)

    def cmd_ips(self, arg: str) -> str:
        t = self._triage()
        summary = t.get("ip_summary") or {}
        if not summary:
            return "(no IP summary)"
        rows = sorted(summary.items(),
                      key=lambda kv: -(kv[1].get("sent", 0) + kv[1].get("recv", 0)))
        lines = [section(f"IP Summary — {self.shell.pcap_file}"), ""]
        lines.append(header("IP", "Sent", "Recv", "Protocols"))
        for i, (ip, info) in enumerate(rows):
            c = WHITE if i % 2 == 0 else DIM
            lines.append(
                c + f"  {ip:<18} {info.get('sent', 0):>9} {info.get('recv', 0):>9} "
                f"{', '.join(info.get('protocols', []))[:20]}" + RESET)
        return "\n".join(lines)

    def cmd_flows(self, arg: str) -> str:
        t = self._triage()
        flows = self.shell.flow_engine.get_all_flows()
        conv = t.get("conversation_count", len(flows))
        rows = sorted(flows, key=lambda f: -getattr(f, "packet_count", 0))[:20]
        lines = [section(f"Flows — {self.shell.pcap_file}"), ""]
        lines.append(f"  Conversations: {conv} | Engine flows: {len(flows)}")
        lines.append("")
        lines.append(header("Source", "Destination", "Proto", "Packets"))
        for i, f in enumerate(rows):
            c = WHITE if i % 2 == 0 else DIM
            lines.append(
                c + f"  {f.src_ip}:{f.src_port:<15} {f.dst_ip}:{f.dst_port:<15} "
                f"{f.protocol:<6} {getattr(f, 'packet_count', '?'):>6}" + RESET)
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
        lines.append(header("Count", "Domain"))
        top = Counter()
        for q in queries:
            top[q["name"]] += 1
        for i, (name, n) in enumerate(top.most_common(15)):
            c = WHITE if i % 2 == 0 else DIM
            lines.append(c + f"  {n:>5}x  {name}" + RESET)
        if d.get("suspicious_long_labels"):
            lines.append("")
            lines.append(DIM + "  Suspicious long labels (possible tunneling):" + RESET)
            for name in d["suspicious_long_labels"][:10]:
                lines.append(DIM + f"    {name}" + RESET)
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
        lines.append(header("Protocol", "Username", "Password"))
        for i, c in enumerate(creds):
            pw = c.get("password") or "(none)"
            proto = c.get("protocol", "?")
            user = c.get("username", "?")
            col = WHITE if i % 2 == 0 else DIM
            lines.append(col + f"  {proto:<10} {user:<25} {pw}" + RESET)
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
        for i, (label, val) in enumerate(items):
            c = WHITE if i % 2 == 0 else DIM
            lines.append(c + f"  {label:<18} {val}" + RESET)
        return "\n".join(lines)

    def cmd_extract(self, arg: str) -> str:
        from ai.payload_analyzer import extract_transferred_files_blobs
        entries = extract_transferred_files_blobs(self.shell.get_packets())
        if not entries:
            return "(no file blobs to extract)"
        out_dir = Path.home() / ".easyshark" / "extracted"
        out_dir.mkdir(parents=True, exist_ok=True)
        saved = []
        for entry in entries:
            data = entry.get("data", b"")
            if not data:
                continue
            fname = entry["filename"]
            target = out_dir / fname
            target.write_bytes(data)
            saved.append(f"  {fname}  ({len(data)} bytes, md5={entry['md5']})")
        if not saved:
            return "(no file blobs recovered)"
        return (f"Extracted {len(saved)} file(s) to {out_dir}:\n"
                + "\n".join(saved))
