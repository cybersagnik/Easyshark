"""
OutputFormatter — one-line packet summaries, section headers, etc.

FROZEN: formatter interface is consumed by the existing tests.
"""
from __future__ import annotations

from typing import Any, List, Optional


class OutputFormatter:
    def header(self, title: str) -> str:
        bar = "=" * len(title)
        return f"\n{title}\n{bar}"

    def packet_line(self, pkt) -> str:
        return pkt.short()

    def packet_list(self, packets, max_rows: int = 50) -> str:
        if not packets:
            return "(no packets match)"
        rows = [self.packet_line(p) for p in packets[:max_rows]]
        more = ""
        if len(packets) > max_rows:
            more = f"\n... ({len(packets) - max_rows} more)"
        return "\n".join(rows) + more

    def stats_block(self, stats: dict) -> str:
        lines = []
        lines.append(f"Total packets: {stats.get('total_packets', 0)}")
        lines.append(f"Total bytes:   {stats.get('total_bytes', 0)}")
        if stats.get("protocols"):
            lines.append("Protocols:")
            for proto, count in list(stats["protocols"].items())[:5]:
                lines.append(f"  - {proto}: {count}")
        if stats.get("top_src_ips"):
            lines.append("Top src IPs:")
            for ip, count in list(stats["top_src_ips"].items())[:5]:
                lines.append(f"  - {ip}: {count}")
        return "\n".join(lines)

    def alerts_block(self, alerts) -> str:
        if not alerts:
            return "(no alerts)"
        return "\n".join(a.short() for a in alerts[:50])

    def flows_block(self, flows) -> str:
        if not flows:
            return "(no flows)"
        return "\n".join(f.short() for f in flows[:50])

    def error(self, message: str) -> str:
        from main import YELLOW, RESET
        return YELLOW + "⚠ " + message + RESET
