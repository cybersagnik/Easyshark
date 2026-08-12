"""Deterministic ATT&CK mapping plus small Sigma/SPL export helpers."""
from __future__ import annotations

from typing import Any, Iterable

MAPPINGS = {
    "port scan": ("T1046", "Network Service Scanning"),
    "dns tunnel": ("T1071.004", "DNS"),
    "beacon": ("T1071", "Application Layer Protocol"),
    "c2": ("T1071", "Application Layer Protocol"),
    "exfil": ("T1041", "Exfiltration Over C2 Channel"),
    "arp spoof": ("T1557.002", "ARP Cache Poisoning"),
    "tls anomaly": ("T1573", "Encrypted Channel"),
}


def map_findings(findings: Iterable[Any]) -> list[dict[str, str]]:
    output = {}
    for finding in findings or []:
        text = " ".join(str(getattr(finding, name, finding)).lower()
                        for name in ("type", "rule_name", "message", "evidence"))
        for keyword, (technique_id, technique) in MAPPINGS.items():
            if keyword in text:
                output.setdefault(technique_id, {"id": technique_id,
                    "technique": technique, "evidence": str(getattr(finding, "evidence", text))})
    return list(output.values())


def sigma_rule(findings: Iterable[Any], title: str = "EasyShark network anomaly") -> dict[str, Any]:
    mapped = map_findings(findings)
    return {"title": title, "status": "experimental", "logsource": {"category": "network_traffic"},
            "detection": {"selection": {"easyshark.technique": [m["id"] for m in mapped]},
                          "condition": "selection"}, "tags": [f"attack.{m['id'].lower()}" for m in mapped]}


def sigma_yaml(findings: Iterable[Any], title: str = "EasyShark network anomaly") -> str:
    """Serialize the small Sigma schema without adding a YAML dependency."""
    rule = sigma_rule(findings, title)
    lines = [f"title: {rule['title']}", f"status: {rule['status']}",
             "logsource:", "  category: network_traffic", "detection:",
             "  selection:", "    easyshark.technique:"]
    lines.extend(f"      - {item}" for item in rule["detection"]["selection"]["easyshark.technique"])
    lines.extend(["  condition: selection", "tags:"])
    lines.extend(f"  - {item}" for item in rule["tags"])
    return "\n".join(lines) + "\n"


def spl_query(findings: Iterable[Any]) -> str:
    ids = [m["id"] for m in map_findings(findings)]
    return " | tstats count where index=network by src_ip,dst_ip,signature" + (
        " | search signature IN (" + ",".join(repr(i) for i in ids) + ")" if ids else "")


map_to_mitre = map_findings
generate_sigma = sigma_rule
generate_sigma_yaml = sigma_yaml
generate_spl = spl_query
