"""Small evidence graph used to make autonomous claims traceable."""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any, Dict, Iterable, List


@dataclass
class EvidenceGraph:
    nodes: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    edges: List[Dict[str, str]] = field(default_factory=list)

    def node(self, node_id: str, kind: str, **data: Any) -> str:
        self.nodes.setdefault(node_id, {"id": node_id, "kind": kind, **data})
        return node_id

    def link(self, source: str, relation: str, target: str) -> None:
        self.edges.append({"source": source, "relation": relation, "target": target})

    def claim(self, claim_id: str, text: str, references: Iterable[str]) -> str:
        refs = [ref for ref in references if ref in self.nodes]
        self.node(claim_id, "claim", text=text, grounded=bool(refs),
                  references=refs)
        for ref in refs:
            self.link(claim_id, "supported_by", ref)
        return claim_id

    def as_dict(self) -> Dict[str, Any]:
        return {"nodes": list(self.nodes.values()), "edges": list(self.edges)}


def from_capture(packets=None, flows=None, alerts=None) -> EvidenceGraph:
    graph = EvidenceGraph()
    for index, packet in enumerate(packets or []):
        key = graph.node(f"packet:{index}", "packet", index=index,
                         protocol=getattr(packet, "protocol", None),
                         src_ip=getattr(packet, "src_ip", None),
                         dst_ip=getattr(packet, "dst_ip", None),
                         timestamp=getattr(packet, "timestamp", None))
        flow_key = getattr(packet, "flow_key", None)
        if flow_key:
            flow_id = graph.node(f"flow:{flow_key}", "flow", key=str(flow_key))
            graph.link(key, "part_of", flow_id)
    for index, flow in enumerate(flows or []):
        graph.node(f"flow:{index}", "flow", src_ip=getattr(flow, "src_ip", None),
                   dst_ip=getattr(flow, "dst_ip", None),
                   packet_count=getattr(flow, "packet_count", 0))
    for index, alert in enumerate(alerts or []):
        graph.node(f"alert:{index}", "alert", rule=getattr(alert, "rule_name", "?"),
                   message=getattr(alert, "message", ""))
    return graph


def references_from_evidence(texts: Iterable[str]) -> List[str]:
    """Extract only explicit packet/flow/alert references from evidence text."""
    refs = []
    for text in texts or []:
        value = str(text)
        refs.extend(f"packet:{n}" for n in re.findall(r"\b(?:packet|pkt)[ _#-]?(\d+)\b", value, re.I))
        refs.extend(f"flow:{n}" for n in re.findall(r"\bflow[ _#-]?(\d+)\b", value, re.I))
        refs.extend(f"alert:{n}" for n in re.findall(r"\balert[ _#-]?(\d+)\b", value, re.I))
    return list(dict.fromkeys(refs))
