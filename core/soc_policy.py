"""SOC asset materiality, adversary projection, and action safety policy."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


_NEXT = {
    "T1046": ("T1021", "Hunt for remote-service authentication and east-west connections."),
    "T1071": ("T1105", "Hunt for payload transfer from the same host or destination."),
    "T1071.004": ("T1105", "Hunt DNS peers for subsequent downloads and process telemetry."),
    "T1041": ("T1070", "Preserve evidence and hunt for log or artifact deletion."),
    "T1021": ("T1003", "Hunt the destination for credential access and new logons."),
}


class AssetPolicy:
    def __init__(self, path: Optional[str] = None):
        self.path = Path(path or os.environ.get("EASYSHARK_ASSET_POLICY", "")) if (path or os.environ.get("EASYSHARK_ASSET_POLICY")) else None
        self.data: Dict[str, Any] = {}
        if self.path and self.path.is_file():
            self.data = json.loads(self.path.read_text(encoding="utf-8"))

    def classify(self, asset: str) -> Dict[str, Any]:
        row = (self.data.get("assets") or {}).get(asset, {})
        criticality = str(row.get("criticality", "standard")).lower()
        weight = {"critical": 1.0, "high": .75, "standard": .35, "low": .1}.get(criticality, .35)
        return {"asset": asset, "criticality": criticality, "materiality": weight,
                "owner": row.get("owner", ""), "tags": row.get("tags", [])}


def adversary_projection(techniques: Iterable[Any]) -> List[Dict[str, str]]:
    out = []
    for item in techniques or []:
        technique_id = str(item.get("id", "") if isinstance(item, dict) else item).upper()
        if technique_id in _NEXT:
            next_id, hunt = _NEXT[technique_id]
            out.append({"observed": technique_id, "likely_next": next_id, "hunt": hunt})
    return out


class ResponsePolicy:
    """Three tiers: local reversible, approval-gated connector, prohibited."""
    LOCAL = {"tag", "watchlist", "snapshot"}
    GATED = {"isolate", "block", "disable-account", "quarantine"}
    PROHIBITED = {"delete", "wipe", "destroy", "ransom", "exfiltrate"}

    @classmethod
    def tier(cls, action: str) -> str:
        verb = (action.strip().split(None, 1) or [""])[0].lower()
        if verb in cls.LOCAL:
            return "local_reversible"
        if verb in cls.PROHIBITED:
            return "prohibited"
        return "approval_gated" if verb in cls.GATED else "approval_gated"

    @classmethod
    def expires_at(cls, ttl_seconds: int = 3600) -> float:
        return time.time() + max(60, min(int(ttl_seconds), 30 * 86400))
