"""
PacketIndex — O(1) lookup table over the loaded packet list.

FROZEN behaviour (per brief §1): get(index) -> meta.
"""
from __future__ import annotations

from typing import Dict, List, Optional
from .packet_metadata import PacketMetadata


class PacketIndex:
    def __init__(self):
        self.packets: List[PacketMetadata] = []
        self._by_index: Dict[int, PacketMetadata] = {}

    def add_packet(self, meta: PacketMetadata) -> None:
        self.packets.append(meta)
        self._by_index[meta.index] = meta

    def get(self, index: int) -> Optional[PacketMetadata]:
        return self._by_index.get(index)

    def __len__(self) -> int:
        return len(self.packets)

    def __iter__(self):
        return iter(self.packets)
