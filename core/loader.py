"""
PCAP loader — reads .pcap and .pcapng files into a list of scapy packets.

FROZEN behaviour (per brief §1): minimal interface — load() -> list[Packets].
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Any

logger = logging.getLogger(__name__)


class PCAPLoader:
    """Wrap scapy's PcapReader / rdpcap with friendly error messages."""

    def __init__(self, pcap_path: str):
        self.pcap_path = Path(pcap_path)
        if not self.pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
        if self.pcap_path.stat().st_size == 0:
            raise ValueError(f"PCAP file is empty: {pcap_path}")

    def load(self) -> List[Any]:
        """Return the full list of scapy packets. Empty list on error."""
        try:
            from scapy.all import rdpcap
            logger.info("Loading PCAP: %s", self.pcap_path)
            packets = list(rdpcap(str(self.pcap_path)))
            logger.info("Loaded %d packets", len(packets))
            return packets
        except Exception as exc:
            logger.error("Failed to load PCAP %s: %s", self.pcap_path, exc)
            return []

    def iter_packets(self):
        """Memory-efficient iterator for large pcaps."""
        try:
            from scapy.all import PcapReader
            with PcapReader(str(self.pcap_path)) as reader:
                for pkt in reader:
                    yield pkt
        except Exception as exc:
            logger.error("Failed to iterate PCAP %s: %s", self.pcap_path, exc)
            return
