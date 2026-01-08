"""
PCAP file loader with lazy loading support.

This loader now supports an opt-in indexed mode using `IndexedPCAPLoader`
which builds a lightweight offset/index file and returns fast metadata
objects on demand. By default behaviour is unchanged (scapy-based full
packet reads); enable `use_index=True` to accelerate large PCAPs.
"""
from scapy.all import PcapReader, Packet
from pathlib import Path
from typing import List, Iterator, Optional
import logging

from .indexed_loader import IndexedPCAPLoader
from .packet_metadata import PacketMetadata

logger = logging.getLogger(__name__)


class PCAPLoader:
    def __init__(self, pcap_path: str, use_index: bool = False, index_path: Optional[str] = None):
        self.pcap_path = Path(pcap_path)
        self.packets: List[Packet] = []
        self._loaded = False
        self.use_index = use_index
        self.index_path = index_path
        self._index_loader: Optional[IndexedPCAPLoader] = None
        
    def load(self) -> List:
        """Load all packets from PCAP file.

        Returns a list of Scapy `Packet` objects when `use_index` is False
        (default). When `use_index` is True the method returns a list of
        `PacketMetadata` objects populated from the fast index (much faster
        and lower memory use). Use `get_packet_bytes()` to fetch raw bytes
        for a specific index if needed.
        """
        if self._loaded:
            return self.packets

        if not self.use_index:
            logger.info(f"Loading PCAP (full decode): {self.pcap_path}")
            try:
                with PcapReader(str(self.pcap_path)) as reader:
                    self.packets = [pkt for pkt in reader]
                self._loaded = True
                logger.info(f"Loaded {len(self.packets)} packets")
                return self.packets
            except Exception as e:
                logger.error(f"Failed to load PCAP: {e}")
                raise
        else:
            # Use indexed loader for fast metadata-only load
            logger.info(f"Loading PCAP (indexed mode): {self.pcap_path}")
            self._index_loader = IndexedPCAPLoader(str(self.pcap_path))
            if self.index_path and Path(self.index_path).exists():
                try:
                    self._index_loader.load_index(self.index_path)
                except Exception:
                    # fallback to building the index
                    self._index_loader.build_index(use_multiprocess=True)
            else:
                self._index_loader.build_index(use_multiprocess=True)

            # populate lightweight packet metadata list
            total = self._index_loader.get_packet_count()
            self.packets = [self._index_loader.get_packet_metadata(i) for i in range(total)]
            self._loaded = True
            logger.info(f"Indexed load complete: {len(self.packets)} metadata entries")
            return self.packets

    def iter_packets(self) -> Iterator:
        """Iterate packets without loading all into memory.

        In indexed mode yields `PacketMetadata` objects; otherwise yields
        Scapy `Packet` objects from streaming reader.
        """
        if not self.use_index:
            with PcapReader(str(self.pcap_path)) as reader:
                for pkt in reader:
                    yield pkt
        else:
            if not self._index_loader:
                self._index_loader = IndexedPCAPLoader(str(self.pcap_path))
                if self.index_path and Path(self.index_path).exists():
                    self._index_loader.load_index(self.index_path)
                else:
                    self._index_loader.build_index(use_multiprocess=True)

            for i in range(self._index_loader.get_packet_count()):
                yield self._index_loader.get_packet_metadata(i)

    def get_packet_count(self) -> int:
        """Get total packet count"""
        if self._loaded:
            return len(self.packets)
        if not self.use_index:
            count = 0
            for _ in self.iter_packets():
                count += 1
            return count
        else:
            if not self._index_loader:
                self._index_loader = IndexedPCAPLoader(str(self.pcap_path))
                if self.index_path and Path(self.index_path).exists():
                    self._index_loader.load_index(self.index_path)
                else:
                    self._index_loader.build_index(use_multiprocess=True)
            return self._index_loader.get_packet_count()