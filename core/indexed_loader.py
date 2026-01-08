"""
Indexed PCAP loader: build a lightweight index of packet offsets and metadata
so the application can load only metadata quickly and fetch full packet bytes
or Scapy packets on demand. Uses the project's FastParser for cheap header parsing
and supports optional multiprocessing for parsing batches.
"""
import struct
import json
from pathlib import Path
from typing import List, Dict, Optional
from concurrent.futures import ProcessPoolExecutor
from .packet_metadata import PacketMetadata
from .fast_parser import FastParser
import time
import logging

logger = logging.getLogger(__name__)


class IndexedPCAPLoader:
    PCAP_GLOBAL_HDR_FMT = 'IHHiiii'  # magic, ver_major, ver_minor, thiszone, sigfigs, snaplen, network
    PCAP_PKT_HDR_FMT = 'IIII'  # ts_sec, ts_usec, incl_len, orig_len
    PCAP_GLOBAL_HDR_LEN = 24
    PCAP_PKT_HDR_LEN = 16

    def __init__(self, path: str):
        self.path = Path(path)
        self.index: List[Dict] = []  # list of dicts: {offset, ts, incl_len, orig_len, fast_parsed}
        self.network: Optional[int] = None
        self._indexed = False

    def _read_global_header(self, fh) -> None:
        gh = fh.read(self.PCAP_GLOBAL_HDR_LEN)
        if len(gh) < self.PCAP_GLOBAL_HDR_LEN:
            raise ValueError('File too small to be a pcap')

        # default assume native endianness; detect common magic
        magic = struct.unpack('I', gh[0:4])[0]
        # Accept both 0xa1b2c3d4 and 0xd4c3b2a1 (swapped)
        if magic == 0xa1b2c3d4:
            fmt = '>'  # big-endian
        elif magic == 0xd4c3b2a1:
            fmt = '<'  # little-endian
        else:
            # fallback: try little-endian
            fmt = '<'

        # parse fields with chosen endianness
        (magic, ver_major, ver_minor, thiszone, sigfigs, snaplen, network) = struct.unpack(fmt + 'IHHiiii', gh)
        self.network = network

    @staticmethod
    def _parse_packet_bytes(raw: bytes) -> Dict:
        try:
            return FastParser.quick_parse(raw)
        except Exception:
            return {'valid': False}

    def build_index(self, use_multiprocess: bool = False, batch_size: int = 2000, save_path: Optional[str] = None) -> None:
        """Build index by scanning the pcap and parsing headers with FastParser.

        - use_multiprocess: parse packets in worker processes (CPU-bound)
        - batch_size: number of packets to read before parsing/submitting
        """
        logger.info(f"Building index for {self.path} (multiprocess={use_multiprocess})")
        self.index = []
        start = time.time()
        with open(self.path, 'rb') as fh:
            self._read_global_header(fh)
            cur_index = 0
            batch = []  # tuples of (file_offset, ts, incl_len, orig_len, raw_bytes)

            while True:
                hdr = fh.read(self.PCAP_PKT_HDR_LEN)
                if not hdr or len(hdr) < self.PCAP_PKT_HDR_LEN:
                    break

                ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<' + self.PCAP_PKT_HDR_FMT, hdr)
                offset = fh.tell()
                raw = fh.read(incl_len)
                if len(raw) < incl_len:
                    break

                batch.append((offset, float(ts_sec) + float(ts_usec) / 1_000_000.0, incl_len, orig_len, raw))

                if len(batch) >= batch_size:
                    self._process_batch(batch, cur_index, use_multiprocess)
                    cur_index += len(batch)
                    batch = []

            if batch:
                self._process_batch(batch, cur_index, use_multiprocess)

        self._indexed = True
        elapsed = time.time() - start
        logger.info(f"Index built: {len(self.index)} packets in {elapsed:.2f}s")

        if save_path:
            self.save_index(save_path)

    def _process_batch(self, batch, start_index: int, use_multiprocess: bool):
        raws = [b[4] for b in batch]
        if use_multiprocess:
            with ProcessPoolExecutor() as ex:
                parsed = list(ex.map(self._parse_packet_bytes, raws))
        else:
            parsed = [self._parse_packet_bytes(r) for r in raws]

        for i, item in enumerate(batch):
            offset, ts, incl_len, orig_len, raw = item
            meta = {
                'index': start_index + i,
                'offset': offset,
                'timestamp': ts,
                'incl_len': incl_len,
                'orig_len': orig_len,
                'fast_parsed': parsed[i]
            }
            self.index.append(meta)

    def save_index(self, path: str) -> None:
        data = {'network': self.network, 'packets': self.index}
        Path(path).write_text(json.dumps(data))

    def load_index(self, path: str) -> None:
        raw = Path(path).read_text()
        data = json.loads(raw)
        self.network = data.get('network')
        self.index = data.get('packets', [])
        self._indexed = True

    def get_packet_count(self) -> int:
        if self._indexed:
            return len(self.index)
        # fallback: build index quickly without multiprocessing
        self.build_index(use_multiprocess=False, batch_size=2000)
        return len(self.index)

    def get_packet_bytes(self, idx: int) -> Optional[bytes]:
        if not self._indexed:
            self.build_index()
        if idx < 0 or idx >= len(self.index):
            return None
        meta = self.index[idx]
        with open(self.path, 'rb') as fh:
            fh.seek(meta['offset'])
            data = fh.read(meta['incl_len'])
            return data

    def get_packet_metadata(self, idx: int) -> Optional[PacketMetadata]:
        if not self._indexed:
            self.build_index()
        if idx < 0 or idx >= len(self.index):
            return None
        meta = self.index[idx]
        fp = meta.get('fast_parsed')
        pm = PacketMetadata(
            index=meta['index'],
            timestamp=meta['timestamp'],
            length=meta['incl_len'],
            src_ip=fp.get('ip', {}).get('src_ip') if fp and fp.get('ip') else None,
            dst_ip=fp.get('ip', {}).get('dst_ip') if fp and fp.get('ip') else None,
            src_port=fp.get('tcp', {}).get('src_port') if fp and fp.get('tcp') else (fp.get('udp', {}).get('src_port') if fp and fp.get('udp') else None),
            dst_port=fp.get('tcp', {}).get('dst_port') if fp and fp.get('tcp') else (fp.get('udp', {}).get('dst_port') if fp and fp.get('udp') else None),
            protocol=('TCP' if fp and fp.get('tcp') else ('UDP' if fp and fp.get('udp') else ('ICMP' if fp and fp.get('ip') and fp['ip'].get('proto')==1 else 'IP'))),
            protocol_num=fp.get('ip', {}).get('proto') if fp and fp.get('ip') else None,
            payload_len=(meta['incl_len'] - (fp.get('tcp', {}).get('data_offset') if fp and fp.get('tcp') else (fp.get('ip', {}).get('ihl') if fp and fp.get('ip') else 0))) if fp else 0,
            fast_parsed=fp
        )
        return pm
