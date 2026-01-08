"""
Simple benchmark script to compare full Scapy load vs indexed metadata load.

Usage:
    python tools/benchmark_pcap.py /path/to/file.pcap

By default it will print timing information for:
- full Scapy decode (`use_index=False`)
- indexed metadata load (`use_index=True`, builds index)

The script avoids heavy work at import time so it is safe to import for syntax checks.
"""
import sys
import time
import json
from pathlib import Path
from typing import Tuple


def time_full_load(pcap_path: str) -> Tuple[float, int]:
    from core.loader import PCAPLoader
    loader = PCAPLoader(pcap_path, use_index=False)
    t0 = time.time()
    pkts = loader.load()
    t1 = time.time()
    return (t1 - t0, len(pkts))


def time_indexed_load(pcap_path: str, index_path: str = None) -> Tuple[float, int]:
    from core.loader import PCAPLoader
    loader = PCAPLoader(pcap_path, use_index=True, index_path=index_path)
    t0 = time.time()
    metas = loader.load()
    t1 = time.time()
    return (t1 - t0, len(metas))


def run(pcap_path: str):
    p = Path(pcap_path)
    if not p.exists():
        print(json.dumps({'error': f'pcap not found: {pcap_path}'}))
        return

    print(f"Benchmarking: {pcap_path}")

    # full load (may be slow for very large files)
    t_full, n_full = time_full_load(str(p))
    print(json.dumps({'mode': 'full', 'seconds': t_full, 'count': n_full}))

    # indexed load (first run will build index)
    idx_path = str(p) + '.idx'
    t_idx, n_idx = time_indexed_load(str(p), index_path=idx_path)
    print(json.dumps({'mode': 'indexed', 'seconds': t_idx, 'count': n_idx, 'index_file': idx_path}))


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python tools/benchmark_pcap.py /path/to/file.pcap')
        sys.exit(1)
    run(sys.argv[1])
