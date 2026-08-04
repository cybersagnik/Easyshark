"""
core/__init__.py — public exports for the core package.

Consumers (cli/, ai/) should import from here:
    from core import PCAPLoader, FlowEngine, StatsEngine, PacketIndex, FilterEngine
    from core import PacketMetadata, FastParser
"""
from .loader import PCAPLoader
from .fast_parser import FastParser
from .packet_metadata import PacketMetadata
from .flow_engine import FlowEngine, Flow
from .stats_engine import StatsEngine, TrafficStats
from .indexing import PacketIndex
from .filter_engine import SimpleFilter, DisplayFilter

__all__ = [
    "PCAPLoader",
    "FastParser",
    "PacketMetadata",
    "FlowEngine",
    "Flow",
    "StatsEngine",
    "TrafficStats",
    "PacketIndex",
    "SimpleFilter",
    "DisplayFilter",
]
