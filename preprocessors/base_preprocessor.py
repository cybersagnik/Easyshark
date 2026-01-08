"""
Base preprocessor interface
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List
from core.packet_metadata import PacketMetadata

class BasePreprocessor(ABC):
    def __init__(self, name: str):
        self.name = name
        self.enabled = True
        self.stats = {
            'packets_processed': 0,
            'alerts_generated': 0
        }
    
    @abstractmethod
    def process(self, meta: PacketMetadata) -> List[str]:
        """
        Process packet and return list of alerts
        Returns: List of alert strings
        """
        pass
    
    def update_stats(self):
        """Update preprocessor statistics"""
        self.stats['packets_processed'] += 1
    
    def add_alert(self, meta: PacketMetadata, alert: str):
        """Add alert to packet metadata"""
        meta.alerts.append(f"[{self.name}] {alert}")
        self.stats['alerts_generated'] += 1
    
    def get_stats(self) -> Dict[str, Any]:
        """Get preprocessor statistics"""
        return {
            'name': self.name,
            'enabled': self.enabled,
            **self.stats
        }
    
    def enable(self):
        """Enable preprocessor"""
        self.enabled = True
    
    def disable(self):
        """Disable preprocessor"""
        self.enabled = False