"""
Unit tests for filter engine
"""
import unittest
from core.filter_engine import FilterEngine
from core.packet_metadata import PacketMetadata

class TestFilterEngine(unittest.TestCase):
    def setUp(self):
        self.engine = FilterEngine()
        self.packets = [
            PacketMetadata(
                index=0,
                timestamp=1000.0,
                length=100,
                src_ip="192.168.1.100",
                dst_ip="8.8.8.8",
                src_port=12345,
                dst_port=80,
                protocol="TCP"
            ),
            PacketMetadata(
                index=1,
                timestamp=1001.0,
                length=200,
                src_ip="192.168.1.101",
                dst_ip="1.1.1.1",
                src_port=54321,
                dst_port=443,
                protocol="UDP"
            ),
            PacketMetadata(
                index=2,
                timestamp=1002.0,
                length=150,
                src_ip="192.168.1.100",
                dst_ip="8.8.4.4",
                src_port=12346,
                dst_port=53,
                protocol="UDP",
                dns_query="example.com"
            )
        ]
    
    def test_filter_by_protocol(self):
        filtered = self.engine.filter_by_protocol(self.packets, "TCP")
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].protocol, "TCP")
    
    def test_filter_by_ip(self):
        filtered = self.engine.filter_by_ip(self.packets, "192.168.1.100")
        self.assertEqual(len(filtered), 2)
    
    def test_filter_by_port(self):
        filtered = self.engine.filter_by_port(self.packets, 80)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].dst_port, 80)
    
    def test_filter_by_name(self):
        filtered = self.engine.filter_by_name(self.packets, "dns")
        self.assertEqual(len(filtered), 1)

if __name__ == '__main__':
    unittest.main()