"""
Unit tests for preprocessors
"""
import unittest
from preprocessors.dns_preprocessor import DNSPreprocessor
from preprocessors.flow_preprocessor import FlowPreprocessor
from core.packet_metadata import PacketMetadata

class TestDNSPreprocessor(unittest.TestCase):
    def setUp(self):
        self.preprocessor = DNSPreprocessor()
    
    def test_suspicious_tld_detection(self):
        meta = PacketMetadata(
            index=0,
            timestamp=1000.0,
            length=100,
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            protocol="UDP",
            dns_query="malicious.tk"
        )
        
        alerts = self.preprocessor.process(meta)
        
        self.assertGreater(len(alerts), 0)
        self.assertIn("Suspicious TLD", alerts[0])
    
    def test_long_dns_query(self):
        meta = PacketMetadata(
            index=0,
            timestamp=1000.0,
            length=100,
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            protocol="UDP",
            dns_query="a" * 100 + ".example.com"
        )
        
        alerts = self.preprocessor.process(meta)
        
        self.assertGreater(len(alerts), 0)

class TestFlowPreprocessor(unittest.TestCase):
    def setUp(self):
        self.preprocessor = FlowPreprocessor()
    
    def test_flow_tracking(self):
        meta = PacketMetadata(
            index=0,
            timestamp=1000.0,
            length=100,
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            flow_key="192.168.1.100:12345-8.8.8.8:80"
        )
        
        self.preprocessor.process(meta)
        
        self.assertIn(meta.flow_key, self.preprocessor.flow_states)

if __name__ == '__main__':
    unittest.main()