"""
Unit tests for flow engine
"""
import unittest
from typing import cast
from core.flow_engine import FlowEngine, Flow
from core.packet_metadata import PacketMetadata

class TestFlowEngine(unittest.TestCase):
    def setUp(self):
        self.engine = FlowEngine()
    
    def test_flow_creation(self):
        meta = PacketMetadata(
            index=0,
            timestamp=1000.0,
            length=100,
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=12345,
            dst_port=80,
            protocol="TCP"
        )
        
        flow = self.engine.process_packet(meta)
        
        self.assertIsNotNone(flow)
        flow = cast(Flow, flow)
        self.assertEqual(flow.src_ip, "192.168.1.100")
        self.assertEqual(flow.dst_ip, "8.8.8.8")
        self.assertEqual(flow.protocol, "TCP")
    
    def test_bidirectional_flow(self):
        meta1 = PacketMetadata(
            index=0,
            timestamp=1000.0,
            length=100,
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=12345,
            dst_port=80,
            protocol="TCP"
        )
        
        meta2 = PacketMetadata(
            index=1,
            timestamp=1001.0,
            length=200,
            src_ip="8.8.8.8",
            dst_ip="192.168.1.100",
            src_port=80,
            dst_port=12345,
            protocol="TCP"
        )
        
        flow1 = self.engine.process_packet(meta1)
        flow2 = self.engine.process_packet(meta2)
        
        self.assertIsNotNone(flow1)
        self.assertIsNotNone(flow2)
        flow1 = cast(Flow, flow1)
        flow2 = cast(Flow, flow2)
        self.assertEqual(flow1.flow_key, flow2.flow_key)
    
    def test_flow_statistics(self):
        for i in range(10):
            meta = PacketMetadata(
                index=i,
                timestamp=1000.0 + i,
                length=100,
                src_ip="192.168.1.100",
                dst_ip="8.8.8.8",
                src_port=12345,
                dst_port=80,
                protocol="TCP"
            )
            self.engine.process_packet(meta)
        
        flows = self.engine.get_all_flows()
        self.assertEqual(len(flows), 1)
        
        flow = flows[0]
        self.assertEqual(len(flow.packets), 10)
        self.assertEqual(flow.duration(), 9.0)

if __name__ == '__main__':
    unittest.main()