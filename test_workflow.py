"""Test actual AI workflow"""
import logging
logging.basicConfig(level=logging.DEBUG)

from ai.llm_client import LLMClient
from ai.explainer import TrafficExplainer
from core.packet_metadata import PacketMetadata

print("1. Creating LLMClient...")
client = LLMClient()
print(f"   Available: {client.is_available()}")

print("\n2. Creating TrafficExplainer...")
explainer = TrafficExplainer(client)

print("\n3. Creating mock data...")
# Create a few mock packets
packets = [
    PacketMetadata(index=i, timestamp=1000.0 + i, length=100,
                   src_ip="192.168.10.152", dst_ip="66.85.157.95",
                   src_port=50000 + i, dst_port=443, protocol="TCP")
    for i in range(10)
]
flows = []
alerts = []

print(f"   Created {len(packets)} mock packets")

print("\n4. Calling explain_traffic...")
try:
    result = explainer.explain_traffic(
        "What are the suspicious queries?",
        packets,
        flows,
        alerts
    )
    print(f"\n5. Result:\n{result}")
except Exception as e:
    print(f"\n5. ERROR: {e}")
    import traceback
    traceback.print_exc()
