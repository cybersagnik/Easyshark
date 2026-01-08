"""Test AI functionality"""
from ai.llm_client import LLMClient
from ai.explainer import TrafficExplainer

# Test LLMClient
print("Testing LLMClient...")
client = LLMClient()
print(f"Is available: {client.is_available()}")

if client.is_available():
    print("\nTesting simple query...")
    response = client.query("Say hello in 5 words", model_type='planner', temperature=0.7)
    print(f"Response: {response}")
    
    print("\nTesting TrafficExplainer...")
    explainer = TrafficExplainer(client)
    
    # Create mock data
    mock_packets = []
    mock_flows = []
    mock_alerts = []
    
    result = explainer.explain_traffic(
        "What suspicious queries are present?",
        mock_packets,
        mock_flows,
        mock_alerts
    )
    print(f"Explainer result:\n{result}")
else:
    print("Ollama is not available!")
