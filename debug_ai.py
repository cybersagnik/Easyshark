"""Debug AI issue"""
import requests
import json

print("Testing direct Ollama API call...")
try:
    response = requests.post(
        "http://localhost:11434/api/generate",
        json={
            'model': 'llama3.1:8b',
            'prompt': 'Say hello briefly',
            'stream': False,
            'options': {
                'temperature': 0.7,
                'num_predict': 50
            }
        },
        timeout=30
    )
    print(f"Status: {response.status_code}")
    result = response.json()
    print(f"Response: {result.get('response', 'NO RESPONSE')}")
except Exception as e:
    print(f"Error: {e}")

print("\n\nNow testing LLMClient...")
from ai.llm_client import LLMClient
client = LLMClient()
print(f"Available: {client.is_available()}")

print("\nQuerying with short prompt...")
result = client.query("Hello", model_type='planner')
print(f"Result: {result}")
