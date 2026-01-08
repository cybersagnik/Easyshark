"""
Application settings and configuration
"""
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent

OLLAMA_BASE_URL = "http://localhost:11434"

LLM_MODELS = {
    'planner': 'llama3.1:8b',
    'explainer': 'deepseek-r1:7b',
    'coder': 'qwen2.5-coder:7b'
}

FLOW_TIMEOUT = 300.0

TCP_REASSEMBLY_ENABLED = True

MAX_PACKET_SIZE = 65535

CACHE_ENABLED = True
CACHE_MAX_SIZE = 1000

THREADING_MAX_WORKERS = 4

LOG_LEVEL = "INFO"
LOG_FILE = None

PREPROCESSORS = {
    'flow': True,
    'dns': True,
    'tls': True,
    'arp': True,
    'http': True
}

DETECTION_RULES = {
    'portscan': {
        'enabled': True,
        'threshold': 20,
        'time_window': 60.0
    },
    'dns_tunnel': {
        'enabled': True,
        'query_threshold': 50,
        'entropy_threshold': 3.5
    },
    'beaconing': {
        'enabled': True,
        'min_connections': 10,
        'interval_tolerance': 0.2
    },
    'tls_anomaly': {
        'enabled': True
    },
    'arp_spoof': {
        'enabled': True
    },
    'signatures': {
        'enabled': True
    },
    'c2_exfil': {
        'enabled': True
    }
}

OUTPUT_FORMAT = {
    'brief_packet_format': True,
    'show_alerts_inline': True,
    'timestamp_format': '%Y-%m-%d %H:%M:%S.%f'
}