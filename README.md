# PCAP-SOC: AI-Powered Network Traffic Analysis

A professional-grade PCAP analysis tool combining Snort-style detection, Zeek-style flow tracking, and AI-powered analysis using local LLM models.

## Features

### Core Capabilities
- **Fast PCAP Parsing**: Byte-level header parsing with Scapy fallback
- **Flow Tracking**: Zeek-style 5-tuple flow engine with state management
- **TCP Reassembly**: Full stream reconstruction for deep payload inspection
- **Advanced Filtering**: Protocol, IP, port, and name-based filtering
- **Statistics Engine**: Real-time traffic analytics and reporting

### Detection Engines

#### Behavioral Detection
- **Port Scanning**: Detects SYN scans and connection attempts
- **DNS Tunneling**: Entropy analysis and query pattern detection
- **Beaconing**: Identifies periodic C2 callback patterns
- **TLS Anomalies**: Detects non-standard TLS usage
- **ARP Spoofing**: MAC address conflict detection

#### Signature-Based Detection
- **Aho-Corasick Engine**: Fast multi-pattern matching
- **Malware Signatures**: Cobalt Strike, Emotet, EternalBlue, etc.
- **Web Attacks**: SQL injection, XSS, command injection
- **Shellcode Detection**: NOP sleds and exploit patterns

#### Hybrid Detection
- **C2 & Exfiltration**: Combines behavioral and signature analysis

### AI Integration

Uses three specialized Ollama models:

1. **llama3.1:8b** - Command planning and intent parsing
2. **deepseek-r1:7b** - Alert explanations and SOC reasoning
3. **qwen2.5-coder:7b** - Rule generation and code snippets

### Preprocessors
- Flow state tracking
- DNS analysis
- TLS/SSL inspection
- ARP monitoring
- HTTP analysis

## Installation

### Prerequisites
```bash
# Install Python dependencies
pip install scapy requests

# Install Ollama (for AI features)
curl -fsSL https://ollama.com/install.sh | sh

# Pull required models
ollama pull llama3.1:8b
ollama pull deepseek-r1:7b
ollama pull qwen2.5-coder:7b
```

### Setup
```bash
git clone <repository>
cd pcap_soc
python main.py <pcap_file>
```

## Usage

### Basic Commands

```bash
# Start the shell
python main.py capture.pcap

# Show packet details
pcap> show 0

# Filter by protocol
pcap> filter protocol tcp

# Filter by IP
pcap> filter ip 192.168.1.100

# Filter by port
pcap> filter port 443

# Filter by name (protocol/alert/rule)
pcap> filter name dns
pcap> filter name portscan

# Search packets
pcap> search port 443
pcap> search ip 10.0.0.1

# Show statistics
pcap> stats

# AI analysis
pcap> analyze What suspicious DNS queries are present?

# Direct natural language queries (no 'analyze' keyword needed)
pcap> What IPs are talking to external servers?
pcap> Are there any port scans in this traffic?

# Exit
pcap> exit
```

### Command-Line Options

```bash
# Basic usage
python main.py capture.pcap

# Enable debug logging
python main.py capture.pcap --debug

# Disable AI features
python main.py capture.pcap --no-ai
```

## Architecture

```
pcap_soc/
├── core/               # Core analysis engines
│   ├── loader.py       # PCAP file loading
│   ├── fast_parser.py  # Fast header parsing
│   ├── flow_engine.py  # Flow tracking
│   ├── stats_engine.py # Statistics
│   └── filter_engine.py # Filtering
│
├── preprocessors/      # Snort-style preprocessors
│   ├── dns_preprocessor.py
│   ├── tls_preprocessor.py
│   └── ...
│
├── detect/            # Detection rules
│   ├── behavioral/    # Behavioral detection
│   │   ├── portscan_rule.py
│   │   ├── dns_tunnel_rule.py
│   │   └── beaconing_rule.py
│   ├── signatures/    # Signature-based
│   │   ├── signature_engine.py
│   │   └── aho_corasick.py
│   └── hybrid/        # Hybrid detection
│       └── c2_exfil_rule.py
│
├── ai/                # AI components
│   ├── llm_client.py  # Unified LLM interface
│   ├── planner.py     # Command planning
│   ├── explainer.py   # Traffic explanation
│   └── rule_generator.py # Rule generation
│
├── cli/               # Interactive shell
│   ├── shell.py
│   ├── commands.py
│   └── formatter.py
│
└── utils/             # Utilities
    ├── logger.py
    ├── caching.py
    └── threading_pool.py
```

## Detection Rules

### Port Scan Detection
- Threshold: 20 unique ports
- Time window: 60 seconds
- Detection: SYN packets to multiple ports

### DNS Tunneling
- Query threshold: 50 queries
- Entropy threshold: 3.5
- Detects: High-entropy subdomains, excessive queries

### Beaconing
- Minimum connections: 10
- Interval tolerance: 20% variance
- Detects: Regular periodic connections

### TLS Anomalies
- Old TLS versions (< TLS 1.2)
- TLS on non-standard ports
- Abnormal session ID lengths

### ARP Spoofing
- MAC address conflicts
- Excessive ARP requests (>100)

## Configuration

Edit `config/settings.py` to customize:

```python
# LLM settings
OLLAMA_BASE_URL = "http://localhost:11434"

# Detection thresholds
DETECTION_RULES = {
    'portscan': {
        'threshold': 20,
        'time_window': 60.0
    },
    ...
}
```

## Performance

- **Fast-path parsing**: Byte slicing for header extraction
- **Lazy loading**: Scapy decoding only when needed
- **Thread pool**: Parallel processing for heavy tasks
- **Caching**: LRU cache for repeated queries
- **Flow timeout**: 300 seconds default

## Testing

```bash
# Run all tests
python -m pytest tests/

# Run specific test
python -m pytest tests/test_flow_engine.py

# Run with coverage
python -m pytest --cov=. tests/
```

## Examples

### Detect Port Scans
```bash
pcap> filter name portscan
pcap> analyze Show me details about the port scans
```

### Investigate DNS Activity
```bash
pcap> filter name dns
pcap> analyze Are there any DNS tunneling attempts?
```

### Find Suspicious IPs
```bash
pcap> What are the top talkers?
pcap> filter ip <suspicious_ip>
pcap> analyze What is this IP doing?
```

### Generate Detection Rules
```bash
pcap> analyze Generate a Snort rule for detecting this behavior
```

## Troubleshooting

### Ollama Connection Issues
```bash
# Check Ollama status
curl http://localhost:11434/api/tags

# Restart Ollama
systemctl restart ollama
```

### Performance Issues
- Use `--no-ai` for faster analysis
- Reduce detection thresholds in config
- Filter packets before analysis

## License

MIT License

## Contributing

Contributions welcome! Please submit pull requests or open issues.

## Credits

- Scapy for packet parsing
- Ollama for local LLM inference
- Inspired by Snort, Zeek, and Wireshark