"""
Detection thresholds and tuning parameters
"""

PORTSCAN_THRESHOLDS = {
    'min_ports': 20,
    'time_window': 60.0,
    'syn_only': True
}

DNS_TUNNEL_THRESHOLDS = {
    'min_queries': 50,
    'entropy_threshold': 3.5,
    'subdomain_length_threshold': 20,
    'suspicion_score_threshold': 0.3
}

BEACONING_THRESHOLDS = {
    'min_connections': 10,
    'interval_tolerance': 0.2,
    'byte_consistency_threshold': 0.7
}

TLS_THRESHOLDS = {
    'old_version_threshold': (3, 2),
    'session_id_max_length': 32,
    'non_standard_port_threshold': 3
}

ARP_THRESHOLDS = {
    'request_threshold': 100
}

FLOW_THRESHOLDS = {
    'timeout': 300.0,
    'max_flows': 100000
}

SIGNATURE_THRESHOLDS = {
    'max_pattern_length': 1024,
    'case_sensitive': False
}

C2_EXFIL_THRESHOLDS = {
    'large_upload_bytes': 1000000,
    'min_command_indicators': 3
}

PAYLOAD_SEARCH_THRESHOLDS = {
    'max_payload_scan': 10000,
    'regex_timeout': 5.0
}