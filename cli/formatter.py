"""
Output formatting utilities
"""
from datetime import datetime
from core.packet_metadata import PacketMetadata

class OutputFormatter:
    def format_packet(self, meta: PacketMetadata) -> str:
        """Format packet details for display"""
        lines = []
        lines.append("="*60)
        lines.append(f"Packet #{meta.index}")
        lines.append("="*60)
        
        timestamp = datetime.fromtimestamp(meta.timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')
        lines.append(f"Timestamp: {timestamp}")
        lines.append(f"Length: {meta.length} bytes")
        lines.append(f"Protocol: {meta.protocol}")
        
        if meta.src_ip and meta.dst_ip:
            lines.append(f"Source: {meta.src_ip}:{meta.src_port or 'N/A'}")
            lines.append(f"Destination: {meta.dst_ip}:{meta.dst_port or 'N/A'}")
        
        if meta.tcp_flags:
            lines.append(f"TCP Flags: {meta.tcp_flags}")
        
        if meta.dns_query:
            lines.append(f"DNS Query: {meta.dns_query}")
        
        if meta.http_method:
            lines.append(f"HTTP Method: {meta.http_method}")
        
        if meta.http_host:
            lines.append(f"HTTP Host: {meta.http_host}")
        
        if meta.payload_len > 0:
            lines.append(f"Payload Length: {meta.payload_len} bytes")
        
        if meta.alerts:
            lines.append("\nAlerts:")
            for alert in meta.alerts:
                lines.append(f"  - {alert}")
        
        if meta.flow_key:
            lines.append(f"\nFlow: {meta.flow_key}")
        
        lines.append("="*60)
        
        return '\n'.join(lines)
    
    def format_packet_brief(self, meta: PacketMetadata) -> str:
        """Format packet in brief single-line format"""
        timestamp = datetime.fromtimestamp(meta.timestamp).strftime('%H:%M:%S.%f')[:-3]
        
        src = f"{meta.src_ip or 'N/A'}:{meta.src_port or ''}" if meta.src_ip else "N/A"
        dst = f"{meta.dst_ip or 'N/A'}:{meta.dst_port or ''}" if meta.dst_ip else "N/A"
        
        alert_indicator = " [!]" if meta.alerts else ""
        
        return f"[{meta.index:5d}] {timestamp} {meta.protocol:8s} {src:21s} -> {dst:21s} {meta.length:5d}b{alert_indicator}"
    
    def format_flow(self, flow) -> str:
        """Format flow details"""
        lines = []
        lines.append(f"Flow: {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port}")
        lines.append(f"  Protocol: {flow.protocol}")
        lines.append(f"  Packets: {len(flow.packets)}")
        lines.append(f"  Bytes: {flow.bytes_sent + flow.bytes_recv}")
        lines.append(f"  Duration: {flow.duration():.2f}s")
        lines.append(f"  State: {flow.state}")
        return '\n'.join(lines)
    
    def format_alert(self, alert) -> str:
        """Format alert details"""
        timestamp = datetime.fromtimestamp(alert.timestamp).strftime('%Y-%m-%d %H:%M:%S')
        return f"[{alert.severity}] {timestamp} - {alert.rule_name}: {alert.message}"
    
    def format_table(self, headers: list, rows: list) -> str:
        """Format data as ASCII table"""
        if not rows:
            return "No data"
        
        col_widths = [len(h) for h in headers]
        
        for row in rows:
            for i, cell in enumerate(row):
                col_widths[i] = max(col_widths[i], len(str(cell)))
        
        lines = []
        
        header_line = " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
        lines.append(header_line)
        lines.append("-" * len(header_line))
        
        for row in rows:
            row_line = " | ".join(str(cell).ljust(col_widths[i]) for i, cell in enumerate(row))
            lines.append(row_line)
        
        return '\n'.join(lines)