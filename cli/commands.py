"""
Command handlers for CLI
"""
import logging
from .formatter import OutputFormatter

logger = logging.getLogger(__name__)

class CommandHandler:
    def __init__(self, shell):
        self.shell = shell
        self.formatter = OutputFormatter()
    
    def show_packet(self, args: str):
        """Show packet details by index"""
        if not args:
            print("Usage: show <packet_index>")
            return
        
        try:
            index = int(args.strip())
        except ValueError:
            print("Usage: show <packet_index>")
            return
        
        packets = self.shell.get_packets()
        
        if index < 0 or index >= len(packets):
            print(f"Error: Index {index} out of range (0-{len(packets)-1})")
            return
        
        meta = packets[index]
        print(self.formatter.format_packet(meta))
    
    def filter_packets(self, args: str):
        """Filter packets by type and value"""
        parts = args.split(maxsplit=1)
        
        if len(parts) != 2:
            print("Usage: filter <type> <value>")
            print("Types: protocol, ip, port, name")
            return
        
        filter_type, value = parts
        filter_type = filter_type.lower()
        
        packets = self.shell.index.packets
        
        if filter_type == 'protocol':
            filtered = self.shell.filter_engine.filter_by_protocol(packets, value)
        elif filter_type == 'ip':
            filtered = self.shell.filter_engine.filter_by_ip(packets, value)
        elif filter_type == 'port':
            try:
                port = int(value)
                filtered = self.shell.filter_engine.filter_by_port(packets, port)
            except ValueError:
                print(f"Error: Invalid port number: {value}")
                return
        elif filter_type == 'name':
            filtered = self.shell.filter_engine.filter_by_name(packets, value)
        else:
            print(f"Error: Unknown filter type: {filter_type}")
            print("Valid types: protocol, ip, port, name")
            return
        
        self.shell.filtered_packets = filtered
        print(f"Filtered to {len(filtered)} packets (use 'filter clear' to reset)")
        
        if filtered and len(filtered) <= 20:
            print("\nFiltered packets:")
            for meta in filtered[:20]:
                print(self.formatter.format_packet_brief(meta))
    
    def search_packets(self, args: str):
        """Search packets by field or payload"""
        parts = args.split(maxsplit=1)
        
        if len(parts) != 2:
            print("Usage: search <field> <value>")
            print("Fields: port, ip, protocol, payload")
            return
        
        field, value = parts
        field = field.lower()
        
        packets = self.shell.get_packets()
        results = []
        
        if field == 'port':
            try:
                port = int(value)
                results = [p for p in packets if p.src_port == port or p.dst_port == port]
            except ValueError:
                print(f"Error: Invalid port number: {value}")
                return
        elif field == 'ip':
            results = [p for p in packets if p.src_ip == value or p.dst_ip == value]
        elif field == 'protocol':
            results = [p for p in packets if p.protocol.lower() == value.lower()]
        elif field == 'payload':
            from core.payload_search import PayloadSearcher
            searcher = PayloadSearcher()
            results = searcher.search_string(packets, value)
        else:
            print(f"Error: Unknown search field: {field}")
            return
        
        print(f"Found {len(results)} matching packets")
        
        if results:
            for meta in results[:20]:
                print(self.formatter.format_packet_brief(meta))
            
            if len(results) > 20:
                print(f"\n... and {len(results) - 20} more")
    
    def show_stats(self):
        """Show traffic statistics"""
        stats = self.shell.stats_engine.get_summary()
        
        print("\n" + "="*60)
        print("Traffic Statistics")
        print("="*60)
        
        print(f"\nTotal Packets: {stats['total_packets']}")
        print(f"Total Bytes: {stats['total_bytes']:,}")
        print(f"Total Alerts: {stats['total_alerts']}")
        
        if stats['protocols']:
            print("\nProtocol Breakdown:")
            for proto, count in stats['protocols'].items():
                pct = (count / stats['total_packets']) * 100
                print(f"  {proto:10s}: {count:6d} ({pct:5.1f}%)")
        
        if stats['top_ips']:
            print("\nTop Talkers:")
            for ip, count in list(stats['top_ips'].items())[:10]:
                print(f"  {ip:15s}: {count:6d} packets")
        
        if stats['top_ports']:
            print("\nTop Ports:")
            for port, count in list(stats['top_ports'].items())[:10]:
                print(f"  Port {port:5d}: {count:6d} packets")
        
        if stats['unique_dns_queries'] > 0:
            print(f"\nUnique DNS Queries: {stats['unique_dns_queries']}")
        
        alert_summary = {}
        for rule in self.shell.rules:
            if rule.alerts:
                alert_summary[rule.name] = len(rule.alerts)
        
        if alert_summary:
            print("\nAlerts by Rule:")
            for rule_name, count in sorted(alert_summary.items(), key=lambda x: x[1], reverse=True):
                print(f"  {rule_name:20s}: {count:4d}")
        
        print("="*60 + "\n")