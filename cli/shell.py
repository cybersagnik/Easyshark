"""
Interactive PCAP analysis shell
"""
import sys
import logging
from pathlib import Path
from .commands import CommandHandler
from .ai_commands import AICommandHandler
from .formatter import OutputFormatter
from core import PCAPLoader, FlowEngine, StatsEngine, PacketIndex, FilterEngine
from core.packet_metadata import PacketMetadata
from core.fast_parser import FastParser
from preprocessors import *
from detect.behavioral.portscan_rule import PortScanRule
from detect.behavioral.dns_tunnel_rule import DNSTunnelRule
from detect.behavioral.beaconing_rule import BeaconingRule
from detect.behavioral.tls_anomaly_rule import TLSAnomalyRule
from detect.behavioral.arp_spoof_rule import ARPSpoofRule
from detect.signatures.signature_engine import SignatureEngine
from detect.hybrid.c2_exfil_rule import C2ExfilRule
from ai.llm_client import LLMClient
from ai.planner import CommandPlanner

logger = logging.getLogger(__name__)

class InteractiveShell:
    def __init__(self, pcap_file: str, enable_ai: bool = True):
        self.pcap_file = pcap_file
        self.enable_ai = enable_ai
        
        print(f"Loading PCAP: {pcap_file}")
        self.loader = PCAPLoader(pcap_file)
        self.packets_raw = self.loader.load()
        
        print(f"Processing {len(self.packets_raw)} packets...")
        self.index = PacketIndex()
        self.flow_engine = FlowEngine()
        self.stats_engine = StatsEngine()
        self.filter_engine = FilterEngine()
        
        self.preprocessors = [
            FlowPreprocessor(),
            DNSPreprocessor(),
            TLSPreprocessor(),
            ARPPreprocessor(),
            HTTPPreprocessor()
        ]
        
        self.rules = [
            PortScanRule(),
            DNSTunnelRule(),
            BeaconingRule(),
            TLSAnomalyRule(),
            ARPSpoofRule(),
            SignatureEngine(),
            C2ExfilRule()
        ]
        
        self._process_packets()
        
        self.llm_client = LLMClient() if enable_ai else None
        self.planner = CommandPlanner(self.llm_client) if enable_ai and self.llm_client else None
        self.cmd_handler = CommandHandler(self)
        self.ai_handler = AICommandHandler(self, self.llm_client) if enable_ai and self.llm_client else None
        self.formatter = OutputFormatter()
        
        self.filtered_packets = None
        
        print(f"Analysis complete. {len(self.index.packets)} packets indexed.")
        print(f"Flows: {len(self.flow_engine.flows)}, Alerts: {sum(len(r.alerts) for r in self.rules)}")
        
        if enable_ai and self.llm_client and not self.llm_client.is_available():
            print("Warning: AI features unavailable (Ollama not running)")
    
    def _process_packets(self):
        """Process all packets through preprocessors and rules"""
        for idx, pkt in enumerate(self.packets_raw):
            fast_parsed = FastParser.quick_parse(bytes(pkt))
            meta = PacketMetadata.from_packet(pkt, idx, fast_parsed)
            
            for preprocessor in self.preprocessors:
                if preprocessor.enabled:
                    preprocessor.process(meta)
            
            self.flow_engine.process_packet(meta)
            self.stats_engine.update(meta)
            self.index.add_packet(meta)
        
        context = {
            'packets': self.index.packets,
            'flows': self.flow_engine.get_all_flows()
        }
        
        for rule in self.rules:
            if rule.enabled:
                rule.analyze(context)
    
    def run(self):
        """Run the interactive shell"""
        self._print_banner()
        
        while True:
            try:
                user_input = input("pcap> ").strip()
                
                if not user_input:
                    continue
                
                if user_input.lower() in ('exit', 'quit'):
                    break
                
                self._execute_command(user_input)
                
            except EOFError:
                break
            except KeyboardInterrupt:
                print("\nUse 'exit' or 'quit' to exit")
            except Exception as e:
                print(f"Error: {e}")
                logger.error(f"Command error: {e}", exc_info=True)
    
    def _execute_command(self, user_input: str):
        """Execute user command"""
        parts = user_input.split(maxsplit=1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""
        
        if cmd == 'help':
            self._print_help()
        elif cmd == 'show':
            self.cmd_handler.show_packet(args)
        elif cmd == 'filter':
            self.cmd_handler.filter_packets(args)
        elif cmd == 'search':
            self.cmd_handler.search_packets(args)
        elif cmd == 'stats':
            self.cmd_handler.show_stats()
        elif cmd == 'analyze':
            if self.ai_handler:
                self.ai_handler.analyze_traffic(args)
            else:
                print("AI features disabled. Use --no-ai flag to enable.")
        else:
            if self.planner:
                context = {
                    'packet_count': len(self.index.packets),
                    'protocols': list(self.index.get_unique_protocols()),
                    'alert_count': sum(len(r.alerts) for r in self.rules)
                }
                result = self.planner.parse_natural_language(user_input, context)
                
                if result:
                    parsed_cmd, parsed_args = result
                    if parsed_cmd == 'analyze':
                        if self.ai_handler:
                            self.ai_handler.analyze_traffic(parsed_args[0] if parsed_args else user_input)
                        else:
                            print("AI features disabled. Use --no-ai flag to enable.")
                    elif parsed_cmd == 'show':
                        self.cmd_handler.show_packet(parsed_args[0] if parsed_args else "")
                    elif parsed_cmd == 'filter':
                        self.cmd_handler.filter_packets(' '.join(parsed_args))
                    elif parsed_cmd == 'search':
                        self.cmd_handler.search_packets(' '.join(parsed_args))
                    elif parsed_cmd == 'stats':
                        self.cmd_handler.show_stats()
                else:
                    print(f"Unknown command: {cmd}")
            else:
                print(f"Unknown command: {cmd}. Type 'help' for available commands.")
    
    def _print_banner(self):
        """Print welcome banner"""
        print("\n" + "="*60)
        print("PCAP-SOC: AI-Powered Network Traffic Analysis")
        print("="*60)
        print(f"Loaded: {self.pcap_file}")
        print(f"Packets: {len(self.index.packets)}")
        print("="*60 + "\n")
        self._print_help()
        print()
    
    def _print_help(self):
        """Print help message"""
        help_text = """
Commands:
  show <index>               Display packet details by index
  filter <type> <value>      Filter packets (type: protocol, ip, port, name)
  search <field> <value>     Search packets or payloads
  stats                      Show packet statistics
  analyze <query>            Analyze traffic with LLM
  help                       Show this help
  exit / quit                Exit the tool

Examples:
  show 0
  filter protocol tcp
  filter ip 192.168.1.100
  filter name dns
  search port 443
  stats
  analyze What DNS queries look suspicious?

Direct Queries:
  Users may type ANY natural-language question directly,
  without the 'analyze' keyword, and it must still work.

Example:
  What suspicious IPs are in this traffic?
"""
        print(help_text)
    
    def get_packets(self):
        """Get current packet list (filtered or all)"""
        if self.filtered_packets is not None:
            return self.filtered_packets
        return self.index.packets