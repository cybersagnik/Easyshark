"""
PCAP-SOC Main Entry Point
"""
import sys
import argparse
from pathlib import Path
from cli.shell import InteractiveShell
from utils.logger import setup_logger

def main():
    parser = argparse.ArgumentParser(description='PCAP-SOC: AI-Powered Network Traffic Analysis')
    parser.add_argument('pcap_file', help='Path to PCAP file')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--no-ai', action='store_true', help='Disable AI features')
    
    args = parser.parse_args()
    
    if not Path(args.pcap_file).exists():
        print(f"Error: PCAP file not found: {args.pcap_file}")
        sys.exit(1)
    
    logger = setup_logger(debug=args.debug)
    
    try:
        shell = InteractiveShell(args.pcap_file, enable_ai=not args.no_ai)
        shell.run()
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == '__main__':
    main()