"""
Fast packet header parser using byte slicing
Avoids full Scapy decoding for performance
"""
import struct
from typing import Dict, Optional, Any

class FastParser:
    ETH_HEADER_LEN = 14
    IP_HEADER_MIN_LEN = 20
    TCP_HEADER_MIN_LEN = 20
    UDP_HEADER_LEN = 8
    
    PROTO_ICMP = 1
    PROTO_TCP = 6
    PROTO_UDP = 17
    
    ETHERTYPE_IP = 0x0800
    ETHERTYPE_ARP = 0x0806
    ETHERTYPE_IPV6 = 0x86DD
    
    @staticmethod
    def parse_ethernet(raw_bytes: bytes) -> Optional[Dict[str, Any]]:
        """Fast parse Ethernet header"""
        if len(raw_bytes) < FastParser.ETH_HEADER_LEN:
            return None
            
        dst_mac = raw_bytes[0:6].hex(':')
        src_mac = raw_bytes[6:12].hex(':')
        ethertype = struct.unpack('!H', raw_bytes[12:14])[0]
        
        return {
            'dst_mac': dst_mac,
            'src_mac': src_mac,
            'ethertype': ethertype,
            'payload_offset': FastParser.ETH_HEADER_LEN
        }
    
    @staticmethod
    def parse_ipv4(raw_bytes: bytes, offset: int = 14) -> Optional[Dict[str, Any]]:
        """Fast parse IPv4 header"""
        if len(raw_bytes) < offset + FastParser.IP_HEADER_MIN_LEN:
            return None
            
        ip_data = raw_bytes[offset:]
        version_ihl = ip_data[0]
        version = version_ihl >> 4
        
        if version != 4:
            return None
            
        ihl = (version_ihl & 0x0F) * 4
        total_len = struct.unpack('!H', ip_data[2:4])[0]
        proto = ip_data[9]
        src_ip = '.'.join(str(b) for b in ip_data[12:16])
        dst_ip = '.'.join(str(b) for b in ip_data[16:20])
        
        return {
            'version': version,
            'ihl': ihl,
            'total_len': total_len,
            'proto': proto,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'payload_offset': offset + ihl
        }
    
    @staticmethod
    def parse_tcp(raw_bytes: bytes, offset: int) -> Optional[Dict[str, Any]]:
        """Fast parse TCP header"""
        if len(raw_bytes) < offset + FastParser.TCP_HEADER_MIN_LEN:
            return None
            
        tcp_data = raw_bytes[offset:]
        src_port = struct.unpack('!H', tcp_data[0:2])[0]
        dst_port = struct.unpack('!H', tcp_data[2:4])[0]
        seq = struct.unpack('!I', tcp_data[4:8])[0]
        ack = struct.unpack('!I', tcp_data[8:12])[0]
        
        data_offset = (tcp_data[12] >> 4) * 4
        flags = tcp_data[13]
        
        return {
            'src_port': src_port,
            'dst_port': dst_port,
            'seq': seq,
            'ack': ack,
            'data_offset': data_offset,
            'flags': flags,
            'flag_fin': bool(flags & 0x01),
            'flag_syn': bool(flags & 0x02),
            'flag_rst': bool(flags & 0x04),
            'flag_psh': bool(flags & 0x08),
            'flag_ack': bool(flags & 0x10),
            'flag_urg': bool(flags & 0x20),
            'payload_offset': offset + data_offset
        }
    
    @staticmethod
    def parse_udp(raw_bytes: bytes, offset: int) -> Optional[Dict[str, Any]]:
        """Fast parse UDP header"""
        if len(raw_bytes) < offset + FastParser.UDP_HEADER_LEN:
            return None
            
        udp_data = raw_bytes[offset:]
        src_port = struct.unpack('!H', udp_data[0:2])[0]
        dst_port = struct.unpack('!H', udp_data[2:4])[0]
        length = struct.unpack('!H', udp_data[4:6])[0]
        
        return {
            'src_port': src_port,
            'dst_port': dst_port,
            'length': length,
            'payload_offset': offset + FastParser.UDP_HEADER_LEN
        }
    
    @staticmethod
    def quick_parse(raw_bytes: bytes) -> Dict[str, Any]:
        """Quick parse packet headers in one pass"""
        result: Dict[str, Any] = {'valid': False}
        
        eth = FastParser.parse_ethernet(raw_bytes)
        if not eth:
            return result
            
        result['eth'] = eth
        
        if eth['ethertype'] == FastParser.ETHERTYPE_IP:
            ip = FastParser.parse_ipv4(raw_bytes, eth['payload_offset'])
            if not ip:
                return result
                
            result['ip'] = ip
            result['valid'] = True
            
            if ip['proto'] == FastParser.PROTO_TCP:
                tcp = FastParser.parse_tcp(raw_bytes, ip['payload_offset'])
                if tcp:
                    result['tcp'] = tcp
            elif ip['proto'] == FastParser.PROTO_UDP:
                udp = FastParser.parse_udp(raw_bytes, ip['payload_offset'])
                if udp:
                    result['udp'] = udp
        
        return result