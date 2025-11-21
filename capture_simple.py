#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
简化版流量捕获模块 - 不依赖Scapy，只支持基本PCAP读取
"""

import struct
import os

class TrafficCapture:
    """简化版流量捕获器 - 不依赖Scapy"""
    
    def __init__(self):
        self.packets = []
        self.running = False
    
    def get_interfaces(self):
        """返回空列表 - 简化版不支持实时捕获"""
        return [{'name': '不支持', 'description': '简化版不支持实时监听，请使用PCAP文件'}]
    
    def _read_pcap_scapy(self, filepath):
        """使用Scapy读取PCAP"""
        from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Raw
        
        packets = []
        pcap_packets = rdpcap(filepath)
        
        for i, pkt in enumerate(pcap_packets):
            try:
                packet_data = {
                    'index': i,
                    'timestamp': float(pkt.time),
                    'length': len(pkt),
                    'protocol': 'OTHER',
                    'src': '',
                    'dst': '',
                    'src_port': 0,
                    'dst_port': 0,
                    'flags': {},
                    'payload': ''
                }
                
                # IP层
                if IP in pkt:
                    packet_data['src'] = pkt[IP].src
                    packet_data['dst'] = pkt[IP].dst
                    
                    # TCP
                    if TCP in pkt:
                        packet_data['protocol'] = 'TCP'
                        packet_data['src_port'] = pkt[TCP].sport
                        packet_data['dst_port'] = pkt[TCP].dport
                        packet_data['flags'] = {
                            'syn': bool(pkt[TCP].flags & 0x02),
                            'ack': bool(pkt[TCP].flags & 0x10),
                            'fin': bool(pkt[TCP].flags & 0x01),
                            'rst': bool(pkt[TCP].flags & 0x04),
                            'psh': bool(pkt[TCP].flags & 0x08)
                        }
                        
                        # 检测HTTP
                        if pkt[TCP].dport in [80, 8080] or pkt[TCP].sport in [80, 8080]:
                            packet_data['protocol'] = 'HTTP'
                        elif pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                            packet_data['protocol'] = 'HTTPS'
                        elif pkt[TCP].dport == 22 or pkt[TCP].sport == 22:
                            packet_data['protocol'] = 'SSH'
                    
                    # UDP
                    elif UDP in pkt:
                        packet_data['protocol'] = 'UDP'
                        packet_data['src_port'] = pkt[UDP].sport
                        packet_data['dst_port'] = pkt[UDP].dport
                        
                        if pkt[UDP].dport == 53 or pkt[UDP].sport == 53:
                            packet_data['protocol'] = 'DNS'
                    
                    # ICMP
                    elif ICMP in pkt:
                        packet_data['protocol'] = 'ICMP'
                
                # Payload
                if Raw in pkt:
                    try:
                        payload = pkt[Raw].load
                        packet_data['payload'] = payload.decode('utf-8', errors='ignore')[:500]
                    except:
                        packet_data['payload'] = str(payload)[:500]
                
                packets.append(packet_data)
                
            except Exception as e:
                continue
        
        return packets
    
    def read_pcap(self, filepath):
        """读取PCAP文件 - 基础实现"""
        try:
            # 尝试使用Scapy（最优先）
            try:
                from scapy.all import rdpcap
                return self._read_pcap_scapy(filepath)
            except ImportError:
                pass
            
            # 尝试使用dpkt库（轻量级）
            try:
                import dpkt
                return self._read_pcap_dpkt(filepath)
            except ImportError:
                pass
            
            # 尝试使用pyshark（需要tshark）
            try:
                import pyshark
                return self._read_pcap_pyshark(filepath)
            except ImportError:
                pass
            
            # 如果都没有，返回错误
            raise Exception("未安装PCAP读取库。请安装: pip install scapy 或 pip install dpkt")
            
        except Exception as e:
            raise Exception(f"读取PCAP文件失败: {e}")
    
    def _read_pcap_dpkt(self, filepath):
        """使用dpkt读取PCAP"""
        import dpkt
        import socket
        
        packets = []
        with open(filepath, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            
            for i, (timestamp, buf) in enumerate(pcap):
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue
                    
                    ip = eth.data
                    packet_data = {
                        'index': i,
                        'timestamp': float(timestamp),
                        'length': len(buf),
                        'protocol': 'OTHER',
                        'src': socket.inet_ntoa(ip.src),
                        'dst': socket.inet_ntoa(ip.dst),
                        'src_port': 0,
                        'dst_port': 0,
                        'flags': {},
                        'payload': ''
                    }
                    
                    # TCP
                    if isinstance(ip.data, dpkt.tcp.TCP):
                        tcp = ip.data
                        packet_data['protocol'] = 'TCP'
                        packet_data['src_port'] = tcp.sport
                        packet_data['dst_port'] = tcp.dport
                        packet_data['flags'] = {
                            'syn': bool(tcp.flags & dpkt.tcp.TH_SYN),
                            'ack': bool(tcp.flags & dpkt.tcp.TH_ACK),
                            'fin': bool(tcp.flags & dpkt.tcp.TH_FIN),
                            'rst': bool(tcp.flags & dpkt.tcp.TH_RST),
                            'psh': bool(tcp.flags & dpkt.tcp.TH_PUSH)
                        }
                        if len(tcp.data) > 0:
                            try:
                                packet_data['payload'] = tcp.data.decode('utf-8', errors='ignore')[:500]
                            except:
                                packet_data['payload'] = tcp.data.hex()[:500]
                    
                    # UDP
                    elif isinstance(ip.data, dpkt.udp.UDP):
                        udp = ip.data
                        packet_data['protocol'] = 'UDP'
                        packet_data['src_port'] = udp.sport
                        packet_data['dst_port'] = udp.dport
                        
                        if udp.dport == 53 or udp.sport == 53:
                            packet_data['protocol'] = 'DNS'
                    
                    # ICMP
                    elif isinstance(ip.data, dpkt.icmp.ICMP):
                        packet_data['protocol'] = 'ICMP'
                    
                    packets.append(packet_data)
                    
                except Exception as e:
                    continue
        
        return packets
    
    def _read_pcap_pyshark(self, filepath):
        """使用pyshark读取PCAP"""
        import pyshark
        
        packets = []
        cap = pyshark.FileCapture(filepath)
        
        for i, pkt in enumerate(cap):
            try:
                packet_data = {
                    'index': i,
                    'timestamp': float(pkt.sniff_timestamp),
                    'length': int(pkt.length),
                    'protocol': 'OTHER',
                    'src': '',
                    'dst': '',
                    'src_port': 0,
                    'dst_port': 0,
                    'flags': {},
                    'payload': ''
                }
                
                if hasattr(pkt, 'ip'):
                    packet_data['src'] = pkt.ip.src
                    packet_data['dst'] = pkt.ip.dst
                    
                    if hasattr(pkt, 'tcp'):
                        packet_data['protocol'] = 'TCP'
                        packet_data['src_port'] = int(pkt.tcp.srcport)
                        packet_data['dst_port'] = int(pkt.tcp.dstport)
                        
                    elif hasattr(pkt, 'udp'):
                        packet_data['protocol'] = 'UDP'
                        packet_data['src_port'] = int(pkt.udp.srcport)
                        packet_data['dst_port'] = int(pkt.udp.dstport)
                
                packets.append(packet_data)
                
            except Exception as e:
                continue
        
        cap.close()
        return packets
    
    def _generate_sample_packets(self):
        """生成示例数据包用于演示"""
        import random
        import time
        
        packets = []
        start_time = time.time()
        
        # 生成一些示例数据
        src_ips = ['192.168.1.100', '192.168.1.101', '192.168.1.150']
        dst_ips = ['8.8.8.8', '10.0.0.50', '185.199.108.153']
        protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS']
        
        for i in range(100):
            packet = {
                'index': i,
                'timestamp': start_time + i * 0.1,
                'length': random.randint(64, 1500),
                'protocol': random.choice(protocols),
                'src': random.choice(src_ips),
                'dst': random.choice(dst_ips),
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice([80, 443, 53, 8080]),
                'flags': {
                    'syn': random.choice([True, False]),
                    'ack': random.choice([True, False]),
                    'fin': False,
                    'rst': False,
                    'psh': False
                },
                'payload': f'Sample payload data {i}'
            }
            packets.append(packet)
        
        return packets
    
    def apply_bpf_filter(self, packets, filter_str):
        """应用BPF过滤器到数据包列表"""
        if not filter_str:
            return packets
        
        filter_str = filter_str.lower().strip()
        filtered = []
        
        for pkt in packets:
            try:
                # 简单的BPF过滤器解析
                if self._match_filter(pkt, filter_str):
                    filtered.append(pkt)
            except Exception as e:
                continue
        
        return filtered
    
    def _match_filter(self, pkt, filter_str):
        """匹配单个数据包与过滤规则"""
        # 支持的过滤语法：
        # tcp, udp, icmp, http, https, dns, ssh
        # port 80, dst port 443, src port 8080
        # host 192.168.1.1, src host 10.0.0.1, dst host 8.8.8.8
        # net 192.168.0.0/24
        # tcp and port 80
        # src host 192.168.1.1 and dst port 443
        
        protocol = pkt.get('protocol', '').lower()
        src = pkt.get('src', '')
        dst = pkt.get('dst', '')
        src_port = pkt.get('src_port', 0)
        dst_port = pkt.get('dst_port', 0)
        
        # 处理 and 连接词
        if ' and ' in filter_str:
            parts = filter_str.split(' and ')
            return all(self._match_filter(pkt, part.strip()) for part in parts)
        
        # 处理 or 连接词
        if ' or ' in filter_str:
            parts = filter_str.split(' or ')
            return any(self._match_filter(pkt, part.strip()) for part in parts)
        
        # 协议匹配
        if filter_str in ['tcp', 'udp', 'icmp', 'http', 'https', 'dns', 'ssh']:
            return protocol == filter_str
        
        # 端口匹配
        if filter_str.startswith('port '):
            port = int(filter_str.split()[1])
            return src_port == port or dst_port == port
        
        if filter_str.startswith('dst port '):
            port = int(filter_str.split()[2])
            return dst_port == port
        
        if filter_str.startswith('src port '):
            port = int(filter_str.split()[2])
            return src_port == port
        
        # 主机匹配
        if filter_str.startswith('host '):
            host = filter_str.split()[1]
            return src == host or dst == host
        
        if filter_str.startswith('src host '):
            host = filter_str.split()[2]
            return src == host
        
        if filter_str.startswith('dst host '):
            host = filter_str.split()[2]
            return dst == host
        
        # 网络匹配 (简化版)
        if filter_str.startswith('net '):
            net = filter_str.split()[1]
            if '/' in net:
                net_base = net.split('/')[0]
                net_prefix = '.'.join(net_base.split('.')[:3])  # 简化：只支持/24
                return src.startswith(net_prefix) or dst.startswith(net_prefix)
        
        return False
    
    def start_capture(self, interface=None, filter_str='', callback=None):
        """简化版不支持实时捕获"""
        raise Exception("简化版不支持实时监听，请安装Scapy或使用PCAP文件分析")
    
    def stop_capture(self):
        """停止捕获"""
        self.running = False
