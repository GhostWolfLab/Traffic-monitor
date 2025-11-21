#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
流量捕获模块 - 支持实时捕获和PCAP读取
"""

from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS
import time
from datetime import datetime

class TrafficCapture:
    """流量捕获器"""
    
    def __init__(self):
        self.packets = []
        self.running = False
    
    def get_interfaces(self):
        """获取可用网络接口"""
        try:
            from scapy.all import get_if_list, get_if_addr, conf
            
            interfaces = []
            iface_list = get_if_list()
            
            for iface in iface_list:
                try:
                    # 获取IP地址
                    ip_addr = get_if_addr(iface)
                    
                    # 跳过无效接口
                    if not ip_addr or ip_addr == '0.0.0.0':
                        continue
                    
                    # 判断接口类型
                    iface_lower = iface.lower()
                    if 'loopback' in iface_lower:
                        iface_type = '🔄 回环'
                    elif 'wi-fi' in iface_lower or 'wireless' in iface_lower or 'wlan' in iface_lower:
                        iface_type = '📡 无线'
                    elif 'ethernet' in iface_lower or 'eth' in iface_lower:
                        iface_type = '🔌 有线'
                    else:
                        iface_type = '🌐 网络'
                    
                    # 创建友好的描述
                    description = f"{iface_type} - {ip_addr}"
                    
                    interfaces.append({
                        'name': iface,
                        'description': description,
                        'ip': ip_addr
                    })
                except Exception as e:
                    continue
            
            # 如果没有找到接口，返回默认接口
            if not interfaces:
                try:
                    default_iface = conf.iface
                    interfaces = [{
                        'name': default_iface,
                        'description': f'🌐 默认接口',
                        'ip': ''
                    }]
                except:
                    pass
            
            return interfaces
        except Exception as e:
            print(f"获取网络接口失败: {e}")
            return []
    
    def read_pcap(self, filepath):
        """读取PCAP文件"""
        try:
            packets = rdpcap(filepath)
            parsed_packets = []
            
            for i, pkt in enumerate(packets):
                parsed = self._parse_packet(pkt, i)
                if parsed:
                    parsed_packets.append(parsed)
            
            return parsed_packets
        except Exception as e:
            raise Exception(f"读取PCAP文件失败: {e}")
    
    def start_capture(self, interface=None, filter_str='', callback=None):
        """开始实时捕获"""
        self.running = True
        self.packets = []  # 重置数据包列表
        
        def packet_handler(pkt):
            if not self.running:
                return
            
            parsed = self._parse_packet(pkt, len(self.packets))
            if parsed:
                self.packets.append(parsed)
                
                # 如果有回调函数，立即调用
                if callback:
                    try:
                        callback(parsed)
                    except Exception as e:
                        print(f"回调函数执行错误: {e}")
                        import traceback
                        traceback.print_exc()
        
        try:
            print(f"正在监听接口: {interface or '默认接口'}")
            if filter_str:
                print(f"应用过滤器: {filter_str}")
            
            # 开始嗅探 - store=False避免内存占用
            sniff(
                iface=interface if interface else None,
                filter=filter_str if filter_str else None,
                prn=packet_handler,
                stop_filter=lambda x: not self.running,
                store=False  # 不在sniff中存储，我们在handler中手动存储
            )
            
            print(f"监听结束，共捕获 {len(self.packets)} 个数据包")
            
        except Exception as e:
            print(f"捕获失败: {e}")
            import traceback
            traceback.print_exc()
            raise Exception(f"捕获失败: {e}")
    
    def stop_capture(self):
        """停止捕获"""
        self.running = False
    
    def apply_bpf_filter(self, packets, filter_str):
        """应用BPF过滤器到数据包列表"""
        if not filter_str:
            return packets
        
        filter_str = filter_str.lower().strip()
        filtered = []
        
        for pkt in packets:
            try:
                if self._match_filter(pkt, filter_str):
                    filtered.append(pkt)
            except Exception as e:
                continue
        
        return filtered
    
    def _match_filter(self, pkt, filter_str):
        """匹配单个数据包与过滤规则"""
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
                net_prefix = '.'.join(net_base.split('.')[:3])
                return src.startswith(net_prefix) or dst.startswith(net_prefix)
        
        return False
    
    def _parse_packet(self, pkt, index):
        """解析数据包"""
        try:
            packet_data = {
                'index': index,
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
                    
                    # HTTP检测
                    if pkt[TCP].dport in [80, 8080] or pkt[TCP].sport in [80, 8080]:
                        packet_data['protocol'] = 'HTTP'
                        if Raw in pkt:
                            try:
                                payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                                packet_data['payload'] = payload[:500]  # 限制长度
                            except:
                                pass
                    
                    # HTTPS
                    elif pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                        packet_data['protocol'] = 'HTTPS'
                    
                    # SSH
                    elif pkt[TCP].dport == 22 or pkt[TCP].sport == 22:
                        packet_data['protocol'] = 'SSH'
                    
                    # FTP
                    elif pkt[TCP].dport in [20, 21] or pkt[TCP].sport in [20, 21]:
                        packet_data['protocol'] = 'FTP'
                
                # UDP
                elif UDP in pkt:
                    packet_data['protocol'] = 'UDP'
                    packet_data['src_port'] = pkt[UDP].sport
                    packet_data['dst_port'] = pkt[UDP].dport
                    
                    # DNS
                    if DNS in pkt or pkt[UDP].dport == 53 or pkt[UDP].sport == 53:
                        packet_data['protocol'] = 'DNS'
                        if DNS in pkt:
                            try:
                                query = pkt[DNS].qd.qname.decode() if pkt[DNS].qd else ''
                                packet_data['payload'] = f"DNS Query: {query}"
                            except:
                                pass
                
                # ICMP
                elif ICMP in pkt:
                    packet_data['protocol'] = 'ICMP'
                    packet_data['payload'] = f"Type: {pkt[ICMP].type}, Code: {pkt[ICMP].code}"
            
            # 提取payload（如果还没有）
            if not packet_data['payload'] and Raw in pkt:
                try:
                    payload = pkt[Raw].load
                    if len(payload) > 0:
                        # 尝试解码
                        try:
                            packet_data['payload'] = payload.decode('utf-8', errors='ignore')[:500]
                        except:
                            packet_data['payload'] = payload.hex()[:500]
                except:
                    pass
            
            return packet_data
            
        except Exception as e:
            print(f"解析数据包失败: {e}")
            return None
