#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
生成示例PCAP文件用于测试流量监测工具
包含多种异常流量模式
"""

from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
import random
import time

def generate_sample_pcap(filename='sample_traffic.pcap'):
    """生成包含多种流量模式的示例PCAP文件"""
    packets = []
    
    print("正在生成示例流量...")
    
    # 1. 正常HTTP流量
    print("  - 添加正常HTTP流量")
    for i in range(20):
        pkt = IP(dst=f"93.184.216.{random.randint(1, 50)}")/TCP(dport=80, sport=random.randint(1024, 65535))
        packets.append(pkt)
    
    # 2. DDoS模拟 - 大量SYN包到同一目标
    print("  - 添加DDoS流量模式 (🦜 鹦鹉)")
    target_ip = "192.168.1.100"
    for i in range(50):
        pkt = IP(dst=target_ip)/TCP(dport=80, flags="S", sport=random.randint(1024, 65535))
        packets.append(pkt)
    
    # 3. 端口扫描 - 扫描同一主机的多个端口
    print("  - 添加端口扫描流量 (🐊 鳄鱼)")
    scan_target = "10.0.0.50"
    for port in range(20, 120, 2):
        pkt = IP(dst=scan_target)/TCP(dport=port, flags="S")
        packets.append(pkt)
    
    # 4. 大流量传输 - 大数据包
    print("  - 添加大流量传输 (🦈 鲨鱼)")
    for i in range(15):
        payload = "X" * random.randint(1200, 1400)
        pkt = IP(dst="172.16.0.10")/TCP(dport=443)/Raw(load=payload)
        packets.append(pkt)
    
    # 5. DNS流量
    print("  - 添加正常DNS流量")
    for i in range(25):
        pkt = IP(dst="8.8.8.8")/UDP(dport=53, sport=random.randint(1024, 65535))
        packets.append(pkt)
    
    # 6. C2通信模拟 - 定期beacon
    print("  - 添加C2通信模式 (🐍 蛇)")
    c2_server = "203.0.113.42"
    for i in range(10):
        pkt = IP(dst=c2_server)/TCP(dport=8443, sport=random.randint(49152, 65535))
        packets.append(pkt)
    
    # 7. ICMP流量
    print("  - 添加ICMP流量")
    for i in range(15):
        pkt = IP(dst=f"192.168.{random.randint(1, 10)}.{random.randint(1, 254)}")/ICMP()
        packets.append(pkt)
    
    # 8. 慢速扫描
    print("  - 添加慢速扫描 (🦎 蜥蜴)")
    slow_target = "10.10.10.10"
    for port in [21, 22, 23, 25, 80, 443, 3389, 8080]:
        pkt = IP(dst=slow_target)/TCP(dport=port, flags="S")
        packets.append(pkt)
    
    # 9. 数据渗透模拟
    print("  - 添加数据渗透模式 (🐘 大象)")
    for i in range(20):
        payload = "SENSITIVE_DATA_" + "A" * random.randint(500, 1000)
        pkt = IP(dst="198.51.100.5")/TCP(dport=443, sport=random.randint(1024, 65535))/Raw(load=payload)
        packets.append(pkt)
    
    # 10. 多目标扫描
    print("  - 添加多目标扫描 (🦅 鹰)")
    for i in range(30):
        target = f"192.168.{random.randint(1, 255)}.{random.randint(1, 254)}"
        pkt = IP(dst=target)/TCP(dport=random.choice([22, 80, 443, 3389]), flags="S")
        packets.append(pkt)
    
    # 11. UDP流量
    print("  - 添加UDP流量")
    for i in range(20):
        pkt = IP(dst=f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}")/UDP(dport=random.randint(1024, 65535))
        packets.append(pkt)
    
    # 12. 正常HTTPS流量
    print("  - 添加正常HTTPS流量")
    for i in range(25):
        pkt = IP(dst=f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}")/TCP(dport=443, sport=random.randint(1024, 65535))
        packets.append(pkt)
    
    # 混洗数据包模拟真实流量
    random.shuffle(packets)
    
    # 写入PCAP文件
    print(f"\n正在写入到 {filename}...")
    wrpcap(filename, packets)
    
    print(f"✓ 完成！生成了 {len(packets)} 个数据包")
    print(f"文件已保存: {filename}")
    print("\n流量模式说明:")
    print("  🦜 鹦鹉 - DDoS/SYN Flood")
    print("  🐊 鳄鱼 - 端口扫描")
    print("  🦈 鲨鱼 - 大流量传输")
    print("  🐍 蛇 - C2通信")
    print("  🦎 蜥蜴 - 慢速扫描")
    print("  🐘 大象 - 数据渗透")
    print("  🦅 鹰 - 多目标扫描")

if __name__ == '__main__':
    try:
        generate_sample_pcap('sample_traffic.pcap')
        print("\n可以使用以下命令启动应用并测试:")
        print("  python app.py")
        print("然后访问 http://localhost:5000 并上传 sample_traffic.pcap")
    except Exception as e:
        print(f"错误: {e}")
        print("\n提示: 请确保已安装 scapy 库")
        print("  pip install scapy")
