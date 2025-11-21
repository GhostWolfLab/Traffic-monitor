#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Traffic Monitor - 异常流量检测工具
基于机器学习的网络流量异常检测与可视化
"""

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from detector import TrafficDetector
import os
import time
import threading
from queue import Queue
from datetime import datetime

# 尝试导入完整的capture模块（需要Scapy）
try:
    from capture import TrafficCapture
    SCAPY_AVAILABLE = True
    print("✓ 使用完整版 capture.py (支持实时监听)")
except ImportError:
    from capture_simple import TrafficCapture
    SCAPY_AVAILABLE = False
    print("⚠️ 使用简化版 capture_simple.py (仅支持PCAP分析)")
    print("   安装Scapy以启用实时监听: pip install scapy")

app = Flask(__name__)
app.config['SECRET_KEY'] = 'traffic-monitor-secret-key'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB

CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# 全局变量
detector = TrafficDetector(method='isolation_forest')
capture = TrafficCapture()
monitoring_active = False
monitoring_thread = None
packet_queue = Queue()  # 数据包队列
current_pcap_file = None  # 当前保存的PCAP文件路径
captured_packets_buffer = []  # 捕获的原始数据包缓冲区

# 确保上传目录存在
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('captures', exist_ok=True)  # 创建captures目录用于保存监听数据

@app.route('/')
def index():
    """主页"""
    return render_template('index.html')

@app.route('/api/upload_pcap', methods=['POST'])
def upload_pcap():
    """上传并分析PCAP文件"""
    try:
        print("\n" + "="*60)
        print("📤 开始处理PCAP上传...")
        
        if 'file' not in request.files:
            return jsonify({'error': '没有上传文件'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': '文件名为空'}), 400
        
        print(f"📁 文件名: {file.filename}")
        
        # 获取BPF过滤器（可选）
        bpf_filter = request.form.get('filter', '').strip()
        if bpf_filter:
            print(f"🔍 BPF过滤器: {bpf_filter}")
        
        # 保存文件
        filename = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filename)
        print(f"💾 文件已保存: {filename}")
        
        # 读取PCAP
        print("📖 正在读取PCAP文件...")
        packets = capture.read_pcap(filename)
        print(f"✅ 读取完成，共 {len(packets)} 个数据包")
        
        if not packets:
            return jsonify({'error': '无法读取PCAP文件或文件为空'}), 400
        
        # 应用BPF过滤器
        if bpf_filter:
            print(f"🔍 应用BPF过滤器: {bpf_filter}")
            packets = capture.apply_bpf_filter(packets, bpf_filter)
            print(f"✅ 过滤后剩余 {len(packets)} 个数据包")
        
        # 分析数据包
        print("🧠 开始分析数据包...")
        results = detector.analyze_packets(packets)
        print(f"✅ 分析完成")
        
        # 准备响应数据 - 匹配前端期望的格式
        response = {
            'success': True,
            'total_packets': len(packets),
            'packets_count': len(packets),
            'anomaly_count': len(results['anomalies']),
            'anomalies': results['anomalies'],
            'packets': results['all_results'],
            'patterns': {},
            'filter_applied': bool(bpf_filter),
            'total_count': len(packets)
        }
        
        # 统计各模式数量
        for pattern_emoji, pattern_packets in results['patterns'].items():
            if pattern_packets:
                pattern_info = pattern_packets[0]['pattern']
                response['patterns'][pattern_emoji] = {
                    'emoji': pattern_emoji,
                    'name': pattern_info['name'],
                    'description': pattern_info['description'],
                    'count': len(pattern_packets)
                }
        
        print(f"📊 结果: {response['total_packets']} 个包, {response['anomaly_count']} 个异常")
        print("="*60 + "\n")
        
        return jsonify(response)
        
    except Exception as e:
        print(f"❌ 处理PCAP文件时出错: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/set_detection_method', methods=['POST'])
def set_detection_method():
    """设置检测方法"""
    try:
        data = request.get_json()
        method = data.get('method', 'isolation_forest')
        
        if detector.set_method(method):
            return jsonify({'success': True, 'method': method})
        else:
            return jsonify({'error': '不支持的检测方法'}), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/get_interfaces', methods=['GET'])
def get_interfaces():
    """获取网络接口列表"""
    try:
        interfaces = capture.get_interfaces()
        return jsonify({
            'interfaces': interfaces,
            'scapy_available': SCAPY_AVAILABLE
        })
    except Exception as e:
        print(f"获取网络接口失败: {e}")
        return jsonify({'error': str(e), 'interfaces': []}), 500

@app.route('/api/start_monitor', methods=['POST'])
def start_monitor():
    """开始实时监听"""
    global monitoring_active, monitoring_thread
    
    if not SCAPY_AVAILABLE:
        return jsonify({'error': 'Scapy未安装，无法进行实时监听'}), 400
    
    if monitoring_active:
        return jsonify({'error': '监听已在运行中'}), 400
    
    try:
        data = request.get_json()
        interface = data.get('interface', '')
        filter_str = data.get('filter', '')
        
        monitoring_active = True
        
        # 清空队列和缓冲区
        while not packet_queue.empty():
            packet_queue.get()
        
        global captured_packets_buffer, current_pcap_file
        captured_packets_buffer = []
        
        # 生成PCAP文件名（使用当前时间）
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        current_pcap_file = os.path.join('captures', f'capture_{timestamp}.pcap')
        print(f"💾 将保存数据包到: {current_pcap_file}")
        
        # 启动两个线程：捕获线程和发送线程
        capture_thread = threading.Thread(
            target=packet_capture_worker,
            args=(interface, filter_str),
            daemon=True
        )
        sender_thread = threading.Thread(
            target=packet_sender_worker,
            daemon=True
        )
        
        capture_thread.start()
        sender_thread.start()
        
        return jsonify({'success': True, 'message': '开始监听'})
        
    except Exception as e:
        monitoring_active = False
        print(f"启动监听失败: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/stop_monitor', methods=['POST'])
def stop_monitor():
    """停止实时监听"""
    global monitoring_active, current_pcap_file, captured_packets_buffer
    
    monitoring_active = False
    capture.stop_capture()
    
    # 保存捕获的数据包到PCAP文件
    saved_file = None
    packet_count = 0
    
    if captured_packets_buffer and current_pcap_file:
        try:
            from scapy.all import wrpcap
            wrpcap(current_pcap_file, captured_packets_buffer)
            packet_count = len(captured_packets_buffer)
            saved_file = current_pcap_file
            print(f"✅ 已保存 {packet_count} 个数据包到: {current_pcap_file}")
        except Exception as e:
            print(f"❌ 保存PCAP文件失败: {e}")
            import traceback
            traceback.print_exc()
    
    # 清理
    captured_packets_buffer = []
    current_pcap_file = None
    
    return jsonify({
        'success': True, 
        'message': '停止监听',
        'saved_file': saved_file,
        'packet_count': packet_count
    })

def packet_capture_worker(interface, filter_str):
    """数据包捕获线程 - 只负责捕获，放入队列"""
    global monitoring_active, captured_packets_buffer
    
    total_captured = 0
    
    def packet_callback(packet_data):
        """捕获到数据包后放入队列"""
        nonlocal total_captured
        
        if not monitoring_active:
            return
        
        try:
            total_captured += 1
            
            # 分析数据包
            result = detector.analyze_single_packet(packet_data)
            
            # 组装数据
            packet_info = {
                'timestamp': packet_data.get('timestamp', time.time()),
                'src': packet_data.get('src', ''),
                'dst': packet_data.get('dst', ''),
                'protocol': packet_data.get('protocol', ''),
                'length': packet_data.get('length', 0),
                'src_port': packet_data.get('src_port', 0),
                'dst_port': packet_data.get('dst_port', 0),
                'is_anomaly': result['is_anomaly'],
                'score': result['score'],
                'pattern': result['pattern'],
                'flags': packet_data.get('flags', {}),
                'payload': packet_data.get('payload', '')[:200]
            }
            
            # 放入队列（非阻塞）
            packet_queue.put(packet_info)
            
            if total_captured % 50 == 0:
                print(f"🎣 已捕获 {total_captured} 个数据包")
            
        except Exception as e:
            print(f"❌ 捕获处理错误: {e}")
    
    try:
        print(f"🚀 捕获线程启动: {interface or '默认'}")
        if filter_str:
            print(f"🔍 BPF过滤器: {filter_str}")
        
        # 分批捕获，避免长时间阻塞
        # 每次捕获50个包就让线程有机会调度
        from scapy.all import sniff, conf
        
        actual_interface = interface if interface else conf.iface
        print(f"正在监听接口: {actual_interface}")
        
        while monitoring_active:
            try:
                # 捕获最多50个包，然后让出控制权
                packets = sniff(
                    iface=actual_interface,
                    filter=filter_str if filter_str else None,
                    count=50,  # 每次只捕获50个
                    timeout=2,  # 2秒超时
                    store=True
                )
                
                # 保存原始数据包到缓冲区（用于保存PCAP）
                captured_packets_buffer.extend(packets)
                
                # 处理这批数据包
                for pkt in packets:
                    if not monitoring_active:
                        break
                    parsed = capture._parse_packet(pkt, total_captured)
                    if parsed:
                        packet_callback(parsed)
                
                # 短暂休眠，让其他线程有机会运行
                time.sleep(0.01)
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"⚠️ 捕获批次错误: {e}")
                time.sleep(0.5)
        
        print(f"✅ 捕获线程结束，共捕获 {total_captured} 个数据包")
        
    except Exception as e:
        print(f"❌ 捕获线程错误: {e}")
        import traceback
        traceback.print_exc()
        monitoring_active = False
        
        while monitoring_active:
            try:
                # 捕获最多50个包，然后让出控制权
                packets = sniff(
                    iface=actual_interface,
                    filter=filter_str if filter_str else None,
                    count=50,  # 每次只捕获50个
                    timeout=2,  # 2秒超时
                    store=True
                )
                
                # 处理这批数据包
                for pkt in packets:
                    if not monitoring_active:
                        break
                    parsed = capture._parse_packet(pkt, total_captured)
                    if parsed:
                        packet_callback(parsed)
                
                # 短暂休眠，让其他线程有机会运行
                time.sleep(0.01)
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"⚠️ 捕获批次错误: {e}")
                time.sleep(0.5)
        
        print(f"✅ 捕获线程结束，共捕获 {total_captured} 个数据包")
        
    except Exception as e:
        print(f"❌ 捕获线程错误: {e}")
        import traceback
        traceback.print_exc()
        monitoring_active = False

def packet_sender_worker():
    """数据包发送线程 - 从队列取数据并通过WebSocket发送"""
    global monitoring_active
    
    packet_count = 0
    
    try:
        print("📡 发送线程启动")
        
        while monitoring_active or not packet_queue.empty():
            try:
                # 从队列获取数据（超时1秒）
                packet_info = packet_queue.get(timeout=1)
                packet_count += 1
                
                # 通过WebSocket发送
                socketio.emit('packet', packet_info)
                
                # 每10个包打印一次
                if packet_count % 10 == 0:
                    print(f"✓ 已发送 {packet_count} 个数据包到前端")
                
                packet_queue.task_done()
                
            except:
                # 队列为空，继续等待
                continue
        
        print(f"✅ 发送线程结束，共发送 {packet_count} 个数据包")
        
    except Exception as e:
        print(f"❌ 发送线程错误: {e}")
        import traceback
        traceback.print_exc()

@socketio.on('connect')
def handle_connect():
    """客户端连接"""
    print('客户端已连接')
    emit('connected', {'data': 'Connected'})

@socketio.on('disconnect')
def handle_disconnect():
    """客户端断开"""
    print('客户端已断开')

if __name__ == '__main__':
    print("=" * 60)
    print("🚀 Traffic Monitor 启动中...")
    print("=" * 60)
    print(f"📊 检测方法: {detector.method}")
    print(f"🔧 Scapy支持: {'✓ 已启用' if SCAPY_AVAILABLE else '✗ 未安装'}")
    print(f"🌐 访问地址: http://localhost:5000")
    print("=" * 60)
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
