#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
异常检测模块 - 支持多种检测算法
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from collections import defaultdict, deque
from datetime import datetime, timedelta
import pickle
import os

class TrafficDetector:
    """流量异常检测器"""
    
    def __init__(self, method='isolation_forest'):
        self.method = method
        self.scaler = StandardScaler()
        self.models = {
            'isolation_forest': None,
            'autoencoder': None,
            'statistical': None
        }
        self.baseline = None
        self.traffic_history = defaultdict(lambda: deque(maxlen=100))
        
        # 动物模式定义
        self.animal_patterns = {
            '🦜': {
                'name': '喋喋不休的鹦鹉',
                'desc': '高频小包通信',
                'condition': lambda f: f['packet_rate'] > 50 and f['avg_size'] < 200
            },
            '🐊': {
                'name': '潜伏的鳄鱼',
                'desc': '长时间静默后突发大流量',
                'condition': lambda f: f['burst_ratio'] > 5 and f['silence_duration'] > 300
            },
            '🦈': {
                'name': '游弋的鲨鱼',
                'desc': '端口扫描行为',
                'condition': lambda f: f['unique_ports'] > 20 and f['avg_size'] < 100
            },
            '🐘': {
                'name': '笨重的大象',
                'desc': '单次大数据传输',
                'condition': lambda f: f['avg_size'] > 5000 and f['packet_rate'] < 10
            },
            '🦎': {
                'name': '变色龙',
                'desc': '协议频繁切换',
                'condition': lambda f: f['protocol_diversity'] > 0.7
            },
            '🐝': {
                'name': '忙碌的蜜蜂',
                'desc': '多目标通信',
                'condition': lambda f: f['unique_dsts'] > 15
            },
            '🦇': {
                'name': '夜行蝙蝠',
                'desc': '非常规端口通信',
                'condition': lambda f: f['uncommon_ports_ratio'] > 0.6
            },
            '🐍': {
                'name': '盘旋的蟒蛇',
                'desc': '持续稳定流量',
                'condition': lambda f: f['packet_rate'] > 20 and f['std_size'] < 50
            },
            '🦅': {
                'name': '俯冲的老鹰',
                'desc': 'SYN扫描特征',
                'condition': lambda f: f['syn_ratio'] > 0.8 and f['packet_rate'] > 30
            },
            '🐢': {
                'name': '缓慢的乌龟',
                'desc': '慢速扫描',
                'condition': lambda f: f['packet_rate'] < 5 and f['unique_ports'] > 10
            }
        }
        
        self._init_models()
    
    def _init_models(self):
        """初始化检测模型"""
        # Isolation Forest
        self.models['isolation_forest'] = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        
        # Autoencoder (延迟初始化)
        self.models['autoencoder'] = None
        self.autoencoder_trained = False
        
        # 统计基线模型
        self.models['statistical'] = {
            'thresholds': {
                'packet_rate': {'mean': 0, 'std': 0},
                'avg_size': {'mean': 0, 'std': 0},
                'unique_dsts': {'mean': 0, 'std': 0},
                'protocol_diversity': {'mean': 0, 'std': 0}
            },
            'trained': False
        }
    
    def set_method(self, method):
        """设置检测方法"""
        if method in self.models:
            self.method = method
            return True
        return False
    
    def extract_features(self, packets):
        """从数据包中提取特征"""
        features = []
        
        for i, packet in enumerate(packets):
            # 计算时间窗口内的统计特征
            window_packets = packets[max(0, i-50):i+1]
            
            feature = self._compute_packet_features(packet, window_packets)
            features.append(feature)
        
        return features
    
    def _compute_packet_features(self, packet, window_packets):
        """计算单个数据包的特征"""
        # 基础特征
        feature_dict = {
            'length': packet.get('length', 0),
            'protocol': self._encode_protocol(packet.get('protocol', 'OTHER')),
            'src_port': packet.get('src_port', 0),
            'dst_port': packet.get('dst_port', 0),
        }
        
        # 窗口统计特征
        if len(window_packets) > 0:
            sizes = [p.get('length', 0) for p in window_packets]
            dsts = [p.get('dst', '') for p in window_packets]
            protocols = [p.get('protocol', '') for p in window_packets]
            ports = [p.get('dst_port', 0) for p in window_packets]
            
            # 计算时间特征
            timestamps = [p.get('timestamp', 0) for p in window_packets]
            if len(timestamps) > 1:
                time_diffs = np.diff(timestamps)
                packet_rate = len(window_packets) / (max(timestamps) - min(timestamps) + 0.001)
            else:
                packet_rate = 0
                time_diffs = [0]
            
            # 流量统计
            feature_dict.update({
                'packet_rate': packet_rate,
                'avg_size': np.mean(sizes),
                'std_size': np.std(sizes),
                'unique_dsts': len(set(dsts)),
                'unique_ports': len(set(ports)),
                'protocol_diversity': len(set(protocols)) / len(protocols) if protocols else 0,
                'uncommon_ports_ratio': sum(1 for p in ports if p > 10000) / len(ports) if ports else 0
            })
            
            # 突发特征
            if len(time_diffs) > 0:
                avg_interval = np.mean(time_diffs)
                max_interval = np.max(time_diffs)
                feature_dict['burst_ratio'] = max_interval / (avg_interval + 0.001)
                feature_dict['silence_duration'] = max_interval
            else:
                feature_dict['burst_ratio'] = 0
                feature_dict['silence_duration'] = 0
            
            # SYN标志统计
            syn_count = sum(1 for p in window_packets if p.get('flags', {}).get('syn', False))
            feature_dict['syn_ratio'] = syn_count / len(window_packets) if window_packets else 0
        else:
            # 默认值
            feature_dict.update({
                'packet_rate': 0, 'avg_size': 0, 'std_size': 0,
                'unique_dsts': 0, 'unique_ports': 0, 'protocol_diversity': 0,
                'uncommon_ports_ratio': 0, 'burst_ratio': 0, 'silence_duration': 0,
                'syn_ratio': 0
            })
        
        return feature_dict
    
    def _encode_protocol(self, protocol):
        """编码协议类型"""
        protocol_map = {
            'TCP': 1, 'UDP': 2, 'ICMP': 3, 'HTTP': 4, 
            'HTTPS': 5, 'DNS': 6, 'SSH': 7, 'FTP': 8
        }
        return protocol_map.get(protocol.upper(), 0)
    
    def train(self, packets):
        """训练模型"""
        features = self.extract_features(packets)
        feature_vectors = self._dict_to_vector(features)
        
        if self.method == 'isolation_forest':
            self.models['isolation_forest'].fit(feature_vectors)
        
        elif self.method == 'statistical':
            # 计算统计基线
            for key in self.models['statistical']['thresholds']:
                values = [f[key] for f in features]
                self.models['statistical']['thresholds'][key] = {
                    'mean': np.mean(values),
                    'std': np.std(values)
                }
            self.models['statistical']['trained'] = True
        
        return True
    
    def _dict_to_vector(self, feature_dicts):
        """将特征字典转换为向量"""
        keys = ['length', 'protocol', 'src_port', 'dst_port', 'packet_rate', 
                'avg_size', 'std_size', 'unique_dsts', 'unique_ports',
                'protocol_diversity', 'uncommon_ports_ratio', 'burst_ratio',
                'silence_duration', 'syn_ratio']
        
        vectors = []
        for fd in feature_dicts:
            vector = [fd.get(k, 0) for k in keys]
            vectors.append(vector)
        
        return np.array(vectors)
    
    def detect_anomalies(self, features):
        """检测异常"""
        feature_vectors = self._dict_to_vector(features)
        
        if self.method == 'isolation_forest':
            predictions = self.models['isolation_forest'].predict(feature_vectors)
            scores = self.models['isolation_forest'].score_samples(feature_vectors)
            anomalies = predictions == -1
            
        elif self.method == 'autoencoder':
            return self._detect_autoencoder(feature_vectors, features)
            
        elif self.method == 'statistical':
            anomalies = []
            scores = []
            
            for feature in features:
                is_anomaly = False
                anomaly_score = 0
                
                for key, threshold in self.models['statistical']['thresholds'].items():
                    value = feature.get(key, 0)
                    mean = threshold['mean']
                    std = threshold['std']
                    
                    if std > 0:
                        z_score = abs(value - mean) / std
                        if z_score > 3:  # 3-sigma规则
                            is_anomaly = True
                        anomaly_score = max(anomaly_score, z_score / 3)
                
                anomalies.append(is_anomaly)
                scores.append(-anomaly_score if is_anomaly else 0)
        
        else:
            anomalies = [False] * len(features)
            scores = [0] * len(features)
        
        return anomalies, scores
    
    def _detect_autoencoder(self, feature_vectors, features):
        """使用自编码器检测异常"""
        try:
            # 尝试导入TensorFlow
            try:
                import tensorflow as tf
                from tensorflow import keras
                from tensorflow.keras import layers
                # 设置日志级别，减少输出
                tf.get_logger().setLevel('ERROR')
            except ImportError:
                print("⚠️ TensorFlow未安装，Autoencoder方法不可用")
                print("   安装命令: pip install tensorflow")
                print("   降级使用 Isolation Forest")
                # 降级到Isolation Forest
                predictions = self.models['isolation_forest'].predict(feature_vectors)
                scores = self.models['isolation_forest'].score_samples(feature_vectors)
                return predictions == -1, scores
            
            # 如果模型未训练，创建并训练
            if not self.autoencoder_trained or self.models['autoencoder'] is None:
                print("🧠 初始化 Autoencoder 模型...")
                
                # 检查数据量
                if len(feature_vectors) < 50:
                    print(f"⚠️ 数据量不足({len(feature_vectors)}个)，至少需要50个样本")
                    print("   降级使用 Isolation Forest")
                    predictions = self.models['isolation_forest'].predict(feature_vectors)
                    scores = self.models['isolation_forest'].score_samples(feature_vectors)
                    return predictions == -1, scores
                
                # 标准化特征
                normalized_features = self.scaler.fit_transform(feature_vectors)
                
                # 定义自编码器结构
                input_dim = normalized_features.shape[1]
                encoding_dim = max(4, input_dim // 2)
                
                # 编码器
                input_layer = keras.Input(shape=(input_dim,))
                encoded = layers.Dense(encoding_dim * 2, activation='relu')(input_layer)
                encoded = layers.Dropout(0.2)(encoded)
                encoded = layers.Dense(encoding_dim, activation='relu')(encoded)
                
                # 解码器
                decoded = layers.Dense(encoding_dim * 2, activation='relu')(encoded)
                decoded = layers.Dropout(0.2)(decoded)
                decoded = layers.Dense(input_dim, activation='linear')(decoded)
                
                # 完整模型
                autoencoder = keras.Model(input_layer, decoded)
                autoencoder.compile(
                    optimizer=keras.optimizers.Adam(learning_rate=0.001),
                    loss='mse'
                )
                
                # 训练模型
                print(f"📚 训练 Autoencoder (样本数: {len(normalized_features)})...")
                history = autoencoder.fit(
                    normalized_features, normalized_features,
                    epochs=50,
                    batch_size=min(32, len(normalized_features) // 2),
                    shuffle=True,
                    verbose=0,
                    validation_split=0.1
                )
                
                self.models['autoencoder'] = autoencoder
                self.autoencoder_trained = True
                final_loss = history.history['loss'][-1]
                print(f"✅ Autoencoder 训练完成 (最终loss: {final_loss:.4f})")
            
            # 标准化当前特征
            normalized_features = self.scaler.transform(feature_vectors)
            
            # 使用模型进行预测
            reconstructed = self.models['autoencoder'].predict(normalized_features, verbose=0)
            
            # 计算重构误差（MSE）
            mse = np.mean(np.power(normalized_features - reconstructed, 2), axis=1)
            
            # 使用自适应阈值（基于重构误差的分位数）
            threshold = np.percentile(mse, 90)  # 90分位数作为阈值
            
            # 标记异常（重构误差大于阈值）
            anomalies = mse > threshold
            
            # 归一化分数到[-1, 1]范围
            # 重构误差越大，异常分数越低（越负）
            max_mse = np.max(mse)
            if max_mse > 0:
                # 将MSE映射到[-1, 0]区间，异常的分数更负
                scores = -1 * (mse / max_mse)
            else:
                scores = np.zeros(len(mse))
            
            return anomalies, scores
            
        except Exception as e:
            print(f"❌ Autoencoder 检测失败: {e}")
            print("   降级使用 Isolation Forest")
            predictions = self.models['isolation_forest'].predict(feature_vectors)
            scores = self.models['isolation_forest'].score_samples(feature_vectors)
            return predictions == -1, scores
    
    def classify_pattern(self, feature):
        """分类流量模式（动物代号）"""
        for emoji, pattern in self.animal_patterns.items():
            try:
                if pattern['condition'](feature):
                    return {
                        'emoji': emoji,
                        'name': pattern['name'],
                        'description': pattern['desc']
                    }
            except:
                continue
        
        return {
            'emoji': '🐱',
            'name': '普通流量',
            'description': '正常通信模式'
        }
    
    def analyze_packets(self, packets):
        """分析数据包列表"""
        if len(packets) < 10:
            return {
                'anomalies': [],
                'patterns': {}
            }
        
        # 提取特征
        features = self.extract_features(packets)
        
        # 训练模型（如果需要）
        if not self.models['statistical']['trained']:
            self.train(packets)
        
        # 检测异常
        anomalies, scores = self.detect_anomalies(features)
        
        # 分类模式
        patterns = defaultdict(list)
        results = []
        
        for i, (packet, feature, is_anomaly, score) in enumerate(zip(packets, features, anomalies, scores)):
            pattern = self.classify_pattern(feature)
            
            result = {
                'index': i,
                'timestamp': packet.get('timestamp', 0),
                'src': packet.get('src', ''),
                'dst': packet.get('dst', ''),
                'protocol': packet.get('protocol', ''),
                'length': packet.get('length', 0),
                'is_anomaly': bool(is_anomaly),
                'score': float(score),
                'pattern': pattern,
                'payload': packet.get('payload', '')
            }
            
            results.append(result)
            
            if is_anomaly:
                patterns[pattern['emoji']].append(result)
        
        return {
            'anomalies': [r for r in results if r['is_anomaly']],
            'patterns': dict(patterns),
            'all_results': results
        }
    
    def analyze_single_packet(self, packet):
        """分析单个数据包（实时监听）"""
        # 将数据包添加到历史记录
        src = packet.get('src', 'unknown')
        self.traffic_history[src].append(packet)
        
        # 获取窗口数据
        window_packets = list(self.traffic_history[src])
        
        # 计算特征
        feature = self._compute_packet_features(packet, window_packets)
        
        # 检测异常
        if self.models['statistical']['trained']:
            feature_vector = self._dict_to_vector([feature])
            
            if self.method == 'isolation_forest':
                prediction = self.models['isolation_forest'].predict(feature_vector)[0]
                score = self.models['isolation_forest'].score_samples(feature_vector)[0]
                is_anomaly = prediction == -1
            else:
                is_anomaly = False
                score = 0
                for key, threshold in self.models['statistical']['thresholds'].items():
                    value = feature.get(key, 0)
                    mean = threshold['mean']
                    std = threshold['std']
                    if std > 0:
                        z_score = abs(value - mean) / std
                        if z_score > 3:
                            is_anomaly = True
                        score = max(score, z_score / 3)
                score = -score if is_anomaly else 0
        else:
            is_anomaly = False
            score = 0
        
        # 分类模式
        pattern = self.classify_pattern(feature)
        
        return {
            'is_anomaly': is_anomaly,
            'score': float(score),
            'pattern': pattern,
            'feature': feature
        }
