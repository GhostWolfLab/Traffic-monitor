# Traffic Monitor - 异常流量检测工具 🚀

<div align="center">

![流量监测](https://img.shields.io/badge/Style-Cyberpunk-00ffff?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python)
![Machine Learning](https://img.shields.io/badge/ML-Enabled-ff00ff?style=for-the-badge)

一个使用机器学习和统计模型检测网络异常的可视化工具。

</div>

## ✨ 特性

### 🔍 多种检测方法
- **Isolation Forest**: 基于孤立森林的异常检测
- **统计模型**: 基于历史基线的3-sigma规则检测
- **Autoencoder**: 深度学习异常检测（预留接口）

### 🦜 创意动物代号系统
使用emoji动物代表不同的流量模式：

| 动物 | 模式名称 | 特征描述 |
|------|---------|---------|
| 🦜 | 喋喋不休的鹦鹉 | 高频小包通信（可能是DDoS或扫描） |
| 🐊 | 潜伏的鳄鱼 | 长时间静默后突发大流量（可能是APT） |
| 🦈 | 游弋的鲨鱼 | 端口扫描行为 |
| 🐘 | 笨重的大象 | 单次大数据传输（可能是数据外泄） |
| 🦎 | 变色龙 | 协议频繁切换（可能是隐蔽隧道） |
| 🐝 | 忙碌的蜜蜂 | 多目标通信（可能是僵尸网络） |
| 🦇 | 夜行蝙蝠 | 非常规端口通信（可能是后门） |
| 🐍 | 盘旋的蟒蛇 | 持续稳定流量（可能是C2通信） |
| 🦅 | 俯冲的老鹰 | SYN扫描特征 |
| 🐢 | 缓慢的乌龟 | 慢速扫描（逃避检测） |

### 🎨 赛博朋克UI
- 炫酷的霓虹灯效果
- 实时流量动画
- 三栏式信息展示
- 响应式设计

### 📊 功能特点
- ✅ 实时网络流量监听
- ✅ PCAP文件分析
- ✅ 异常流量实时告警
- ✅ 详细的数据包信息展示
- ✅ 流量模式分类统计
- ✅ WebSocket实时推送

## 🛠️ 安装

### 系统要求
- Python 3.8+
- Windows/Linux/macOS
- 管理员权限（用于网络监听）

### 快速开始

1. **克隆或进入项目目录**
```bash
cd Traffic-monitor
```

2. **安装依赖**
```bash
pip install -r requirements.txt
```

3. **启动服务**
```bash
python app.py
```

4. **访问界面**
打开浏览器访问: `http://localhost:5000`

## 📖 使用指南

### 实时监听

1. 选择检测方法（Isolation Forest、统计模型 或 Autoencoder）
2. 选择网络接口（或留空自动选择）
3. 可选：设置BPF过滤器（如 `tcp port 80`）
4. 点击“开始监听”按钮
5. 实时查看检测到的异常流量

### 分析PCAP文件

1. 点击"上传PCAP"按钮
2. 选择.pcap或.pcapng文件
3. 等待分析完成
4. 查看检测结果和异常模式

### 查看详情

1. 在左侧面板点击任意数据包
2. 右侧面板显示详细信息：
   - 基本信息（时间、源地址、目标地址、协议）
   - 检测结果（异常状态、分数、流量模式）
   - 数据内容（Payload）

### 过滤功能

- 点击左上角的动物模式卡片
- 自动过滤显示该模式的所有数据包

## 🔧 配置选项

### 检测方法切换
```python
# 在界面中选择，或通过API设置
POST /api/set_detection_method
{
    "method": "isolation_forest"  // 或 "statistical", "autoencoder"
}
```

### BPF过滤器示例
```bash
# 只监听HTTP流量
tcp port 80

# 监听特定IP
host 192.168.1.100

# 监听TCP和UDP
tcp or udp

# 排除SSH流量
not port 22
```

## 🎯 异常检测算法

### Isolation Forest
- 基于随机森林的无监督学习
- 适合检测离群点
- 不需要标记数据
- 计算效率高

### 统计模型
- 基于历史流量基线
- 使用3-sigma规则
- 实时自适应
- 可解释性强

### Autoencoder 🆕
- 基于深度学习的重构误差检测
- 自动学习正常流量模式
- 对复杂异常更敏感
- **需要安装**: `pip install tensorflow`
- **数据要求**: 至少50个样本用于训练
- **自动降级**: 数据不足或TensorFlow未安装时自动使用Isolation Forest

### 特征提取
从数据包中提取14维特征：
- 数据包长度
- 协议类型
- 源/目标端口
- 数据包速率
- 平均/标准差大小
- 唯一目的地数量
- 唯一端口数量
- 协议多样性
- 非常规端口比例
- 突发比例
- 静默时长
- SYN标志比例

## 🚨 常见问题

### Q: 为什么需要管理员权限？
A: 网络流量捕获需要底层访问权限。在Linux/macOS上使用`sudo`，Windows上需要以管理员身份运行。

### Q: 监听不到流量？
A:
1. 确认有管理员权限
2. 检查网络接口是否正确
3. 确认防火墙没有阻止
4. 尝试使用其他网络接口

### Q: 如何提高检测准确率？
A:
1. 使用足够的训练数据（至少100个包）
2. 根据网络环境调整过滤器
3. 尝试不同的检测方法
4. 观察并学习动物模式特征

### Q: 如何使用 Autoencoder 方法？
A:
1. 安装 TensorFlow: `pip install tensorflow`
2. 界面选择 "Autoencoder" 检测方法
3. 至少提供50个数据包样本
4. 首次使用会自动训练模型（50 epochs）
5. 后续检测使用已训练模型
6. 如果数据不足或TensorFlow未安装，会自动降级到Isolation Forest

### Q: 支持哪些协议？
A: TCP, UDP, ICMP, HTTP, HTTPS, DNS, SSH, FTP 等常见协议。

## 🔐 安全提示

⚠️ **重要**: 此工具仅用于合法的网络安全研究和监控。

- 只监控您有权限的网络
- 遵守当地法律法规
- 不要用于非法目的
- 注意保护敏感数据

## 📊 性能优化

- 使用BPF过滤器减少无关流量
- 限制显示的数据包数量（最多1000个）
- WebSocket异步推送，不阻塞主线程
- 自动清理历史数据

## 🤝 贡献

欢迎提交Issue和Pull Request！

## 📝 许可证

MIT License

## 👨‍💻 作者

Ghost Wolf Lab
