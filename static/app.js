// Traffic Monitor - 前端交互逻辑

class TrafficMonitor {
    constructor() {
        this.socket = null;
        this.packets = [];
        this.patterns = {};
        this.selectedPacket = null;
        this.isMonitoring = false;
        
        this.init();
    }
    
    init() {
        // 检查必要元素是否存在
        const requiredElements = [
            'detection-method',
            'interface',
            'filter',
            'start-btn',
            'stop-btn',
            'upload-btn',
            'pcap-file',
            'clear-packets',
            'close-details',
            'patterns-list',
            'packets-list',
            'details-content'
        ];
        
        let allElementsPresent = true;
        requiredElements.forEach(id => {
            const el = document.getElementById(id);
            if (!el) {
                console.error(`✗ 缺少元素: #${id}`);
                allElementsPresent = false;
            } else {
                console.log(`✓ 找到元素: #${id}`);
            }
        });
        
        if (!allElementsPresent) {
            console.error('页面元素不完整，请检查HTML!');
            return;
        }
        
        console.log('✓ 所有必要元素已就绪');
        
        // 初始化Socket.IO连接
        this.socket = io();
        
        // 绑定事件
        this.bindEvents();
        
        // 加载网络接口
        this.loadInterfaces();
        
        // 连接状态
        this.socket.on('connect', () => {
            console.log('WebSocket已连接');
            this.updateStatus('已连接', 'success');
        });
        
        this.socket.on('disconnect', () => {
            console.log('WebSocket已断开');
            this.updateStatus('已断开', 'danger');
        });
        
        // 接收数据包
        this.socket.on('packet', (data) => {
            this.handlePacket(data);
        });
        
        // 错误处理
        this.socket.on('error', (data) => {
            this.showNotification(data.message, 'danger');
        });
    }
    
    bindEvents() {
        // 检测方法切换
        document.getElementById('detection-method').addEventListener('change', (e) => {
            this.setDetectionMethod(e.target.value);
        });
        
        // 开始监听
        document.getElementById('start-btn').addEventListener('click', () => {
            this.startMonitoring();
        });
        
        // 停止监听
        document.getElementById('stop-btn').addEventListener('click', () => {
            this.stopMonitoring();
        });
        
        // 上传PCAP - 使用箭头函数保持this上下文
        const uploadBtn = document.getElementById('upload-btn');
        const pcapFile = document.getElementById('pcap-file');
        
        if (uploadBtn && pcapFile) {
            uploadBtn.addEventListener('click', (e) => {
                e.preventDefault();
                pcapFile.click();
            });
            
            pcapFile.addEventListener('change', (e) => {
                if (e.target.files[0]) {
                    this.uploadPCAP(e.target.files[0]);
                }
            });
        } else {
            console.error('✗ 找不到上传按钮或文件输入元素!');
            console.error('upload-btn:', uploadBtn);
            console.error('pcap-file:', pcapFile);
        }
        
        // 清空数据包
        document.getElementById('clear-packets').addEventListener('click', () => {
            this.clearPackets();
        });
        
        // 关闭详情
        document.getElementById('close-details').addEventListener('click', () => {
            this.closeDetails();
        });
        
        // 帮助按钮
        document.getElementById('help-btn').addEventListener('click', () => {
            this.showHelp();
        });
        
        // 关闭帮助弹窗
        document.getElementById('close-help').addEventListener('click', () => {
            this.closeHelp();
        });
        
        // 点击弹窗外部关闭
        document.getElementById('help-modal').addEventListener('click', (e) => {
            if (e.target.id === 'help-modal') {
                this.closeHelp();
            }
        });
    }
    
    showHelp() {
        document.getElementById('help-modal').style.display = 'flex';
    }
    
    closeHelp() {
        document.getElementById('help-modal').style.display = 'none';
    }
    
    async loadInterfaces() {
        try {
            const response = await fetch('/api/get_interfaces');
            const data = await response.json();
            
            const select = document.getElementById('interface');
            
            // 清空现有选项
            select.innerHTML = '';
            
            if (data.interfaces && data.interfaces.length > 0) {
                data.interfaces.forEach(iface => {
                    const option = document.createElement('option');
                    option.value = iface.name;
                    
                    // 显示友好的描述，如果有的话
                    if (iface.description && iface.description !== iface.name) {
                        option.textContent = iface.description;
                        option.title = iface.name; // 悬停时显示完整名称
                    } else {
                        option.textContent = iface.name;
                    }
                    
                    select.appendChild(option);
                });
            } else {
                // 没有接口时显示提示
                const option = document.createElement('option');
                option.value = '';
                option.textContent = '未检测到网络接口';
                option.disabled = true;
                select.appendChild(option);
            }
            
            // 显示 Scapy 状态
            if (data.scapy_available === false) {
                this.showNotification('实时监听需要 Scapy。当前仅支持 PCAP 文件分析', 'warning');
            }
        } catch (error) {
            console.error('加载网络接口失败:', error);
            this.showNotification('获取网络接口失败', 'danger');
        }
    }
    
    async setDetectionMethod(method) {
        try {
            const response = await fetch('/api/set_detection_method', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({method})
            });
            
            const data = await response.json();
            if (data.success) {
                this.showNotification(`检测方法已切换: ${method}`, 'success');
            }
        } catch (error) {
            this.showNotification('切换失败: ' + error.message, 'danger');
        }
    }
    
    async startMonitoring() {
        const interfaceName = document.getElementById('interface').value;
        const filter = document.getElementById('filter').value;
        
        if (!interfaceName || interfaceName === '不支持') {
            this.showNotification('请选择有效的网络接口', 'danger');
            return;
        }
        
        try {
            const response = await fetch('/api/start_monitor', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({interface: interfaceName, filter})
            });
            
            const data = await response.json();
            if (data.success) {
                this.isMonitoring = true;
                this.updateStatus('监听中', 'success');
                document.getElementById('start-btn').disabled = true;
                document.getElementById('stop-btn').disabled = false;
                document.getElementById('interface').disabled = true;
                document.getElementById('filter').disabled = true;
                this.showNotification(`开始监听 ${interfaceName}`, 'success');
            } else if (data.error) {
                this.showNotification('启动失败: ' + data.error, 'danger');
            }
        } catch (error) {
            this.showNotification('启动失败: ' + error.message, 'danger');
        }
    }
    
    async stopMonitoring() {
        try {
            const response = await fetch('/api/stop_monitor', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'}
            });
            
            const data = await response.json();
            if (data.success) {
                this.isMonitoring = false;
                this.updateStatus('已停止', 'warning');
                document.getElementById('start-btn').disabled = false;
                document.getElementById('stop-btn').disabled = true;
                document.getElementById('interface').disabled = false;
                document.getElementById('filter').disabled = false;
                
                // 显示保存信息
                if (data.saved_file && data.packet_count > 0) {
                    this.showNotification(
                        `监听已停止，已保存 ${data.packet_count} 个数据包到: ${data.saved_file}`, 
                        'success'
                    );
                } else {
                    this.showNotification('已停止监听', 'warning');
                }
            }
        } catch (error) {
            this.showNotification('停止失败: ' + error.message, 'danger');
        }
    }
    
    async uploadPCAP(file) {
        if (!file) {
            this.showNotification('请选择文件', 'danger');
            return;
        }
        
        // 获取BPF过滤器
        const filter = document.getElementById('filter').value.trim();
        
        const formData = new FormData();
        formData.append('file', file);
        if (filter) {
            formData.append('filter', filter);
        }
        
        this.updateStatus('分析中', 'warning');
        this.showNotification('正在分析PCAP文件...', 'info');
        
        try {
            const response = await fetch('/api/upload_pcap', {
                method: 'POST',
                body: formData
            });
            
            const data = await response.json();
            
            if (data.success) {
                let message = `分析完成: ${data.packets_count}个数据包`;
                if (data.filter_applied) {
                    message += ` (过滤自${data.total_count}个)`;
                }
                if (data.anomalies.length > 0) {
                    message += `, ${data.anomalies.length}个异常`;
                }
                this.showNotification(message, 'success');
                
                // 显示结果
                this.displayPCAPResults(data);
                this.updateStatus('就绪', 'success');
            } else {
                this.showNotification('分析失败: ' + data.error, 'danger');
                this.updateStatus('错误', 'danger');
            }
        } catch (error) {
            this.showNotification('上传失败: ' + error.message, 'danger');
            this.updateStatus('错误', 'danger');
        }
    }
    
    displayPCAPResults(data) {
        // 清空当前数据
        this.clearPackets();
        
        // 如果有过滤器但没有异常，显示所有数据包
        if (data.filter_applied && data.packets && data.packets.length > 0) {
            // 显示过滤后的所有数据包
            data.packets.forEach(packet => {
                this.addPacketToUI({
                    ...packet,
                    is_anomaly: false,
                    index: this.packets.length
                });
                this.packets.push(packet);
            });
        }
        
        // 按模式分组（异常包）
        const patternGroups = {};
        
        data.anomalies.forEach(packet => {
            const emoji = packet.pattern.emoji;
            if (!patternGroups[emoji]) {
                patternGroups[emoji] = {
                    pattern: packet.pattern,
                    packets: []
                };
            }
            patternGroups[emoji].packets.push(packet);
            
            // 添加到全局packets
            this.packets.push(packet);
        });
        
        this.patterns = patternGroups;
        
        // 渲染
        this.renderPatterns();
        this.renderPackets(this.packets);
        
        // 更新计数
        this.updateCounts();
    }
    
    handlePacket(packet) {
        // 添加索引
        packet.index = this.packets.length;
        
        // 添加到数据包列表
        this.packets.unshift(packet);
        
        // 限制列表长度
        if (this.packets.length > 1000) {
            this.packets.pop();
        }
        
        // 如果是异常，添加到模式分组
        if (packet.is_anomaly) {
            const emoji = packet.pattern.emoji;
            if (!this.patterns[emoji]) {
                this.patterns[emoji] = {
                    pattern: packet.pattern,
                    packets: []
                };
            }
            this.patterns[emoji].packets.unshift(packet);
            
            // 限制模式列表长度
            if (this.patterns[emoji].packets.length > 100) {
                this.patterns[emoji].packets.pop();
            }
        }
        
        // 渲染
        this.renderPatterns();
        this.addPacketToUI(packet);
        
        // 更新计数
        this.updateCounts();
    }
    
    renderPatterns() {
        const container = document.getElementById('patterns-list');
        
        if (Object.keys(this.patterns).length === 0) {
            container.innerHTML = '<div class="empty-state">等待检测数据...</div>';
            return;
        }
        
        container.innerHTML = '';
        
        // 按数量排序
        const sorted = Object.entries(this.patterns).sort((a, b) => 
            b[1].packets.length - a[1].packets.length
        );
        
        sorted.forEach(([emoji, data]) => {
            const item = document.createElement('div');
            item.className = 'pattern-item';
            item.innerHTML = `
                <div class="pattern-header">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <span class="pattern-emoji">${emoji}</span>
                        <span class="pattern-name">${data.pattern.name}</span>
                    </div>
                    <span class="pattern-count-badge">${data.packets.length}</span>
                </div>
                <div class="pattern-desc">${data.pattern.description}</div>
            `;
            
            item.addEventListener('click', () => {
                this.filterByPattern(emoji);
            });
            
            container.appendChild(item);
        });
    }
    
    renderPackets(packets) {
        const container = document.getElementById('packets-list');
        container.innerHTML = '';
        
        if (packets.length === 0) {
            container.innerHTML = '<div class="empty-state">暂无数据包...</div>';
            return;
        }
        
        packets.slice(0, 100).forEach(packet => {
            this.addPacketToUI(packet, container);
        });
    }
    
    addPacketToUI(packet, container = null) {
        if (!container) {
            container = document.getElementById('packets-list');
            
            // 移除empty state
            const emptyState = container.querySelector('.empty-state');
            if (emptyState) {
                emptyState.remove();
            }
        }
        
        const item = document.createElement('div');
        item.className = `packet-item ${packet.is_anomaly ? 'anomaly' : 'normal'}`;
        item.dataset.index = packet.index || this.packets.indexOf(packet);
        
        const timestamp = new Date(packet.timestamp * 1000).toLocaleTimeString();
        
        item.innerHTML = `
            <div class="packet-header">
                <div class="packet-flow">
                    ${packet.src}
                    <span class="arrow">→</span>
                    ${packet.dst}
                </div>
                <div class="packet-time">${timestamp}</div>
            </div>
            <div class="packet-info">
                <span class="packet-protocol">${packet.protocol}</span>
                <span>${packet.length} bytes</span>
                ${packet.is_anomaly ? '<span style="color: var(--danger-color)">⚠ 异常</span>' : ''}
            </div>
            ${packet.is_anomaly ? `
                <div class="packet-pattern">
                    <span>${packet.pattern.emoji}</span>
                    <span>${packet.pattern.name}</span>
                </div>
            ` : ''}
        `;
        
        item.addEventListener('click', (e) => {
            this.showPacketDetails(packet, e.currentTarget);
        });
        
        // 插入到开头
        container.insertBefore(item, container.firstChild);
        
        // 限制UI显示数量
        while (container.children.length > 100) {
            container.removeChild(container.lastChild);
        }
    }
    
    showPacketDetails(packet, clickedElement) {
        this.selectedPacket = packet;
        
        const container = document.getElementById('details-content');
        
        // 高亮选中项
        document.querySelectorAll('.packet-item').forEach(item => {
            item.classList.remove('selected');
        });
        if (clickedElement) {
            clickedElement.classList.add('selected');
        }
        
        const timestamp = new Date(packet.timestamp * 1000).toLocaleString();
        
        let flagsHtml = '';
        if (packet.flags && Object.keys(packet.flags).length > 0) {
            flagsHtml = Object.entries(packet.flags)
                .filter(([k, v]) => v)
                .map(([k, v]) => k.toUpperCase())
                .join(', ') || '无';
        }
        
        container.innerHTML = `
            <div class="detail-section">
                <h3>基本信息</h3>
                <div class="detail-row">
                    <span class="detail-label">时间:</span>
                    <span class="detail-value">${timestamp}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">源地址:</span>
                    <span class="detail-value highlight">${packet.src}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">目标地址:</span>
                    <span class="detail-value highlight">${packet.dst}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">协议:</span>
                    <span class="detail-value highlight">${packet.protocol}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">长度:</span>
                    <span class="detail-value">${packet.length} bytes</span>
                </div>
                ${flagsHtml ? `
                <div class="detail-row">
                    <span class="detail-label">TCP标志:</span>
                    <span class="detail-value">${flagsHtml}</span>
                </div>
                ` : ''}
            </div>
            
            <div class="detail-section">
                <h3>检测结果</h3>
                <div class="detail-row">
                    <span class="detail-label">异常状态:</span>
                    <span class="detail-value ${packet.is_anomaly ? 'danger' : 'success'}">
                        ${packet.is_anomaly ? '⚠ 异常' : '✓ 正常'}
                    </span>
                </div>
                ${packet.score !== undefined ? `
                <div class="detail-row">
                    <span class="detail-label">异常分数:</span>
                    <span class="detail-value">${packet.score.toFixed(4)}</span>
                </div>
                ` : ''}
                ${packet.pattern ? `
                <div class="detail-row">
                    <span class="detail-label">流量模式:</span>
                    <span class="detail-value">
                        ${packet.pattern.emoji} ${packet.pattern.name}
                    </span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">模式描述:</span>
                    <span class="detail-value">${packet.pattern.description}</span>
                </div>
                ` : `
                <div class="detail-row">
                    <span class="detail-label">流量模式:</span>
                    <span class="detail-value">正常流量</span>
                </div>
                `}
            </div>
            
            ${packet.payload ? `
            <div class="detail-section">
                <h3>数据内容</h3>
                <div class="payload-box">${this.escapeHtml(packet.payload)}</div>
            </div>
            ` : ''}
        `;
    }
    
    filterByPattern(emoji) {
        if (this.patterns[emoji]) {
            const packets = this.patterns[emoji].packets;
            this.renderPackets(packets);
            this.showNotification(`过滤: ${this.patterns[emoji].pattern.name}`, 'info');
        }
    }
    
    clearPackets() {
        this.packets = [];
        this.patterns = {};
        
        document.getElementById('patterns-list').innerHTML = '<div class="empty-state">等待检测数据...</div>';
        document.getElementById('packets-list').innerHTML = '<div class="empty-state">暂无数据包...</div>';
        
        this.updateCounts();
    }
    
    closeDetails() {
        document.getElementById('details-content').innerHTML = '<div class="empty-state">点击数据包查看详情...</div>';
        
        document.querySelectorAll('.packet-item').forEach(item => {
            item.classList.remove('selected');
        });
    }
    
    updateCounts() {
        document.getElementById('packet-count').textContent = this.packets.length;
        
        const anomalyCount = this.packets.filter(p => p.is_anomaly).length;
        document.getElementById('anomaly-count').textContent = anomalyCount;
        
        document.getElementById('pattern-count').textContent = Object.keys(this.patterns).length;
    }
    
    updateStatus(text, type = 'info') {
        const statusEl = document.getElementById('monitor-status');
        statusEl.textContent = text;
        
        // 移除旧的类
        statusEl.classList.remove('success', 'danger', 'warning');
        
        // 添加新的类
        if (type !== 'info') {
            statusEl.classList.add(type);
        }
    }
    
    showNotification(message, type = 'info') {
        console.log(`[${type.toUpperCase()}] ${message}`);
        
        // 创建通知元素
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--bg-panel);
            border: 2px solid var(--${type === 'success' ? 'success' : type === 'danger' ? 'danger' : 'primary'}-color);
            color: var(--text-primary);
            padding: 15px 25px;
            border-radius: 4px;
            box-shadow: 0 0 20px rgba(0, 255, 255, 0.5);
            z-index: 1000;
            animation: slideIn 0.3s ease-out;
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease-out';
            setTimeout(() => {
                notification.remove();
            }, 300);
        }, 3000);
    }
    
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// 初始化
document.addEventListener('DOMContentLoaded', () => {
    // 检查Socket.IO是否加载
    if (typeof io === 'undefined') {
        console.error('Socket.IO未加载!');
        alert('错误: Socket.IO库未加载，页面功能可能受限');
        return;
    }
    
    // 创建实例
    window.trafficMonitor = new TrafficMonitor();
});
