// WebSocket連接
const socket = io();

// 圖表實例
let protocolChart, ipChart;

// 初始化
document.addEventListener('DOMContentLoaded', function() {
    initializeCharts();
    loadDashboardData();
    setupWebSocket();
    
    // 每30秒自動刷新
    setInterval(loadDashboardData, 30000);
});

// 初始化圖表
function initializeCharts() {
    // 協定分布圓餅圖
    const protocolCtx = document.getElementById('protocolChart').getContext('2d');
    protocolChart = new Chart(protocolCtx, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    '#FF6384',
                    '#36A2EB',
                    '#FFCE56',
                    '#4BC0C0',
                    '#9966FF',
                    '#FF9F40'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            height: 300,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });

    // IP活躍度柱狀圖
    const ipCtx = document.getElementById('ipChart').getContext('2d');
    ipChart = new Chart(ipCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: '封包數量',
                data: [],
                backgroundColor: '#36A2EB',
                borderColor: '#1E88E5',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            height: 300,
            scales: {
                y: {
                    beginAtZero: true
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
}

// 載入儀表板資料
async function loadDashboardData() {
    try {
        const response = await fetch('/api/dashboard');
        const data = await response.json();
        
        if (data.analysis && data.detection) {
            updateStatistics(data.analysis.summary, data.detection);
            updateProtocolChart(data.analysis.protocol_distribution);
            updateIPChart(data.analysis.top_ips);
        }
        
        // 載入最新偵測和封包
        await Promise.all([
            loadDetections(),
            loadPackets()
        ]);
        
    } catch (error) {
        console.error('載入儀表板資料失敗:', error);
        updateConnectionStatus(false);
    }
}

// 更新統計資料
function updateStatistics(analysisData, detectionData) {
    document.getElementById('total-packets').textContent = formatNumber(analysisData.total_packets || 0);
    document.getElementById('total-ips').textContent = formatNumber(analysisData.total_ips || 0);
    document.getElementById('malicious-packets').textContent = formatNumber(detectionData.malicious_packets || 0);
    
    const detectionRate = analysisData.total_packets > 0 
        ? ((detectionData.malicious_packets || 0) / analysisData.total_packets * 100).toFixed(1)
        : 0;
    document.getElementById('detection-rate').textContent = detectionRate + '%';
}

// 更新協定圖表
function updateProtocolChart(protocolData) {
    if (!protocolData || protocolData.length === 0) return;
    
    const labels = protocolData.map(item => item.protocol);
    const data = protocolData.map(item => item.packet_count);
    
    protocolChart.data.labels = labels;
    protocolChart.data.datasets[0].data = data;
    protocolChart.update();
}

// 更新IP圖表
function updateIPChart(ipData) {
    if (!ipData || ipData.length === 0) return;
    
    const labels = ipData.map(item => item.ip);
    const data = ipData.map(item => item.packet_count);
    
    ipChart.data.labels = labels;
    ipChart.data.datasets[0].data = data;
    ipChart.update();
}

// 載入偵測資料
async function loadDetections() {
    try {
        const response = await fetch('/api/detections?limit=20');
        const detections = await response.json();
        
        const tableBody = document.getElementById('detections-table');
        tableBody.innerHTML = '';
        
        detections.forEach(detection => {
            const row = document.createElement('tr');
            row.className = 'malicious-packet';
            
            const maliciousTypes = JSON.parse(detection.malicious_type || '[]');
            const threatType = maliciousTypes.join(', ') || '未知';
            
            row.innerHTML = `
                <td>${formatDateTime(detection.timestamp)}</td>
                <td>${detection.src_ip}</td>
                <td>${detection.dst_ip}</td>
                <td><span class="badge bg-info">${detection.protocol}</span></td>
                <td><span class="badge bg-danger">${threatType}</span></td>
            `;
            
            tableBody.appendChild(row);
        });
        
    } catch (error) {
        console.error('載入偵測資料失敗:', error);
    }
}

// 載入封包資料
async function loadPackets() {
    try {
        const response = await fetch('/api/packets?limit=20');
        const packets = await response.json();
        
        const tableBody = document.getElementById('packets-table');
        tableBody.innerHTML = '';
        
        packets.forEach(packet => {
            const row = document.createElement('tr');
            if (packet.is_malicious) {
                row.className = 'malicious-packet';
            }
            
            const status = packet.is_malicious 
                ? '<span class="badge bg-danger">惡意</span>'
                : '<span class="badge bg-success">正常</span>';
            
            row.innerHTML = `
                <td>${formatDateTime(packet.timestamp)}</td>
                <td>${packet.src_ip}</td>
                <td>${packet.dst_ip}</td>
                <td><span class="badge bg-info">${packet.protocol}</span></td>
                <td>${formatBytes(packet.length)}</td>
                <td>${status}</td>
            `;
            
            tableBody.appendChild(row);
        });
        
    } catch (error) {
        console.error('載入封包資料失敗:', error);
    }
}

// 設定WebSocket
function setupWebSocket() {
    socket.on('connect', () => {
        console.log('WebSocket已連接');
        updateConnectionStatus(true);
    });
    
    socket.on('disconnect', () => {
        console.log('WebSocket已斷線');
        updateConnectionStatus(false);
    });
    
    socket.on('dashboard-update', (data) => {
        console.log('收到即時更新');
        if (data.dashboard) {
            updateStatistics(data.dashboard.summary, data.detection || {});
            updateProtocolChart(data.dashboard.protocol_distribution);
            updateIPChart(data.dashboard.top_ips);
        }
    });
}

// 更新連接狀態
function updateConnectionStatus(isConnected) {
    const statusIndicator = document.getElementById('connection-status');
    const statusText = document.getElementById('status-text');
    
    if (isConnected) {
        statusIndicator.className = 'status-indicator status-online';
        statusText.textContent = '運行中';
    } else {
        statusIndicator.className = 'status-indicator status-offline';
        statusText.textContent = '離線';
    }
}

// 刷新函數
function refreshDetections() {
    loadDetections();
}

function refreshPackets() {
    loadPackets();
}

// 工具函數
function formatNumber(num) {
    return new Intl.NumberFormat().format(num);
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDateTime(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString('zh-TW', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}
