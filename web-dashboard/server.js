const express = require('express');
const cors = require('cors');
const axios = require('axios');
const path = require('path');
const { Server } = require('socket.io');
const http = require('http');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

const PORT = process.env.PORT || 3000;
const ANALYSIS_API_URL = process.env.ANALYSIS_API_URL || 'http://localhost:8080';
const DETECTION_API_URL = process.env.DETECTION_API_URL || 'http://localhost:8081';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// API代理路由
app.get('/api/dashboard', async (req, res) => {
    try {
        const [analysisResponse, detectionResponse] = await Promise.all([
            axios.get(`${ANALYSIS_API_URL}/api/dashboard`),
            axios.get(`${DETECTION_API_URL}/api/stats`)
        ]);
        
        res.json({
            analysis: analysisResponse.data,
            detection: detectionResponse.data
        });
    } catch (error) {
        console.error('Dashboard API錯誤:', error.message);
        res.status(500).json({ error: '無法取得儀表板資料' });
    }
});

app.get('/api/packets', async (req, res) => {
    try {
        const response = await axios.get(`${ANALYSIS_API_URL}/api/packets`, {
            params: req.query
        });
        res.json(response.data);
    } catch (error) {
        console.error('封包API錯誤:', error.message);
        res.status(500).json({ error: '無法取得封包資料' });
    }
});

app.get('/api/ip-stats', async (req, res) => {
    try {
        const response = await axios.get(`${ANALYSIS_API_URL}/api/ip-stats`, {
            params: req.query
        });
        res.json(response.data);
    } catch (error) {
        console.error('IP統計API錯誤:', error.message);
        res.status(500).json({ error: '無法取得IP統計資料' });
    }
});

app.get('/api/detections', async (req, res) => {
    try {
        const response = await axios.get(`${DETECTION_API_URL}/api/detections`, {
            params: req.query
        });
        res.json(response.data);
    } catch (error) {
        console.error('偵測API錯誤:', error.message);
        res.status(500).json({ error: '無法取得偵測資料' });
    }
});

// WebSocket連接
io.on('connection', (socket) => {
    console.log('客戶端已連接:', socket.id);
    
    socket.on('disconnect', () => {
        console.log('客戶端已斷線:', socket.id);
    });
});

// 定期推送更新資料
setInterval(async () => {
    try {
        const [dashboardData, recentDetections] = await Promise.all([
            axios.get(`${ANALYSIS_API_URL}/api/dashboard`),
            axios.get(`${DETECTION_API_URL}/api/detections?limit=10`)
        ]);
        
        io.emit('dashboard-update', {
            dashboard: dashboardData.data,
            detections: recentDetections.data
        });
    } catch (error) {
        console.error('推送更新失敗:', error.message);
    }
}, 10000); // 每10秒更新一次

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

server.listen(PORT, () => {
    console.log(`Web儀表板運行在 http://localhost:${PORT}`);
});
