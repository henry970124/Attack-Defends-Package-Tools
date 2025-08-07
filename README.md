# Attack & Defense 封包分析系統

這是一個完整的網路封包攔截、鑑識和惡意流量偵測系統，專為Attack & Defense (紅藍對抗)演練設計。

## 系統架構

系統包含四個主要組件：

1. **封包錄製系統** (packet-capture) - 負責錄製網路封包
2. **封包鑑識系統** (packet-analysis) - 分析封包並提供統計資料
3. **惡意流量偵測系統** (malicious-detection) - 偵測惡意payload和異常行為
4. **Web儀表板** (web-dashboard) - 提供視覺化介面

## 功能特色

### 封包錄製系統
- 即時錄製網路封包
- 自動輪轉PCAP檔案
- 支援自定義過濾器
- 自動通知分析系統

### 封包鑑識系統
- 深度封包分析
- IP統計和分類
- 協定分析
- 地理位置資訊
- RESTful API

### 惡意流量偵測系統
- 規則基礎偵測 (YARA規則)
- 機器學習異常偵測
- 行為分析
- 即時威脅警報
- 支援自定義規則

### Web儀表板
- 即時資料視覺化
- 互動式圖表
- 威脅情報展示
- 即時更新 (WebSocket)

## 偵測能力

系統能夠偵測以下攻擊類型：

- **SQL注入攻擊**
- **跨站腳本攻擊 (XSS)**
- **命令注入攻擊**
- **目錄遍歷攻擊**
- **惡意軟體特徵**
- **端口掃描**
- **高頻率連線**
- **異常流量模式**

## 快速開始

### 前置需求

- Docker
- Docker Compose
- 管理員權限 (用於封包錄製)

### 安裝與執行

1. 克隆專案：
```bash
git clone <repository-url>
cd AD專案開發
```

2. 啟動所有服務：
```bash
docker-compose up -d
```

3. 檢查服務狀態：
```bash
docker-compose ps
```

4. 存取Web介面：
   - 主儀表板: http://localhost:3000
   - 封包分析API: http://localhost:8080
   - 惡意偵測API: http://localhost:8081

### 停止服務

```bash
docker-compose down
```

## 服務端點

### 封包分析API (8080)
- `GET /api/packets` - 取得封包資料
- `GET /api/ip-stats` - 取得IP統計
- `GET /api/protocol-stats` - 取得協定統計
- `GET /api/dashboard` - 取得儀表板資料
- `POST /api/analyze` - 分析PCAP檔案

### 惡意偵測API (8081)
- `GET /api/detections` - 取得偵測結果
- `GET /api/stats` - 取得偵測統計
- `POST /api/scan` - 手動掃描

### Web儀表板 (3000)
- `GET /` - 主要儀表板介面
- `GET /api/dashboard` - 整合的儀表板資料

## 配置選項

### 環境變數

#### 封包錄製系統
- `INTERFACE` - 網路介面 (預設: eth0)
- `CAPTURE_FILTER` - 封包過濾器

#### 惡意偵測系統
- `YARA_RULES_PATH` - YARA規則路徑
- `ALERT_THRESHOLD` - 警報閾值

#### Web儀表板
- `ANALYSIS_API_URL` - 分析API URL
- `DETECTION_API_URL` - 偵測API URL

## 資料目錄

- `./shared/pcap/` - PCAP檔案儲存
- `./shared/analysis/` - 分析結果和資料庫
- `./shared/logs/` - 系統日誌

## 自定義規則

您可以在 `./malicious-detection/rules/` 目錄中添加自定義YARA規則：

```yara
rule Custom_Attack {
    meta:
        description = "自定義攻擊偵測"
        severity = "high"
        
    strings:
        $a = "malicious_pattern"
        
    condition:
        $a
}
```

## 效能調整

### 封包錄製
- 調整 `rotation_size` 來控制檔案大小
- 使用 `CAPTURE_FILTER` 來減少不必要的封包

### 資料庫
- 定期清理舊資料
- 考慮使用更高效能的資料庫

### 偵測系統
- 調整掃描間隔
- 優化規則複雜度

## 故障排除

### 常見問題

1. **封包錄製失敗**
   - 檢查是否有管理員權限
   - 確認網路介面名稱正確

2. **服務無法連接**
   - 檢查防火牆設定
   - 確認埠口未被占用

3. **資料庫錯誤**
   - 檢查磁碟空間
   - 確認權限設定

### 日誌檢查

```bash
# 檢查所有服務日誌
docker-compose logs

# 檢查特定服務日誌
docker-compose logs packet-capture
docker-compose logs packet-analysis
docker-compose logs malicious-detection
docker-compose logs web-dashboard
```

## 安全注意事項

1. **網路權限**: 封包錄製需要特殊權限
2. **資料保護**: 確保敏感資料的安全
3. **存取控制**: 在生產環境中添加身份驗證
4. **日誌管理**: 定期輪轉和備份日誌

## 開發指南

### 添加新的偵測規則

1. 編輯 `malicious-detection/detection_server.py`
2. 在 `signature_rules` 中添加新規則
3. 重新建置容器

### 擴展API功能

1. 修改對應的Flask應用程式
2. 更新前端代碼
3. 測試新功能

## 授權

本專案採用 MIT 授權條款。

## 貢獻

歡迎提交Issue和Pull Request來改善這個系統。

## 聯絡資訊

如有問題或建議，請聯絡開發團隊。
