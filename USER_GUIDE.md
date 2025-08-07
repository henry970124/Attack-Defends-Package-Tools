# Attack & Defense 封包分析系統 - 使用指南

## 快速開始

### 方法一：使用自動設定腳本 (推薦)
```bash
python setup.py
```
這個腳本會自動完成所有設定步驟。

### 方法二：手動設定
1. **啟動系統**
   ```bash
   # Windows
   start.bat
   
   # Linux/Mac
   ./start.sh
   ```

2. **檢查系統狀態**
   ```bash
   python test_system.py
   ```

3. **產生測試資料**
   ```bash
   python generate_test_data.py
   ```

## 系統使用

### 1. Web儀表板 (http://localhost:3000)
- **總覽頁面**: 顯示系統整體統計資料
- **即時監控**: 自動更新的封包統計和威脅偵測
- **視覺化圖表**: 協定分布、IP活躍度等圖表

### 2. 封包分析功能
- **IP分類**: 自動分類來源IP並標記可疑IP
- **協定分析**: 統計各種網路協定的使用情況
- **流量統計**: 分析網路流量模式和趨勢

### 3. 惡意流量偵測
- **即時偵測**: 自動掃描新封包尋找惡意特徵
- **威脅分類**: 識別SQL注入、XSS、命令注入等攻擊
- **行為分析**: 偵測異常連線模式和端口掃描

## API使用指南

### 封包分析API (端口 8080)

#### 取得封包資料
```bash
# 取得最新100個封包
curl "http://localhost:8080/api/packets?limit=100"

# 過濾特定IP的封包
curl "http://localhost:8080/api/packets?src_ip=192.168.1.100"

# 只取得惡意封包
curl "http://localhost:8080/api/packets?malicious_only=true"
```

#### 取得IP統計
```bash
# 取得所有IP統計
curl "http://localhost:8080/api/ip-stats"

# 只取得可疑IP
curl "http://localhost:8080/api/ip-stats?suspicious_only=true"
```

#### 取得協定統計
```bash
curl "http://localhost:8080/api/protocol-stats"
```

### 惡意偵測API (端口 8081)

#### 取得偵測結果
```bash
curl "http://localhost:8081/api/detections?limit=50"
```

#### 取得偵測統計
```bash
curl "http://localhost:8081/api/stats"
```

#### 手動觸發掃描
```bash
curl -X POST "http://localhost:8081/api/scan"
```

## 實際使用場景

### 場景1：紅藍對抗演練監控
1. 啟動系統開始錄製網路流量
2. 在Web儀表板監控即時活動
3. 當偵測到惡意活動時，系統會自動標記和警報
4. 分析攻擊來源IP和攻擊類型

### 場景2：網路安全事件調查
1. 導入現有的PCAP檔案進行分析
2. 使用API查詢特定時間範圍的活動
3. 分析可疑IP的行為模式
4. 生成事件報告

### 場景3：威脅獵取
1. 監控網路中的異常行為
2. 分析高頻率連線和端口掃描
3. 識別潛在的C&C通信
4. 追蹤惡意軟體活動

## 自定義規則

### 添加YARA規則
編輯 `malicious-detection/rules/malicious_traffic.yar` 檔案：

```yara
rule Custom_Attack {
    meta:
        description = "偵測自定義攻擊模式"
        severity = "high"
        
    strings:
        $pattern1 = "malicious_string"
        $pattern2 = /regex_pattern/i
        
    condition:
        any of them
}
```

### 修改偵測邏輯
編輯 `malicious-detection/detection_server.py` 中的 `signature_rules` 字典。

## 系統管理

### 查看日誌
```bash
# 查看所有服務日誌
docker-compose logs

# 查看特定服務日誌
docker-compose logs packet-capture
docker-compose logs packet-analysis
docker-compose logs malicious-detection
docker-compose logs web-dashboard
```

### 重新啟動服務
```bash
# 重新啟動所有服務
docker-compose restart

# 重新啟動特定服務
docker-compose restart packet-analysis
```

### 清理資料
```bash
# 停止服務
docker-compose down

# 清理舊資料
rm -rf shared/pcap/*
rm -rf shared/analysis/*
rm -rf shared/logs/*

# 重新啟動
docker-compose up -d
```

### 備份資料
```bash
# 備份分析資料庫
cp shared/analysis/packets.db backup/packets_$(date +%Y%m%d).db

# 備份PCAP檔案
tar -czf backup/pcap_$(date +%Y%m%d).tar.gz shared/pcap/
```

## 效能調整

### 封包錄製調整
編輯 `docker-compose.yml` 中的環境變數：
```yaml
environment:
  - INTERFACE=eth0  # 設定網路介面
  - CAPTURE_FILTER=host 192.168.1.0/24  # 設定過濾器
```

### 偵測靈敏度調整
編輯 `docker-compose.yml` 中的惡意偵測設定：
```yaml
environment:
  - ALERT_THRESHOLD=3  # 降低警報閾值
```

## 故障排除

### 常見問題

1. **封包錄製失敗**
   - 確認Docker有足夠權限
   - 檢查網路介面名稱是否正確
   - 在Windows上可能需要以管理員權限執行

2. **Web介面無法載入**
   - 檢查所有服務是否正常啟動
   - 確認防火牆沒有阻擋埠口
   - 等待服務完全啟動後再訪問

3. **資料庫錯誤**
   - 檢查 `shared/analysis` 目錄權限
   - 確認有足夠的磁碟空間
   - 嘗試刪除資料庫檔案重新建立

4. **Docker容器無法啟動**
   - 檢查Docker和Docker Compose版本
   - 確認沒有埠口衝突
   - 查看詳細錯誤日誌

### 取得協助
如果遇到問題，請：
1. 檢查系統日誌：`docker-compose logs`
2. 確認系統資源充足
3. 查看GitHub Issues或聯絡開發團隊

## 進階功能

### 整合外部威脅情報
可以修改偵測系統來整合外部威脅情報源，如：
- VirusTotal API
- 開源威脅情報feeds
- 自定義IP黑名單

### 自動化報告
可以擴展系統來自動生成報告：
- 每日威脅摘要
- 週期性安全評估
- 事件響應報告

### 分散式部署
對於大規模環境，可以：
- 使用多個封包錄製節點
- 部署集中式分析服務
- 實施負載平衡

這個系統為您提供了完整的網路安全監控和分析能力，適合各種Attack & Defense場景使用！
