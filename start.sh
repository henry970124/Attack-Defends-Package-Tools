#!/bin/bash

echo "==================================="
echo "Attack & Defense 封包分析系統"
echo "==================================="

# 檢查Docker是否安裝
if ! command -v docker &> /dev/null; then
    echo "錯誤: Docker未安裝，請先安裝Docker"
    exit 1
fi

# 檢查Docker Compose是否安裝
if ! command -v docker-compose &> /dev/null; then
    echo "錯誤: Docker Compose未安裝，請先安裝Docker Compose"
    exit 1
fi

echo "正在啟動系統..."

# 建立必要的目錄
mkdir -p shared/pcap shared/analysis shared/logs

# 停止現有的容器
echo "停止現有容器..."
docker-compose down

# 建置並啟動服務
echo "建置並啟動服務..."
docker-compose up --build -d

# 等待服務啟動
echo "等待服務啟動..."
sleep 10

# 檢查服務狀態
echo "檢查服務狀態..."
docker-compose ps

echo ""
echo "系統啟動完成！"
echo ""
echo "服務端點:"
echo "- Web儀表板: http://localhost:3000"
echo "- 封包分析API: http://localhost:8080"
echo "- 惡意偵測API: http://localhost:8081"
echo ""
echo "使用 'docker-compose logs [service]' 查看日誌"
echo "使用 'docker-compose down' 停止系統"
