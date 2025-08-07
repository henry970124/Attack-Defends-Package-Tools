FROM python:3.9-slim

# 安裝系統依賴
RUN apt-get update && apt-get install -y \
    tshark \
    sqlite3 \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# 建立工作目錄
WORKDIR /app

# 複製需求檔案
COPY requirements.txt .

# 安裝Python依賴
RUN pip install -r requirements.txt

# 複製應用程式檔案
COPY . .

# 建立數據目錄
RUN mkdir -p /data/pcap /data/analysis /data/logs

# 暴露埠口
EXPOSE 8080

# 執行命令
CMD ["python", "analysis_server.py"]
