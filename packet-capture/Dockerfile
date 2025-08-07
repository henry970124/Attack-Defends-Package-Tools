FROM ubuntu:22.04

# 安裝必要套件
RUN apt-get update && apt-get install -y \
    tcpdump \
    tshark \
    python3 \
    python3-pip \
    python3-venv \
    iproute2 \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# 建立工作目錄
WORKDIR /app

# 複製需求檔案
COPY requirements.txt .

# 安裝Python依賴
RUN pip3 install -r requirements.txt

# 複製應用程式檔案
COPY . .

# 建立數據目錄
RUN mkdir -p /data/pcap /data/logs

# 設定權限
RUN chmod +x capture.py

# 暴露埠口 (如果需要API)
EXPOSE 8082

# 執行命令
CMD ["python3", "capture.py"]
