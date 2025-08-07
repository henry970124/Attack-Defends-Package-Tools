FROM python:3.9-slim

# 安裝系統依賴
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
    autoconf \
    libtool \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# 建立工作目錄
WORKDIR /app

# 複製需求檔案
COPY requirements.txt .

# 安裝Python依賴
RUN pip install -r requirements.txt

# 複製應用程式檔案
COPY . .

# 建立目錄
RUN mkdir -p /data/pcap /data/analysis /data/logs /app/rules

# 下載並編譯YARA
RUN apt-get update && apt-get install -y wget && \
    wget https://github.com/VirusTotal/yara/archive/v4.3.2.tar.gz && \
    tar -zxf v4.3.2.tar.gz && \
    cd yara-4.3.2 && \
    ./bootstrap.sh && \
    ./configure && \
    make && \
    make install && \
    ldconfig && \
    cd .. && \
    rm -rf yara-4.3.2 v4.3.2.tar.gz

# 安裝yara-python
RUN pip install yara-python

# 暴露埠口
EXPOSE 8081

# 執行命令
CMD ["python", "detection_server.py"]
