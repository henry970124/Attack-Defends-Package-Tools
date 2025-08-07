#!/usr/bin/env python3
"""
封包錄製系統
負責錄製網路封包並儲存為pcap檔案
"""

import os
import time
import subprocess
import logging
import signal
import sys
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import requests

# 設定日誌
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/data/logs/packet-capture.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class PacketCapture:
    def __init__(self):
        self.interface = os.getenv('INTERFACE', 'eth0')
        self.capture_filter = os.getenv('CAPTURE_FILTER', '')
        self.pcap_dir = '/data/pcap'
        self.rotation_size = 100  # MB
        self.is_running = True
        
        # 確保目錄存在
        os.makedirs(self.pcap_dir, exist_ok=True)
        
    def get_filename(self):
        """產生時間戳記檔名"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"{self.pcap_dir}/capture_{timestamp}.pcap"
    
    def start_capture(self):
        """開始封包錄製"""
        logger.info(f"開始在 {self.interface} 介面上錄製封包")
        
        while self.is_running:
            try:
                filename = self.get_filename()
                logger.info(f"錄製封包到: {filename}")
                
                # 建構tcpdump命令
                cmd = [
                    'tcpdump',
                    '-i', self.interface,
                    '-w', filename,
                    '-C', str(self.rotation_size),  # 檔案大小限制 (MB)
                    '-G', '3600',  # 每小時輪轉
                    '-s', '65535',  # 封包大小
                ]
                
                # 如果有過濾器，加入命令
                if self.capture_filter:
                    cmd.append(self.capture_filter)
                
                # 執行tcpdump
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                # 等待程序結束或中斷
                while self.is_running and process.poll() is None:
                    time.sleep(1)
                
                if process.poll() is None:
                    process.terminate()
                    process.wait()
                    
            except Exception as e:
                logger.error(f"錄製封包時發生錯誤: {e}")
                time.sleep(5)  # 等待後重試
    
    def stop_capture(self):
        """停止封包錄製"""
        logger.info("停止封包錄製")
        self.is_running = False

class PCAPHandler(FileSystemEventHandler):
    """監控PCAP檔案變化"""
    
    def __init__(self):
        self.analysis_url = "http://packet-analysis:8080/api/analyze"
    
    def on_created(self, event):
        if event.is_dir or not event.src_path.endswith('.pcap'):
            return
            
        logger.info(f"新的PCAP檔案: {event.src_path}")
        self.notify_analysis_service(event.src_path)
    
    def notify_analysis_service(self, pcap_file):
        """通知分析服務有新的PCAP檔案"""
        try:
            data = {'pcap_file': pcap_file}
            response = requests.post(self.analysis_url, json=data, timeout=10)
            if response.status_code == 200:
                logger.info(f"成功通知分析服務: {pcap_file}")
            else:
                logger.warning(f"通知分析服務失敗: {response.status_code}")
        except Exception as e:
            logger.error(f"通知分析服務時發生錯誤: {e}")

def signal_handler(signum, frame):
    """信號處理器"""
    logger.info("收到停止信號")
    global capture_service
    if capture_service:
        capture_service.stop_capture()
    sys.exit(0)

def main():
    global capture_service
    
    # 註冊信號處理器
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    logger.info("封包錄製系統啟動")
    
    # 建立封包錄製服務
    capture_service = PacketCapture()
    
    # 建立檔案監控
    event_handler = PCAPHandler()
    observer = Observer()
    observer.schedule(event_handler, '/data/pcap', recursive=False)
    observer.start()
    
    try:
        # 開始錄製
        capture_service.start_capture()
    except KeyboardInterrupt:
        logger.info("使用者中斷程式")
    finally:
        observer.stop()
        observer.join()
        logger.info("封包錄製系統停止")

if __name__ == "__main__":
    main()
