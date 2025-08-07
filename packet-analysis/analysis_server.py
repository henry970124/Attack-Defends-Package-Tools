#!/usr/bin/env python3
"""
封包鑑識分析系統
負責分析PCAP檔案並提供REST API
"""

import os
import sqlite3
import logging
import json
import ipaddress
from datetime import datetime
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import pyshark
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
import pandas as pd
import threading
import time

# 設定日誌
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/data/logs/packet-analysis.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

class PacketAnalyzer:
    def __init__(self):
        self.db_path = '/data/analysis/packets.db'
        self.init_database()
        
    def init_database(self):
        """初始化資料庫"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 建立封包資料表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    length INTEGER,
                    payload TEXT,
                    pcap_file TEXT,
                    is_malicious BOOLEAN DEFAULT 0,
                    malicious_type TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # 建立IP統計資料表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ip_stats (
                    ip TEXT PRIMARY KEY,
                    packet_count INTEGER DEFAULT 0,
                    total_bytes INTEGER DEFAULT 0,
                    first_seen DATETIME,
                    last_seen DATETIME,
                    country TEXT,
                    is_suspicious BOOLEAN DEFAULT 0
                )
            ''')
            
            # 建立協定統計資料表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS protocol_stats (
                    protocol TEXT PRIMARY KEY,
                    packet_count INTEGER DEFAULT 0,
                    total_bytes INTEGER DEFAULT 0
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("資料庫初始化完成")
            
        except Exception as e:
            logger.error(f"資料庫初始化失敗: {e}")
    
    def analyze_pcap(self, pcap_file):
        """分析PCAP檔案"""
        try:
            logger.info(f"開始分析PCAP檔案: {pcap_file}")
            
            # 使用scapy讀取pcap檔案
            packets = rdpcap(pcap_file)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for packet in packets:
                if IP in packet:
                    self.process_packet(cursor, packet, pcap_file)
            
            conn.commit()
            conn.close()
            
            # 更新統計資料
            self.update_statistics()
            
            logger.info(f"PCAP分析完成: {pcap_file}")
            
        except Exception as e:
            logger.error(f"分析PCAP檔案時發生錯誤: {e}")
    
    def process_packet(self, cursor, packet, pcap_file):
        """處理單個封包"""
        try:
            timestamp = datetime.fromtimestamp(float(packet.time))
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            length = len(packet)
            
            # 取得埠口資訊
            src_port = dst_port = None
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                protocol_name = 'TCP'
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                protocol_name = 'UDP'
            elif ICMP in packet:
                protocol_name = 'ICMP'
            else:
                protocol_name = f'Protocol-{protocol}'
            
            # 取得payload
            payload = ""
            if packet.haslayer('Raw'):
                payload = bytes(packet['Raw']).hex()
            
            # 插入封包資料
            cursor.execute('''
                INSERT INTO packets 
                (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, payload, pcap_file)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, src_ip, dst_ip, src_port, dst_port, protocol_name, length, payload, pcap_file))
            
            # 更新IP統計
            self.update_ip_stats(cursor, src_ip, length, timestamp)
            self.update_ip_stats(cursor, dst_ip, length, timestamp)
            
            # 更新協定統計
            self.update_protocol_stats(cursor, protocol_name, length)
            
        except Exception as e:
            logger.error(f"處理封包時發生錯誤: {e}")
    
    def update_ip_stats(self, cursor, ip, length, timestamp):
        """更新IP統計資料"""
        cursor.execute('SELECT * FROM ip_stats WHERE ip = ?', (ip,))
        existing = cursor.fetchone()
        
        if existing:
            cursor.execute('''
                UPDATE ip_stats 
                SET packet_count = packet_count + 1,
                    total_bytes = total_bytes + ?,
                    last_seen = ?
                WHERE ip = ?
            ''', (length, timestamp, ip))
        else:
            cursor.execute('''
                INSERT INTO ip_stats (ip, packet_count, total_bytes, first_seen, last_seen)
                VALUES (?, 1, ?, ?, ?)
            ''', (ip, length, timestamp, timestamp))
    
    def update_protocol_stats(self, cursor, protocol, length):
        """更新協定統計資料"""
        cursor.execute('SELECT * FROM protocol_stats WHERE protocol = ?', (protocol,))
        existing = cursor.fetchone()
        
        if existing:
            cursor.execute('''
                UPDATE protocol_stats 
                SET packet_count = packet_count + 1,
                    total_bytes = total_bytes + ?
                WHERE protocol = ?
            ''', (length, protocol))
        else:
            cursor.execute('''
                INSERT INTO protocol_stats (protocol, packet_count, total_bytes)
                VALUES (?, 1, ?)
            ''', (protocol, length))
    
    def update_statistics(self):
        """更新統計資料"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 檢查可疑IP (高流量或特殊行為)
            cursor.execute('''
                UPDATE ip_stats 
                SET is_suspicious = 1 
                WHERE packet_count > 1000 OR total_bytes > 10000000
            ''')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"更新統計資料時發生錯誤: {e}")

# 建立分析器實例
analyzer = PacketAnalyzer()

@app.route('/')
def index():
    """主頁面"""
    return jsonify({
        "service": "封包鑑識分析系統",
        "status": "運行中",
        "endpoints": [
            "/api/analyze",
            "/api/packets",
            "/api/ip-stats",
            "/api/protocol-stats",
            "/api/dashboard"
        ]
    })

@app.route('/api/analyze', methods=['POST'])
def analyze_pcap():
    """分析PCAP檔案的API端點"""
    try:
        data = request.get_json()
        pcap_file = data.get('pcap_file')
        
        if not pcap_file or not os.path.exists(pcap_file):
            return jsonify({"error": "PCAP檔案不存在"}), 400
        
        # 在背景執行分析
        thread = threading.Thread(target=analyzer.analyze_pcap, args=(pcap_file,))
        thread.start()
        
        return jsonify({"message": f"開始分析 {pcap_file}"}), 200
        
    except Exception as e:
        logger.error(f"API錯誤: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/packets', methods=['GET'])
def get_packets():
    """取得封包資料"""
    try:
        limit = request.args.get('limit', 100, type=int)
        offset = request.args.get('offset', 0, type=int)
        src_ip = request.args.get('src_ip')
        protocol = request.args.get('protocol')
        malicious_only = request.args.get('malicious_only', False, type=bool)
        
        conn = sqlite3.connect(analyzer.db_path)
        
        # 建構查詢
        query = "SELECT * FROM packets WHERE 1=1"
        params = []
        
        if src_ip:
            query += " AND src_ip = ?"
            params.append(src_ip)
        
        if protocol:
            query += " AND protocol = ?"
            params.append(protocol)
        
        if malicious_only:
            query += " AND is_malicious = 1"
        
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        df = pd.read_sql_query(query, conn, params=params)
        conn.close()
        
        return jsonify(df.to_dict('records'))
        
    except Exception as e:
        logger.error(f"取得封包資料錯誤: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/ip-stats', methods=['GET'])
def get_ip_stats():
    """取得IP統計資料"""
    try:
        suspicious_only = request.args.get('suspicious_only', False, type=bool)
        
        conn = sqlite3.connect(analyzer.db_path)
        
        query = "SELECT * FROM ip_stats"
        if suspicious_only:
            query += " WHERE is_suspicious = 1"
        query += " ORDER BY packet_count DESC"
        
        df = pd.read_sql_query(query, conn)
        conn.close()
        
        return jsonify(df.to_dict('records'))
        
    except Exception as e:
        logger.error(f"取得IP統計錯誤: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/protocol-stats', methods=['GET'])
def get_protocol_stats():
    """取得協定統計資料"""
    try:
        conn = sqlite3.connect(analyzer.db_path)
        df = pd.read_sql_query("SELECT * FROM protocol_stats ORDER BY packet_count DESC", conn)
        conn.close()
        
        return jsonify(df.to_dict('records'))
        
    except Exception as e:
        logger.error(f"取得協定統計錯誤: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/dashboard', methods=['GET'])
def get_dashboard_data():
    """取得儀表板資料"""
    try:
        conn = sqlite3.connect(analyzer.db_path)
        
        # 總體統計
        total_packets = pd.read_sql_query("SELECT COUNT(*) as count FROM packets", conn).iloc[0]['count']
        total_ips = pd.read_sql_query("SELECT COUNT(DISTINCT src_ip) as count FROM packets", conn).iloc[0]['count']
        malicious_packets = pd.read_sql_query("SELECT COUNT(*) as count FROM packets WHERE is_malicious = 1", conn).iloc[0]['count']
        
        # 前10名IP
        top_ips = pd.read_sql_query("""
            SELECT ip, packet_count, total_bytes, is_suspicious 
            FROM ip_stats 
            ORDER BY packet_count DESC 
            LIMIT 10
        """, conn)
        
        # 協定分布
        protocol_dist = pd.read_sql_query("""
            SELECT protocol, packet_count 
            FROM protocol_stats 
            ORDER BY packet_count DESC
        """, conn)
        
        conn.close()
        
        return jsonify({
            "summary": {
                "total_packets": total_packets,
                "total_ips": total_ips,
                "malicious_packets": malicious_packets
            },
            "top_ips": top_ips.to_dict('records'),
            "protocol_distribution": protocol_dist.to_dict('records')
        })
        
    except Exception as e:
        logger.error(f"取得儀表板資料錯誤: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    logger.info("封包鑑識分析系統啟動")
    app.run(host='0.0.0.0', port=8080, debug=False)
