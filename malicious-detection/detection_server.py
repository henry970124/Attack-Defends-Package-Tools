#!/usr/bin/env python3
"""
惡意流量偵測系統
使用規則和機器學習偵測惡意payload
"""

import os
import sqlite3
import logging
import json
import re
import hashlib
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import IsolationForest
import requests
import threading
import time

# 設定日誌
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/data/logs/malicious-detection.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

class MaliciousDetector:
    def __init__(self):
        self.db_path = '/data/analysis/packets.db'
        self.rules_path = '/app/rules'
        self.alert_threshold = int(os.getenv('ALERT_THRESHOLD', 5))
        self.init_detection_rules()
        self.load_ml_model()
        
    def init_detection_rules(self):
        """初始化偵測規則"""
        self.signature_rules = {
            'sql_injection': [
                r"union\s+select",
                r"'\s*or\s*'1'\s*=\s*'1",
                r"'\s*;\s*drop\s+table",
                r"exec\s*\(\s*char\s*\(",
                r"information_schema\.",
            ],
            'xss': [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"on\w+\s*=",
                r"<iframe[^>]*>",
                r"document\.cookie",
            ],
            'command_injection': [
                r";\s*cat\s+/etc/passwd",
                r";\s*ls\s+-la",
                r";\s*whoami",
                r"\|\s*nc\s+",
                r"bash\s+-i",
            ],
            'directory_traversal': [
                r"\.\./",
                r"\.\.\\",
                r"/etc/passwd",
                r"/etc/shadow",
                r"c:\\windows\\system32",
            ],
            'malware_signatures': [
                r"metasploit",
                r"meterpreter",
                r"mimikatz",
                r"cobalt.*strike",
                r"empire\s+framework",
            ]
        }
        
        # 編譯正則表達式
        self.compiled_rules = {}
        for category, patterns in self.signature_rules.items():
            self.compiled_rules[category] = [
                re.compile(pattern, re.IGNORECASE) for pattern in patterns
            ]
    
    def load_ml_model(self):
        """載入機器學習模型"""
        try:
            # 使用Isolation Forest進行異常偵測
            self.anomaly_detector = IsolationForest(
                contamination=0.1,
                random_state=42
            )
            
            # TF-IDF向量化器用於文本分析
            self.tfidf_vectorizer = TfidfVectorizer(
                max_features=1000,
                ngram_range=(1, 3),
                analyzer='char'
            )
            
            logger.info("機器學習模型初始化完成")
            
        except Exception as e:
            logger.error(f"載入機器學習模型失敗: {e}")
    
    def detect_malicious_payload(self, payload, src_ip, dst_ip, protocol):
        """偵測惡意payload"""
        detections = []
        
        try:
            # 解碼hex payload
            if payload:
                try:
                    decoded_payload = bytes.fromhex(payload).decode('utf-8', errors='ignore')
                except:
                    decoded_payload = payload
            else:
                decoded_payload = ""
            
            # 規則基礎偵測
            rule_detections = self.rule_based_detection(decoded_payload)
            detections.extend(rule_detections)
            
            # 機器學習偵測
            ml_detections = self.ml_based_detection(decoded_payload)
            detections.extend(ml_detections)
            
            # 行為分析
            behavior_detections = self.behavior_analysis(src_ip, dst_ip, protocol)
            detections.extend(behavior_detections)
            
            return detections
            
        except Exception as e:
            logger.error(f"偵測惡意payload時發生錯誤: {e}")
            return []
    
    def rule_based_detection(self, payload):
        """規則基礎偵測"""
        detections = []
        
        for category, patterns in self.compiled_rules.items():
            for pattern in patterns:
                if pattern.search(payload):
                    detections.append({
                        'type': 'signature',
                        'category': category,
                        'severity': 'high',
                        'description': f'偵測到{category}攻擊特徵',
                        'pattern': pattern.pattern
                    })
        
        return detections
    
    def ml_based_detection(self, payload):
        """機器學習基礎偵測"""
        detections = []
        
        try:
            if len(payload) < 10:  # 太短的payload跳過
                return detections
            
            # 特徵提取
            features = self.extract_features(payload)
            
            # 異常分數
            anomaly_score = self.anomaly_detector.decision_function([features])[0]
            
            if anomaly_score < -0.5:  # 異常閾值
                detections.append({
                    'type': 'anomaly',
                    'category': 'suspicious_payload',
                    'severity': 'medium',
                    'description': f'異常payload偵測 (分數: {anomaly_score:.3f})',
                    'score': anomaly_score
                })
                
        except Exception as e:
            logger.error(f"機器學習偵測錯誤: {e}")
        
        return detections
    
    def behavior_analysis(self, src_ip, dst_ip, protocol):
        """行為分析"""
        detections = []
        
        try:
            # 檢查高頻率連線
            if self.check_high_frequency_connections(src_ip):
                detections.append({
                    'type': 'behavior',
                    'category': 'high_frequency',
                    'severity': 'medium',
                    'description': f'偵測到來自 {src_ip} 的高頻率連線'
                })
            
            # 檢查端口掃描
            if self.check_port_scanning(src_ip):
                detections.append({
                    'type': 'behavior',
                    'category': 'port_scanning',
                    'severity': 'high',
                    'description': f'偵測到來自 {src_ip} 的端口掃描行為'
                })
                
        except Exception as e:
            logger.error(f"行為分析錯誤: {e}")
        
        return detections
    
    def extract_features(self, payload):
        """提取payload特徵"""
        features = []
        
        # 基本統計特徵
        features.append(len(payload))  # 長度
        features.append(payload.count(' '))  # 空格數量
        features.append(payload.count('\n'))  # 換行數量
        features.append(len(set(payload)))  # 唯一字符數
        
        # 字符統計
        alpha_count = sum(c.isalpha() for c in payload)
        digit_count = sum(c.isdigit() for c in payload)
        special_count = len(payload) - alpha_count - digit_count
        
        features.extend([alpha_count, digit_count, special_count])
        
        # 熵值計算
        entropy = self.calculate_entropy(payload)
        features.append(entropy)
        
        return features
    
    def calculate_entropy(self, data):
        """計算字串熵值"""
        if not data:
            return 0
        
        counts = {}
        for char in data:
            counts[char] = counts.get(char, 0) + 1
        
        entropy = 0
        length = len(data)
        for count in counts.values():
            if count > 0:
                probability = count / length
                entropy -= probability * np.log2(probability)
        
        return entropy
    
    def check_high_frequency_connections(self, src_ip):
        """檢查高頻率連線"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 檢查最近5分鐘內的連線數
            cursor.execute('''
                SELECT COUNT(*) FROM packets 
                WHERE src_ip = ? AND timestamp > datetime('now', '-5 minutes')
            ''', (src_ip,))
            
            count = cursor.fetchone()[0]
            conn.close()
            
            return count > 100  # 5分鐘內超過100個連線
            
        except Exception as e:
            logger.error(f"檢查高頻率連線錯誤: {e}")
            return False
    
    def check_port_scanning(self, src_ip):
        """檢查端口掃描"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 檢查最近10分鐘內連接的不同端口數
            cursor.execute('''
                SELECT COUNT(DISTINCT dst_port) FROM packets 
                WHERE src_ip = ? AND timestamp > datetime('now', '-10 minutes')
                AND dst_port IS NOT NULL
            ''', (src_ip,))
            
            port_count = cursor.fetchone()[0]
            conn.close()
            
            return port_count > 50  # 10分鐘內掃描超過50個端口
            
        except Exception as e:
            logger.error(f"檢查端口掃描錯誤: {e}")
            return False
    
    def mark_malicious_packet(self, packet_id, detections):
        """標記惡意封包"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            malicious_types = [d['category'] for d in detections]
            
            cursor.execute('''
                UPDATE packets 
                SET is_malicious = 1, malicious_type = ?
                WHERE id = ?
            ''', (json.dumps(malicious_types), packet_id))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"標記惡意封包錯誤: {e}")
    
    def scan_packets(self):
        """掃描並分析封包"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 取得未分析的封包
            cursor.execute('''
                SELECT id, src_ip, dst_ip, protocol, payload 
                FROM packets 
                WHERE is_malicious = 0 AND payload IS NOT NULL AND payload != ''
                ORDER BY timestamp DESC 
                LIMIT 100
            ''')
            
            packets = cursor.fetchall()
            conn.close()
            
            for packet in packets:
                packet_id, src_ip, dst_ip, protocol, payload = packet
                
                detections = self.detect_malicious_payload(payload, src_ip, dst_ip, protocol)
                
                if detections:
                    logger.warning(f"偵測到惡意活動 - 封包ID: {packet_id}, IP: {src_ip}")
                    self.mark_malicious_packet(packet_id, detections)
                    
                    # 通知分析系統
                    self.notify_analysis_system(packet_id, src_ip, detections)
            
        except Exception as e:
            logger.error(f"掃描封包錯誤: {e}")
    
    def notify_analysis_system(self, packet_id, src_ip, detections):
        """通知分析系統"""
        try:
            data = {
                'packet_id': packet_id,
                'src_ip': src_ip,
                'detections': detections,
                'timestamp': datetime.now().isoformat()
            }
            
            # 發送到分析系統 (這裡可以擴展為更複雜的通知機制)
            logger.info(f"惡意活動警報: {data}")
            
        except Exception as e:
            logger.error(f"通知分析系統錯誤: {e}")

# 建立偵測器實例
detector = MaliciousDetector()

@app.route('/')
def index():
    """主頁面"""
    return jsonify({
        "service": "惡意流量偵測系統",
        "status": "運行中",
        "endpoints": [
            "/api/scan",
            "/api/detections",
            "/api/stats"
        ]
    })

@app.route('/api/scan', methods=['POST'])
def manual_scan():
    """手動掃描"""
    try:
        detector.scan_packets()
        return jsonify({"message": "掃描完成"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/detections', methods=['GET'])
def get_detections():
    """取得偵測結果"""
    try:
        limit = request.args.get('limit', 50, type=int)
        
        conn = sqlite3.connect(detector.db_path)
        df = pd.read_sql_query('''
            SELECT * FROM packets 
            WHERE is_malicious = 1 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', conn, params=[limit])
        conn.close()
        
        return jsonify(df.to_dict('records'))
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/stats', methods=['GET'])
def get_detection_stats():
    """取得偵測統計"""
    try:
        conn = sqlite3.connect(detector.db_path)
        
        # 總體統計
        total_packets = pd.read_sql_query("SELECT COUNT(*) as count FROM packets", conn).iloc[0]['count']
        malicious_packets = pd.read_sql_query("SELECT COUNT(*) as count FROM packets WHERE is_malicious = 1", conn).iloc[0]['count']
        
        # 惡意類型分布
        malicious_types = pd.read_sql_query('''
            SELECT malicious_type, COUNT(*) as count 
            FROM packets 
            WHERE is_malicious = 1 AND malicious_type IS NOT NULL
            GROUP BY malicious_type
        ''', conn)
        
        conn.close()
        
        return jsonify({
            "total_packets": total_packets,
            "malicious_packets": malicious_packets,
            "detection_rate": malicious_packets / total_packets if total_packets > 0 else 0,
            "malicious_types": malicious_types.to_dict('records')
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def background_scanner():
    """背景掃描器"""
    logger.info("背景掃描器啟動")
    while True:
        try:
            detector.scan_packets()
            time.sleep(30)  # 每30秒掃描一次
        except Exception as e:
            logger.error(f"背景掃描錯誤: {e}")
            time.sleep(60)

if __name__ == '__main__':
    # 啟動背景掃描器
    scanner_thread = threading.Thread(target=background_scanner, daemon=True)
    scanner_thread.start()
    
    logger.info("惡意流量偵測系統啟動")
    app.run(host='0.0.0.0', port=8081, debug=False)
