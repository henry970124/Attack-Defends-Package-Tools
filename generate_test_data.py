#!/usr/bin/env python3
"""
模擬測試資料產生器
用於產生測試封包和惡意流量
"""

import sqlite3
import random
import time
from datetime import datetime, timedelta
import json

# 模擬IP地址池
IP_POOLS = {
    'normal': [
        '192.168.1.100', '192.168.1.101', '192.168.1.102',
        '10.0.0.10', '10.0.0.11', '10.0.0.12',
        '172.16.0.5', '172.16.0.6'
    ],
    'suspicious': [
        '203.0.113.1', '198.51.100.1', '203.0.113.254',
        '192.0.2.1', '198.51.100.254'
    ],
    'external': [
        '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1',
        '208.67.222.222', '208.67.220.220'
    ]
}

PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'FTP', 'SSH']

# 惡意payload範例
MALICIOUS_PAYLOADS = [
    "' OR '1'='1",  # SQL Injection
    "<script>alert('XSS')</script>",  # XSS
    "; cat /etc/passwd",  # Command Injection
    "../../../etc/passwd",  # Directory Traversal
    "metasploit payload",  # Malware signature
]

def create_test_database():
    """建立測試資料庫和資料"""
    db_path = './shared/analysis/packets.db'
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # 確保資料表存在
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
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS protocol_stats (
                protocol TEXT PRIMARY KEY,
                packet_count INTEGER DEFAULT 0,
                total_bytes INTEGER DEFAULT 0
            )
        ''')
        
        # 產生測試封包
        print("產生測試封包資料...")
        generate_test_packets(cursor, 1000)  # 產生1000個正常封包
        generate_malicious_packets(cursor, 50)  # 產生50個惡意封包
        
        # 更新統計資料
        print("更新統計資料...")
        update_statistics(cursor)
        
        conn.commit()
        conn.close()
        
        print("✓ 測試資料庫建立完成")
        return True
        
    except Exception as e:
        print(f"✗ 建立測試資料庫失敗: {e}")
        return False

def generate_test_packets(cursor, count):
    """產生正常測試封包"""
    for i in range(count):
        timestamp = datetime.now() - timedelta(hours=random.randint(0, 24))
        src_ip = random.choice(IP_POOLS['normal'])
        dst_ip = random.choice(IP_POOLS['external'])
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 21, 25, 53, 110, 143])
        protocol = random.choice(PROTOCOLS)
        length = random.randint(64, 1500)
        payload = generate_normal_payload()
        pcap_file = f"/data/pcap/test_{timestamp.strftime('%Y%m%d')}.pcap"
        
        cursor.execute('''
            INSERT INTO packets 
            (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, payload, pcap_file)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, payload, pcap_file))

def generate_malicious_packets(cursor, count):
    """產生惡意測試封包"""
    malicious_types = ['sql_injection', 'xss', 'command_injection', 'directory_traversal', 'malware_signatures']
    
    for i in range(count):
        timestamp = datetime.now() - timedelta(hours=random.randint(0, 12))
        src_ip = random.choice(IP_POOLS['suspicious'])
        dst_ip = random.choice(IP_POOLS['normal'])
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 21])
        protocol = random.choice(['TCP', 'HTTP', 'HTTPS'])
        length = random.randint(100, 2000)
        payload = random.choice(MALICIOUS_PAYLOADS).encode().hex()
        pcap_file = f"/data/pcap/test_{timestamp.strftime('%Y%m%d')}.pcap"
        malicious_type = json.dumps([random.choice(malicious_types)])
        
        cursor.execute('''
            INSERT INTO packets 
            (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, payload, pcap_file, is_malicious, malicious_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
        ''', (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, payload, pcap_file, malicious_type))

def generate_normal_payload():
    """產生正常的payload"""
    normal_payloads = [
        "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "POST /api/data HTTP/1.1\r\nContent-Type: application/json\r\n\r\n",
        "SSH-2.0-OpenSSH_7.4",
        "220 FTP Server ready",
        "",  # 空payload
    ]
    return random.choice(normal_payloads).encode().hex()

def update_statistics(cursor):
    """更新統計資料"""
    # 更新IP統計
    all_ips = set()
    cursor.execute('SELECT DISTINCT src_ip FROM packets')
    all_ips.update([row[0] for row in cursor.fetchall()])
    cursor.execute('SELECT DISTINCT dst_ip FROM packets')
    all_ips.update([row[0] for row in cursor.fetchall()])
    
    for ip in all_ips:
        cursor.execute('''
            SELECT COUNT(*), SUM(length), MIN(timestamp), MAX(timestamp)
            FROM packets 
            WHERE src_ip = ? OR dst_ip = ?
        ''', (ip, ip))
        
        packet_count, total_bytes, first_seen, last_seen = cursor.fetchone()
        total_bytes = total_bytes or 0
        
        is_suspicious = 1 if ip in IP_POOLS['suspicious'] else 0
        
        cursor.execute('''
            INSERT OR REPLACE INTO ip_stats 
            (ip, packet_count, total_bytes, first_seen, last_seen, is_suspicious)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (ip, packet_count, total_bytes, first_seen, last_seen, is_suspicious))
    
    # 更新協定統計
    cursor.execute('''
        SELECT protocol, COUNT(*), SUM(length)
        FROM packets 
        GROUP BY protocol
    ''')
    
    for protocol, packet_count, total_bytes in cursor.fetchall():
        total_bytes = total_bytes or 0
        cursor.execute('''
            INSERT OR REPLACE INTO protocol_stats 
            (protocol, packet_count, total_bytes)
            VALUES (?, ?, ?)
        ''', (protocol, packet_count, total_bytes))

def main():
    print("=================================")
    print("Attack & Defense 測試資料產生器")
    print("=================================")
    
    print("正在建立測試資料...")
    
    if create_test_database():
        print("\n✓ 測試資料產生完成!")
        print("\n產生的資料:")
        print("- 1000個正常封包")
        print("- 50個惡意封包")
        print("- IP和協定統計資料")
        print("\n現在您可以:")
        print("1. 啟動系統: docker-compose up -d")
        print("2. 訪問Web介面: http://localhost:3000")
        print("3. 查看分析結果")
    else:
        print("\n✗ 測試資料產生失敗")
        print("請確保shared/analysis目錄存在且有寫入權限")

if __name__ == "__main__":
    main()
