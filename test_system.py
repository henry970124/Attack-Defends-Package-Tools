#!/usr/bin/env python3
"""
系統測試腳本
用於驗證各個組件是否正常運行
"""

import requests
import time
import json

def test_analysis_api():
    """測試封包分析API"""
    try:
        response = requests.get('http://localhost:8080/', timeout=5)
        print(f"✓ 封包分析系統: {response.status_code}")
        return True
    except Exception as e:
        print(f"✗ 封包分析系統: {e}")
        return False

def test_detection_api():
    """測試惡意偵測API"""
    try:
        response = requests.get('http://localhost:8081/', timeout=5)
        print(f"✓ 惡意偵測系統: {response.status_code}")
        return True
    except Exception as e:
        print(f"✗ 惡意偵測系統: {e}")
        return False

def test_web_dashboard():
    """測試Web儀表板"""
    try:
        response = requests.get('http://localhost:3000/', timeout=5)
        print(f"✓ Web儀表板: {response.status_code}")
        return True
    except Exception as e:
        print(f"✗ Web儀表板: {e}")
        return False

def test_api_endpoints():
    """測試API端點"""
    endpoints = [
        ('http://localhost:8080/api/dashboard', '分析API儀表板'),
        ('http://localhost:8081/api/stats', '偵測API統計'),
        ('http://localhost:3000/api/dashboard', 'Web API儀表板')
    ]
    
    for url, name in endpoints:
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                print(f"✓ {name}: 正常")
            else:
                print(f"⚠ {name}: HTTP {response.status_code}")
        except Exception as e:
            print(f"✗ {name}: {e}")

def main():
    print("=================================")
    print("Attack & Defense 系統測試")
    print("=================================")
    
    print("\n檢查服務狀態...")
    analysis_ok = test_analysis_api()
    detection_ok = test_detection_api()
    web_ok = test_web_dashboard()
    
    print("\n檢查API端點...")
    test_api_endpoints()
    
    print("\n測試結果:")
    if analysis_ok and detection_ok and web_ok:
        print("✓ 所有核心服務正常運行")
        print("\n您可以開始使用系統:")
        print("- 打開瀏覽器訪問: http://localhost:3000")
        print("- API文檔: http://localhost:8080 和 http://localhost:8081")
    else:
        print("✗ 某些服務可能未正常啟動")
        print("請檢查 docker-compose logs 獲取詳細資訊")

if __name__ == "__main__":
    main()
