#!/usr/bin/env python3
"""
快速設定腳本
一鍵設定和啟動Attack & Defense系統
"""

import os
import subprocess
import sys
import time
import requests

def run_command(command, description):
    """執行命令並顯示結果"""
    print(f"正在{description}...")
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✓ {description}完成")
            return True
        else:
            print(f"✗ {description}失敗: {result.stderr}")
            return False
    except Exception as e:
        print(f"✗ {description}失敗: {e}")
        return False

def check_docker():
    """檢查Docker是否安裝"""
    return run_command("docker --version", "檢查Docker")

def check_docker_compose():
    """檢查Docker Compose是否安裝"""
    return run_command("docker-compose --version", "檢查Docker Compose")

def create_directories():
    """建立必要目錄"""
    directories = [
        "shared/pcap",
        "shared/analysis", 
        "shared/logs"
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
    print("✓ 目錄結構建立完成")

def build_and_start():
    """建置並啟動服務"""
    print("正在建置Docker映像檔...")
    if not run_command("docker-compose build", "建置Docker映像檔"):
        return False
    
    print("正在啟動服務...")
    if not run_command("docker-compose up -d", "啟動服務"):
        return False
    
    return True

def wait_for_services():
    """等待服務啟動"""
    print("等待服務啟動...")
    
    services = [
        ("http://localhost:8080", "封包分析服務"),
        ("http://localhost:8081", "惡意偵測服務"),
        ("http://localhost:3000", "Web儀表板")
    ]
    
    max_retries = 30
    for url, name in services:
        for i in range(max_retries):
            try:
                response = requests.get(url, timeout=2)
                if response.status_code in [200, 404]:  # 404也表示服務在運行
                    print(f"✓ {name}已啟動")
                    break
            except:
                pass
            
            if i == max_retries - 1:
                print(f"⚠ {name}可能未正確啟動")
            else:
                time.sleep(2)

def generate_test_data():
    """產生測試資料"""
    print("正在產生測試資料...")
    if os.path.exists("generate_test_data.py"):
        return run_command("python generate_test_data.py", "產生測試資料")
    else:
        print("⚠ 測試資料產生器不存在，跳過此步驟")
        return True

def show_status():
    """顯示系統狀態"""
    print("\n正在檢查服務狀態...")
    run_command("docker-compose ps", "檢查服務狀態")

def main():
    print("=========================================")
    print("Attack & Defense 封包分析系統 - 快速設定")
    print("=========================================")
    
    # 檢查前置需求
    print("\n1. 檢查前置需求...")
    if not check_docker():
        print("請先安裝Docker: https://docs.docker.com/get-docker/")
        return False
    
    if not check_docker_compose():
        print("請先安裝Docker Compose: https://docs.docker.com/compose/install/")
        return False
    
    # 建立目錄結構
    print("\n2. 建立目錄結構...")
    create_directories()
    
    # 停止現有服務
    print("\n3. 停止現有服務...")
    run_command("docker-compose down", "停止現有服務")
    
    # 建置並啟動服務
    print("\n4. 建置並啟動服務...")
    if not build_and_start():
        print("啟動失敗，請檢查錯誤訊息")
        return False
    
    # 等待服務啟動
    print("\n5. 等待服務啟動...")
    wait_for_services()
    
    # 產生測試資料
    print("\n6. 產生測試資料...")
    generate_test_data()
    
    # 顯示狀態
    print("\n7. 檢查最終狀態...")
    show_status()
    
    # 顯示成功訊息
    print("\n" + "="*50)
    print("🎉 系統設定完成！")
    print("="*50)
    print("\n服務端點:")
    print("📊 Web儀表板:     http://localhost:3000")
    print("🔍 封包分析API:   http://localhost:8080")
    print("🛡️ 惡意偵測API:   http://localhost:8081")
    print("\n常用命令:")
    print("查看日誌:         docker-compose logs [service_name]")
    print("停止系統:         docker-compose down")
    print("重新啟動:         docker-compose restart")
    print("\n開始使用您的Attack & Defense封包分析系統吧！")
    
    return True

if __name__ == "__main__":
    if main():
        sys.exit(0)
    else:
        sys.exit(1)
