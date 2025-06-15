#!/usr/bin/env python3
"""
SDN Honeypot Controller API Test Script
Bu script controller'a doğrudan classification verileri gönderir
"""

import requests
import time
import random
import datetime
import json
from typing import List, Dict

# Controller URL
CONTROLLER_URL = "http://localhost:8080"

def send_classification(source_ip: str, classification: str, risk_score: float, ml_prediction: int = None, honeypot_type: str = "test"):
    """Controller'a classification verisi gönder"""
    url = f"{CONTROLLER_URL}/honeypot/classification"
    
    data = {
        'source_ip': source_ip,
        'classification': classification,
        'risk_score': risk_score * 100,  # 0-100 scale
        'honeypot_type': honeypot_type,
        'ml_prediction': ml_prediction,
        'timestamp': datetime.datetime.now().isoformat()
    }
    
    try:
        response = requests.post(url, json=data, timeout=5)
        if response.status_code == 200:
            print(f"✅ Sent {classification} classification for {source_ip} (risk: {risk_score:.2f})")
            return True
        else:
            print(f"❌ Failed to send classification: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error sending classification: {e}")
        return False

def get_controller_stats():
    """Controller istatistiklerini al"""
    try:
        response = requests.get(f"{CONTROLLER_URL}/api/stats", timeout=5)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"❌ Failed to get stats: {response.status_code}")
            return None
    except Exception as e:
        print(f"❌ Error getting stats: {e}")
        return None

def simulate_normal_traffic():
    """Normal trafik simülasyonu"""
    normal_ips = ["10.0.0.6", "192.168.1.50", "192.168.1.75"]
    
    for ip in normal_ips:
        risk = random.uniform(0.1, 0.3)  # Düşük risk
        send_classification(ip, "normal", risk, 0, "triage")
        time.sleep(0.5)

def simulate_suspicious_traffic():
    """Şüpheli trafik simülasyonu"""
    suspicious_ips = ["203.0.113.10", "198.51.100.20", "192.0.2.30"]
    
    for ip in suspicious_ips:
        risk = random.uniform(0.4, 0.7)  # Orta risk
        send_classification(ip, "suspicious", risk, 0, "triage")
        time.sleep(0.5)

def simulate_malicious_traffic():
    """Kötü amaçlı trafik simülasyonu"""
    malicious_ips = ["185.220.101.15", "45.227.253.8", "91.240.118.172"]
    
    for ip in malicious_ips:
        risk = random.uniform(0.8, 1.0)  # Yüksek risk
        ml_pred = 1 if risk > 0.85 else 0
        send_classification(ip, "malicious", risk, ml_pred, "deep")
        time.sleep(0.5)

def simulate_attack_scenario():
    """Gerçekçi saldırı senaryosu simülasyonu"""
    print("🎯 Simulating realistic attack scenario...")
    
    # Saldırgan IP
    attacker_ip = "178.128.83.165"
    
    scenarios = [
        ("Port scanning", "suspicious", 0.6, 0),
        ("Login bruteforce attempt", "suspicious", 0.7, 0),
        ("Multiple failed logins", "malicious", 0.8, 1),
        ("Admin panel access", "malicious", 0.9, 1),
        ("File download attempt", "malicious", 1.0, 1),
    ]
    
    for description, classification, risk, ml_pred in scenarios:
        print(f"  📡 {description}")
        send_classification(attacker_ip, classification, risk, ml_pred, "deep")
        time.sleep(2)

def continuous_monitoring():
    """Sürekli monitoring simülasyonu"""
    print("🔄 Starting continuous monitoring simulation...")
    print("Press Ctrl+C to stop")
    
    try:
        while True:
            # Random aktivite simülasyonu
            activity_type = random.choices(
                ['normal', 'suspicious', 'malicious'], 
                weights=[60, 30, 10]  # %60 normal, %30 şüpheli, %10 kötü amaçlı
            )[0]
            
            if activity_type == 'normal':
                simulate_normal_traffic()
            elif activity_type == 'suspicious':
                simulate_suspicious_traffic()
            else:
                simulate_malicious_traffic()
            
            # İstatistikleri göster
            stats = get_controller_stats()
            if stats:
                print(f"📊 Stats: Active IPs: {stats.get('active_ips', 0)}, "
                      f"Suspicious: {len(stats.get('suspicious_ips', []))}, "
                      f"Malicious: {len(stats.get('malicious_ips', []))}")
            
            time.sleep(5)  # 5 saniye bekle
            
    except KeyboardInterrupt:
        print("\n🛑 Monitoring stopped")

def main():
    """Ana menü"""
    print("🛡️  SDN Honeypot Controller API Test Script")
    print("=" * 50)
    
    # Controller erişilebilirlik testi
    stats = get_controller_stats()
    if not stats:
        print("❌ Controller'a erişilemiyor! Önce sistemi başlatın.")
        return
    
    print("✅ Controller'a bağlanıldı!")
    print()
    
    while True:
        print("\nSeçenekler:")
        print("1. Normal trafik simülasyonu")
        print("2. Şüpheli trafik simülasyonu") 
        print("3. Kötü amaçlı trafik simülasyonu")
        print("4. Gerçekçi saldırı senaryosu")
        print("5. Sürekli monitoring simülasyonu")
        print("6. Controller istatistikleri")
        print("0. Çıkış")
        
        choice = input("\nSeçiminiz (0-6): ").strip()
        
        if choice == "1":
            simulate_normal_traffic()
        elif choice == "2":
            simulate_suspicious_traffic()
        elif choice == "3":
            simulate_malicious_traffic()
        elif choice == "4":
            simulate_attack_scenario()
        elif choice == "5":
            continuous_monitoring()
        elif choice == "6":
            stats = get_controller_stats()
            if stats:
                print(json.dumps(stats, indent=2))
        elif choice == "0":
            print("👋 Goodbye!")
            break
        else:
            print("❌ Geçersiz seçim!")

if __name__ == "__main__":
    main() 