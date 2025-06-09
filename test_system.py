#!/usr/bin/env python3

"""
Test script for the improved SDN Honeypot system
Tests ML model integration and flow table redirection
"""

import sys
import os
import requests
import json
import time

# Add ML model to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'ml_model'))
from simulate_model import classify_traffic

def test_ml_model():
    """Test the simplified ML model"""
    print("🧪 Testing Simulated ML Model")
    print("=" * 50)
    
    test_cases = [
        # High risk cases (should return 1)
        ('10.0.0.6', {'username': 'admin', 'user_agent': 'curl/7.68.0'}),
        ('10.0.0.6', {'username': 'root', 'user_agent': 'python-requests'}),
        
        # Medium risk cases
        ('192.168.1.50', {'username': 'user', 'user_agent': 'Mozilla/5.0'}),
        
        # Low risk cases (should return 0)
        ('192.168.1.100', {'username': 'john_doe', 'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}),
    ]
    
    for i, (ip, data) in enumerate(test_cases, 1):
        # Simulate multiple requests for frequency testing
        for _ in range(5):
            prediction, risk_score = classify_traffic(ip, data)
        
        print(f"Test {i}: IP={ip}")
        print(f"  Username: {data['username']}")
        print(f"  User-Agent: {data['user_agent']}")
        print(f"  ML Prediction: {prediction} ({'Malicious' if prediction == 1 else 'Benign'})")
        print(f"  Risk Score: {risk_score:.3f}")
        print()

def test_controller_api():
    """Test controller API integration"""
    print("🌐 Testing Controller API Integration")
    print("=" * 50)
    
    controller_url = "http://localhost:8080"
    
    # Test classification endpoint
    test_data = {
        'source_ip': '10.0.0.6',
        'classification': 'malicious',
        'risk_score': 85,
        'ml_prediction': 1,
        'honeypot_type': 'triage'
    }
    
    try:
        response = requests.post(f"{controller_url}/honeypot/classification", 
                               json=test_data, timeout=5)
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Classification API: {result}")
        else:
            print(f"❌ Classification API failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Controller API not accessible: {e}")
        print("   Make sure the controller is running with:")
        print("   ryu-manager controller/controller.py --wsapi-port 8080")
    
    # Test stats endpoint
    try:
        response = requests.get(f"{controller_url}/honeypot/stats", timeout=5)
        if response.status_code == 200:
            stats = response.json()
            print(f"✅ Stats API: {stats}")
        else:
            print(f"❌ Stats API failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Stats API not accessible: {e}")

def test_triage_honeypot():
    """Test triage honeypot ML integration"""
    print("🍯 Testing Triage Honeypot ML Integration")
    print("=" * 50)
    
    # Check if running in network namespace aware mode
    print("🔍 Checking triage honeypot process...")
    import subprocess
    try:
        # Check if triage honeypot process is running
        result = subprocess.run(['pgrep', '-f', 'python3.*app.py 8004'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ Triage Honeypot Process: Running (PID: {})".format(result.stdout.strip()))
            print("📍 Location: Mininet namespace (10.0.0.4:8004)")
            print("ℹ️  Note: Direct localhost testing skipped due to network namespace isolation")
            print("💡 To test honeypot functionality, use Mininet CLI:")
            print("   h6 curl -s http://10.0.0.4:8004/api/ml_status")
        else:
            print("❌ Triage Honeypot Process: Not running")
            print("   Make sure the system is started with ./start_system.sh")
    except Exception as e:
        print(f"❌ Cannot check triage honeypot: {e}")
        
    # Check if localhost access works (for debugging)
    honeypot_url = "http://localhost:8004"
    try:
        response = requests.get(f"{honeypot_url}/api/ml_status", timeout=2)
        if response.status_code == 200:
            ml_status = response.json()
            print(f"✅ Direct localhost access works: {ml_status}")
    except:
        print("ℹ️  localhost:8004 not accessible (expected in Mininet setup)")

def simulate_attack_traffic():
    """Simulate various types of traffic for testing"""
    print("⚔️  Simulating Attack Traffic")
    print("=" * 50)
    
    # Simulate multiple rapid requests (should trigger ML model)
    print("Simulating rapid-fire requests...")
    for i in range(10):
        prediction, risk_score = classify_traffic('10.0.0.6', {
            'username': 'admin',
            'user_agent': 'curl/7.68.0'
        })
        print(f"Request {i+1}: Prediction={prediction}, Risk={risk_score:.3f}")
        time.sleep(0.1)  # Short delay between requests

def generate_flow_table_summary():
    """Generate summary of expected flow table rules"""
    print("📋 Expected Flow Table Rules Summary")
    print("=" * 50)
    
    print("HIGH PRIORITY (200): Redirection flows")
    print("  - Malicious traffic → Deep honeypot")
    print("  - Suspicious traffic → Triage honeypot")
    print("  - Bidirectional flows with 600s timeout")
    print()
    
    print("MEDIUM PRIORITY (50): Topology forwarding")
    print("  - s1: Routes to s2 and s3 based on destination")
    print("  - s2: Routes to s4 and s5")
    print("  - s3: Routes to s6 and s7")
    print()
    
    print("LOW PRIORITY (10): ARP flooding")
    print("LOW PRIORITY (0): Default to controller")

if __name__ == '__main__':
    print("🛡️  SDN Honeypot System Test Suite")
    print("=" * 60)
    print()
    
    # Run all tests
    test_ml_model()
    print()
    
    test_controller_api()
    print()
    
    test_triage_honeypot()
    print()
    
    simulate_attack_traffic()
    print()
    
    generate_flow_table_summary()
    print()
    
    print("✅ Test suite completed!")
    print("\nTo run the complete system:")
    print("1. Start controller: ryu-manager controller/controller.py --wsapi-port 8080")
    print("2. Start topology: sudo python3 topology/topology.py")
    print("3. In Mininet CLI, test with: h6 curl http://10.0.0.1:8001/") 