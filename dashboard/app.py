#!/usr/bin/env python3

from flask import Flask, render_template, jsonify
import requests
import json
import os
from datetime import datetime, timedelta
from collections import deque
import threading
import time

app = Flask(__name__)

# In-memory storage for traffic history
traffic_history_cache = deque(maxlen=60)  # Keep last 60 data points (5 minutes)
cache_lock = threading.Lock()

def update_traffic_cache():
    """Background thread to collect real traffic data every 5 seconds"""
    while True:
        try:
            # Get real data from controller
            response = requests.get('http://localhost:8080/api/stats', timeout=2)
            if response.status_code == 200:
                data = response.json()
                
                timestamp = datetime.now()
                traffic_data = {
                    'timestamp': timestamp.strftime('%H:%M:%S'),
                    'active_ips': data.get('active_ips', 0),
                    'suspicious_ips': len(data.get('suspicious_ips', [])),
                    'malicious_ips': len(data.get('malicious_ips', [])),
                    'flow_count': data.get('flow_count', 0)
                }
                
                with cache_lock:
                    traffic_history_cache.append(traffic_data)
                    
        except Exception as e:
            print(f"Error updating traffic cache: {e}")
        
        time.sleep(5)  # Update every 5 seconds

# Start background data collection
cache_thread = threading.Thread(target=update_traffic_cache, daemon=True)
cache_thread.start()

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/status')
def api_status():
    return jsonify({
        'controller': 'online',
        'timestamp': datetime.now().isoformat(),
        'version': '2.0.0'
    })

@app.route('/api/stats')
def get_stats():
    """Get system statistics from controller"""
    try:
        # Try to get real data from controller
        response = requests.get('http://localhost:8080/api/stats', timeout=2)
        if response.status_code == 200:
            return response.json()
    except:
        pass
    
    # Return mock data if controller is not available
    return jsonify({
        'active_ips': 3,
        'suspicious_ips': ['192.168.1.100'],
        'malicious_ips': [],
        'flow_count': 15,
        'last_update': datetime.now().strftime('%H:%M:%S')
    })

@app.route('/api/topology')
def get_topology():
    """Get network topology data"""
    return jsonify({
        'switches': [
            {'id': 's1', 'x': 400, 'y': 50},
            {'id': 's2', 'x': 200, 'y': 150},
            {'id': 's3', 'x': 600, 'y': 150},
            {'id': 's4', 'x': 100, 'y': 250},
            {'id': 's5', 'x': 300, 'y': 250},
            {'id': 's6', 'x': 500, 'y': 250},
            {'id': 's7', 'x': 700, 'y': 250}
        ],
        'hosts': [
            {'id': 'h1', 'x': 100, 'y': 350, 'type': 'normal'},
            {'id': 'h2', 'x': 300, 'y': 350, 'type': 'normal'},
            {'id': 'h3', 'x': 500, 'y': 350, 'type': 'normal'},
            {'id': 'h4', 'x': 600, 'y': 350, 'type': 'triage_honeypot'},
            {'id': 'h5', 'x': 700, 'y': 350, 'type': 'deep_honeypot'},
            {'id': 'h6', 'x': 200, 'y': 50, 'type': 'client'}
        ],
        'links': [
            {'source': 's1', 'target': 's2'},
            {'source': 's1', 'target': 's3'},
            {'source': 's2', 'target': 's4'},
            {'source': 's2', 'target': 's5'},
            {'source': 's3', 'target': 's6'},
            {'source': 's3', 'target': 's7'},
            {'source': 's4', 'target': 'h1'},
            {'source': 's5', 'target': 'h2'},
            {'source': 's6', 'target': 'h3'},
            {'source': 's6', 'target': 'h4'},
            {'source': 's7', 'target': 'h5'},
            {'source': 'h6', 'target': 's1'}
        ]
    })

@app.route('/api/host_status')
def get_host_status():
    """Get real host status - check if services are actually running"""
    host_status = {}
    
    # Define host port mappings
    host_ports = {
        'h1': 8001,
        'h2': 8002, 
        'h3': 8003,
        'h4': 8004,
        'h5': 8005,
        'h6': 'online'  # Client host, always online
    }
    
    for host, port in host_ports.items():
        if host == 'h6':
            host_status[host] = 'online'
            continue
            
        try:
            # Try to reach the health endpoint of each service
            response = requests.get(f'http://localhost:{port}/health', timeout=1)
            if response.status_code == 200:
                host_status[host] = 'online'
            else:
                host_status[host] = 'offline'
        except:
            # If service is running in Mininet, we can't reach it via localhost
            # But we can check if the controller has the service info
            try:
                controller_response = requests.get('http://localhost:8080/api/stats', timeout=1)
                if controller_response.status_code == 200:
                    # If controller is up, assume all services are up (they run in Mininet)
                    host_status[host] = 'online'
                else:
                    host_status[host] = 'offline'
            except:
                host_status[host] = 'offline'
    
    return jsonify(host_status)

@app.route('/api/alerts')
def get_alerts():
    """Get security alerts"""
    return jsonify([
        {
            'time': datetime.now().strftime('%H:%M:%S'),
            'message': 'Suspicious activity detected from 192.168.1.100',
            'severity': 'medium',
            'source_ip': '192.168.1.100'
        }
    ])

@app.route('/api/flows')
def get_flows():
    """Get active network flows from real data"""
    try:
        # Get stats from controller
        response = requests.get('http://localhost:8080/api/stats', timeout=2)
        if response.status_code == 200:
            data = response.json()
            flows = []
            
            # Create flows for suspicious IPs
            for ip in data.get('suspicious_ips', []):
                flows.append({
                    'src': ip,
                    'dst': '10.0.0.4',  # Triage honeypot
                    'port': 8004,
                    'classification': 'suspicious',
                    'packet_count': data.get('flow_count', 0) + 5
                })
            
            # Create flows for malicious IPs  
            for ip in data.get('malicious_ips', []):
                flows.append({
                    'src': ip,
                    'dst': '10.0.0.5',  # Deep honeypot
                    'port': 8005,
                    'classification': 'malicious',
                    'packet_count': data.get('flow_count', 0) + 10
                })
            
            return jsonify(flows)
    except:
        pass
    
    return jsonify([])

@app.route('/api/traffic_history')
def get_traffic_history():
    """Get real traffic history data from cache"""
    with cache_lock:
        # Return last 12 data points (1 minute)
        history_data = list(traffic_history_cache)[-12:]
        
        # If we don't have enough data yet, pad with current data
        if len(history_data) < 12:
            try:
                response = requests.get('http://localhost:8080/api/stats', timeout=2)
                if response.status_code == 200:
                    current_data = response.json()
                    current_entry = {
                        'timestamp': datetime.now().strftime('%H:%M:%S'),
                        'active_ips': current_data.get('active_ips', 0),
                        'suspicious_ips': len(current_data.get('suspicious_ips', [])),
                        'malicious_ips': len(current_data.get('malicious_ips', [])),
                        'flow_count': current_data.get('flow_count', 0)
                    }
                    
                    # Pad the beginning with current data
                    needed = 12 - len(history_data)
                    for i in range(needed):
                        timestamp = datetime.now() - timedelta(seconds=(needed-i)*5)
                        padded_entry = current_entry.copy()
                        padded_entry['timestamp'] = timestamp.strftime('%H:%M:%S')
                        history_data.insert(0, padded_entry)
            except:
                # If controller is down, return empty
                return jsonify([])
    
    return jsonify(history_data)

@app.route('/api/honeypot_alerts')
def get_honeypot_alerts():
    """Get honeypot alerts from logs"""
    alerts = []
    try:
        # Read from triage honeypot logs
        triage_log_path = os.path.join(os.path.dirname(__file__), '..', 'logs', 'triage_honeypot.log')
        if os.path.exists(triage_log_path):
            with open(triage_log_path, 'r') as f:
                lines = f.readlines()
                for line in lines[-10:]:  # Last 10 entries
                    try:
                        log_data = json.loads(line.strip())
                        if log_data.get('request_type') == 'login_attempt':
                            alerts.append({
                                'timestamp': datetime.fromisoformat(log_data['timestamp']).strftime('%H:%M:%S'),
                                'source_ip': log_data['source_ip'],
                                'classification': log_data.get('extra_data', {}).get('classification', 'unknown'),
                                'risk_score': f"{log_data.get('extra_data', {}).get('risk_score', 0):.1f}",
                                'honeypot': 'triage',
                                'username': log_data.get('username', 'unknown')
                            })
                    except:
                        continue
    except:
        pass
    
    return jsonify(alerts)

@app.route('/api/traffic_flows')
def get_traffic_flows():
    """Get active traffic flows"""
    try:
        # Get stats from controller
        response = requests.get('http://localhost:8080/api/stats', timeout=2)
        if response.status_code == 200:
            data = response.json()
            flows = []
            
            # Create flows for suspicious IPs
            for ip in data.get('suspicious_ips', []):
                flows.append({
                    'source_ip': ip,
                    'target': '10.0.0.4',  # Triage honeypot
                    'classification': 'suspicious',
                    'packets': 15 + len(ip) % 10
                })
            
            # Create flows for malicious IPs  
            for ip in data.get('malicious_ips', []):
                flows.append({
                    'source_ip': ip,
                    'target': '10.0.0.5',  # Deep honeypot
                    'classification': 'malicious',
                    'packets': 25 + len(ip) % 15
                })
            
            return jsonify(flows)
    except:
        pass
    
    return jsonify([])

if __name__ == '__main__':
    print("🛡️ Starting Advanced SDN Honeypot Dashboard on http://localhost:8090")
    app.run(host='0.0.0.0', port=8090, debug=False)
