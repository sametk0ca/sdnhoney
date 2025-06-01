#!/usr/bin/env python3

from flask import Flask, render_template, jsonify, request
import requests
import json
import time
import threading
from datetime import datetime
import os
import glob

app = Flask(__name__)

# Configuration
CONTROLLER_API = "http://localhost:8080"
LOG_DIR = "../logs"

# Global stats storage
network_stats = {
    'active_ips': 0,
    'suspicious_ips': [],
    'malicious_ips': [],
    'flow_count': 0,
    'last_update': None
}

traffic_history = []
honeypot_alerts = []

# Network topology definition
TOPOLOGY = {
    'switches': [
        {'id': 's1', 'name': 'Root Switch', 'level': 0, 'x': 400, 'y': 50},
        {'id': 's2', 'name': 'Switch 2', 'level': 1, 'x': 200, 'y': 150},
        {'id': 's3', 'name': 'Switch 3', 'level': 1, 'x': 600, 'y': 150},
        {'id': 's4', 'name': 'Switch 4', 'level': 2, 'x': 100, 'y': 250},
        {'id': 's5', 'name': 'Switch 5', 'level': 2, 'x': 300, 'y': 250},
        {'id': 's6', 'name': 'Switch 6', 'level': 2, 'x': 500, 'y': 250},
        {'id': 's7', 'name': 'Switch 7', 'level': 2, 'x': 700, 'y': 250},
    ],
    'hosts': [
        {'id': 'h1', 'name': 'Normal Server 1', 'ip': '10.0.0.1', 'port': 8001, 'type': 'normal', 'switch': 's4', 'x': 50, 'y': 350},
        {'id': 'h2', 'name': 'Normal Server 2', 'ip': '10.0.0.2', 'port': 8002, 'type': 'normal', 'switch': 's5', 'x': 250, 'y': 350},
        {'id': 'h3', 'name': 'Normal Server 3', 'ip': '10.0.0.3', 'port': 8003, 'type': 'normal', 'switch': 's6', 'x': 450, 'y': 350},
        {'id': 'h4', 'name': 'Triage Honeypot', 'ip': '10.0.0.4', 'port': 8004, 'type': 'triage_honeypot', 'switch': 's7', 'x': 650, 'y': 350},
        {'id': 'h5', 'name': 'Deep Honeypot', 'ip': '10.0.0.5', 'port': 8005, 'type': 'deep_honeypot', 'switch': 's7', 'x': 750, 'y': 350},
        {'id': 'h6', 'name': 'Client', 'ip': '10.0.0.6', 'port': None, 'type': 'client', 'switch': 's4', 'x': 150, 'y': 350},
    ],
    'links': [
        {'source': 's1', 'target': 's2', 'type': 'switch'},
        {'source': 's1', 'target': 's3', 'type': 'switch'},
        {'source': 's2', 'target': 's4', 'type': 'switch'},
        {'source': 's2', 'target': 's5', 'type': 'switch'},
        {'source': 's3', 'target': 's6', 'type': 'switch'},
        {'source': 's3', 'target': 's7', 'type': 'switch'},
        {'source': 'h1', 'target': 's4', 'type': 'host'},
        {'source': 'h2', 'target': 's5', 'type': 'host'},
        {'source': 'h3', 'target': 's6', 'type': 'host'},
        {'source': 'h4', 'target': 's7', 'type': 'host'},
        {'source': 'h5', 'target': 's7', 'type': 'host'},
        {'source': 'h6', 'target': 's4', 'type': 'host'},
    ]
}

def fetch_controller_stats():
    """Fetch stats from the Ryu controller"""
    try:
        response = requests.get(f"{CONTROLLER_API}/honeypot/stats", timeout=2)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        print(f"Error fetching controller stats: {e}")
    return None

def fetch_honeypot_logs():
    """Fetch recent honeypot logs"""
    alerts = []
    try:
        log_files = glob.glob(f"{LOG_DIR}/*.json")
        for log_file in log_files[-5:]:  # Last 5 log files
            with open(log_file, 'r') as f:
                for line in f.readlines()[-10:]:  # Last 10 lines
                    try:
                        log_entry = json.loads(line.strip())
                        if 'classification' in log_entry or 'risk_score' in log_entry:
                            alerts.append(log_entry)
                    except:
                        continue
    except Exception as e:
        print(f"Error reading logs: {e}")
    return alerts[-20:]  # Last 20 alerts

def update_stats():
    """Background thread to update statistics"""
    global network_stats, traffic_history, honeypot_alerts
    
    while True:
        try:
            # Fetch controller stats
            stats = fetch_controller_stats()
            if stats:
                network_stats.update(stats)
                network_stats['last_update'] = datetime.now().strftime('%H:%M:%S')
                
                # Add to traffic history
                traffic_history.append({
                    'timestamp': datetime.now().strftime('%H:%M:%S'),
                    'active_ips': stats.get('active_ips', 0),
                    'suspicious_ips': len(stats.get('suspicious_ips', [])),
                    'malicious_ips': len(stats.get('malicious_ips', []))
                })
                
                # Keep only last 50 entries
                if len(traffic_history) > 50:
                    traffic_history = traffic_history[-50:]
            
            # Fetch honeypot alerts
            honeypot_alerts = fetch_honeypot_logs()
            
        except Exception as e:
            print(f"Stats update error: {e}")
        
        time.sleep(5)  # Update every 5 seconds

# Start background stats updater
stats_thread = threading.Thread(target=update_stats, daemon=True)
stats_thread.start()

@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/topology')
def api_topology():
    """Get network topology data"""
    return jsonify(TOPOLOGY)

@app.route('/api/stats')
def api_stats():
    """Get current network statistics"""
    return jsonify(network_stats)

@app.route('/api/traffic_history')
def api_traffic_history():
    """Get traffic history for charts"""
    return jsonify(traffic_history)

@app.route('/api/honeypot_alerts')
def api_honeypot_alerts():
    """Get recent honeypot alerts"""
    return jsonify(honeypot_alerts)

@app.route('/api/host_status')
def api_host_status():
    """Check status of all hosts"""
    host_status = {}
    
    for host in TOPOLOGY['hosts']:
        if host['port']:
            try:
                response = requests.get(f"http://{host['ip']}:{host['port']}/", timeout=1)
                host_status[host['id']] = 'online' if response.status_code == 200 else 'error'
            except:
                host_status[host['id']] = 'offline'
        else:
            host_status[host['id']] = 'client'
    
    return jsonify(host_status)

@app.route('/api/traffic_flows')
def api_traffic_flows():
    """Get current traffic flows"""
    # This would integrate with controller to get real flow data
    # For now, simulate based on current stats
    flows = []
    
    if network_stats.get('suspicious_ips'):
        for ip in network_stats['suspicious_ips']:
            flows.append({
                'source_ip': ip,
                'target': 'h4',  # Triage honeypot
                'classification': 'suspicious',
                'packets': 'unknown'
            })
    
    if network_stats.get('malicious_ips'):
        for ip in network_stats['malicious_ips']:
            flows.append({
                'source_ip': ip,
                'target': 'h5',  # Deep honeypot
                'classification': 'malicious',
                'packets': 'unknown'
            })
    
    return jsonify(flows)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000) 