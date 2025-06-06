#!/usr/bin/env python3

from flask import Flask, render_template, jsonify
import requests
import json
import os
from datetime import datetime

app = Flask(__name__)

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
    """Get system statistics"""
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
    """Get host status information"""
    return jsonify({
        'h1': 'online',
        'h2': 'online', 
        'h3': 'online',
        'h4': 'online',
        'h5': 'online',
        'h6': 'online'
    })

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
    """Get active network flows"""
    return jsonify([
        {
            'src': '10.0.0.6',
            'dst': '10.0.0.1',
            'port': 80,
            'classification': 'normal',
            'packet_count': 45
        },
        {
            'src': '10.0.0.6', 
            'dst': '10.0.0.4',
            'port': 80,
            'classification': 'suspicious',
            'packet_count': 23
        }
    ])

if __name__ == '__main__':
    print("🛡️ Starting Advanced SDN Honeypot Dashboard on http://localhost:8090")
    app.run(host='0.0.0.0', port=8090, debug=False)
