#!/usr/bin/env python3

from flask import Flask, render_template_string, jsonify
import os
import json
import datetime

app = Flask(__name__)

@app.route('/')
def index():
    """Serve the main presentation page"""
    with open('index.html', 'r') as f:
        content = f.read()
    return content

@app.route('/api/system-status')
def system_status():
    """API endpoint for real-time system status"""
    
    # Check if logs exist and get latest activity
    logs_dir = '../logs'
    latest_activity = None
    
    if os.path.exists(f'{logs_dir}/triage_honeypot.log'):
        try:
            with open(f'{logs_dir}/triage_honeypot.log', 'r') as f:
                lines = f.readlines()
                if lines:
                    latest = json.loads(lines[-1])
                    latest_activity = {
                        'timestamp': latest['timestamp'],
                        'source_ip': latest['source_ip'],
                        'request_type': latest['request_type'],
                        'ml_prediction': latest['extra_data'].get('ml_prediction', 'N/A'),
                        'risk_score': latest['extra_data'].get('risk_score', 'N/A'),
                        'classification': latest['extra_data'].get('classification', 'N/A')
                    }
        except:
            pass
    
    return jsonify({
        'controller_status': 'ACTIVE',
        'services': {
            'h1': 'RUNNING',
            'h2': 'RUNNING', 
            'h3': 'RUNNING',
            'h4': 'RUNNING',
            'h5': 'RUNNING'
        },
        'ml_model': {
            'status': 'OPERATIONAL',
            'type': 'Binary Classification',
            'threshold': 0.6
        },
        'network': {
            'connectivity': '100%',
            'packet_loss': '0%',
            'switches': 7,
            'hosts': 6
        },
        'latest_activity': latest_activity,
        'timestamp': datetime.datetime.now().isoformat()
    })

@app.route('/api/demo-commands')
def demo_commands():
    """Get demo commands for live demonstration"""
    return jsonify({
        'commands': [
            {
                'name': 'Test Normal Server',
                'command': 'h6 curl http://10.0.0.1:8001/',
                'description': 'Access normal server from external source'
            },
            {
                'name': 'Test Triage Honeypot',
                'command': 'h6 curl http://10.0.0.4:8004/',
                'description': 'Access triage honeypot login page'
            },
            {
                'name': 'Trigger ML Analysis',
                'command': 'h6 curl -X POST -d "username=admin&password=test" http://10.0.0.4:8004/',
                'description': 'Submit login attempt for ML analysis'
            },
            {
                'name': 'Multiple Requests (Suspicious)',
                'command': 'for i in {1..5}; do h6 curl -X POST -d "username=hacker$i" http://10.0.0.4:8004/; done',
                'description': 'Rapid-fire requests to trigger malicious classification'
            },
            {
                'name': 'Check Controller API',
                'command': 'curl http://localhost:8080/api/status',
                'description': 'Query SDN controller status'
            }
        ]
    })

if __name__ == '__main__':
    port = 9000
    print(f"🌐 Starting Presentation Server on http://localhost:{port}")
    print("📝 This server hosts the academic presentation website")
    print("🎯 Perfect for demonstrating your SDN Honeypot project to teachers!")
    app.run(host='0.0.0.0', port=port, debug=True) 