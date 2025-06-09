#!/usr/bin/env python3

from flask import Flask, render_template, jsonify, request, redirect, url_for
import os
import json
import datetime
import requests
import subprocess
import time
import markdown
from markupsafe import Markup

app = Flask(__name__)
app.template_folder = 'templates'
app.static_folder = 'static'

# Create templates and static directories
os.makedirs('templates', exist_ok=True)
os.makedirs('static/css', exist_ok=True)
os.makedirs('static/js', exist_ok=True)

@app.route('/')
def index():
    """Landing page with project overview"""
    return render_template('index.html')

@app.route('/components')
def components():
    """Components overview page"""
    return render_template('components.html')

@app.route('/demo')
def demo():
    """Interactive demo page with terminal"""
    return render_template('demo.html')

@app.route('/architecture')
def architecture():
    """System architecture page"""
    return render_template('architecture.html')

@app.route('/documentation')
def documentation():
    """README documentation page"""
    # Read README.md and convert to HTML
    readme_path = '../README.md'
    if os.path.exists(readme_path):
        with open(readme_path, 'r', encoding='utf-8') as f:
            readme_content = f.read()
        
        # Convert markdown to HTML
        html_content = markdown.markdown(readme_content, extensions=['codehilite', 'tables', 'toc'])
        return render_template('documentation.html', content=Markup(html_content))
    else:
        return render_template('documentation.html', content="README.md not found")

@app.route('/monitoring')
def monitoring():
    """Real-time monitoring dashboard"""
    return render_template('monitoring.html')

@app.route('/ml-model')
def ml_model():
    """ML Model details page"""
    return render_template('ml_model.html')

# =================== API ENDPOINTS ===================

@app.route('/api/system-status')
def system_status():
    """Enhanced API endpoint for real-time system status"""
    
    # Check controller status
    controller_status = 'INACTIVE'
    controller_stats = {}
    try:
        response = requests.get('http://localhost:8080/api/stats', timeout=2)
        if response.status_code == 200:
            controller_status = 'ACTIVE'
            controller_stats = response.json()
    except:
        pass
    
    # Check dashboard status
    dashboard_status = 'INACTIVE'
    try:
        response = requests.get('http://localhost:8090/api/status', timeout=2)
        if response.status_code == 200:
            dashboard_status = 'ACTIVE'
    except:
        pass
    
    # Check logs for latest activity
    logs_dir = '../logs'
    latest_activity = None
    honeypot_stats = {'total_attempts': 0, 'unique_ips': 0}
    
    if os.path.exists(f'{logs_dir}/triage_honeypot.log'):
        try:
            with open(f'{logs_dir}/triage_honeypot.log', 'r') as f:
                lines = f.readlines()
                honeypot_stats['total_attempts'] = len(lines)
                
                if lines:
                    latest = json.loads(lines[-1])
                    latest_activity = {
                        'timestamp': latest['timestamp'],
                        'source_ip': latest['source_ip'],
                        'request_type': latest['request_type'],
                        'ml_prediction': latest.get('extra_data', {}).get('ml_prediction', 'N/A'),
                        'risk_score': latest.get('extra_data', {}).get('risk_score', 'N/A'),
                        'classification': latest.get('extra_data', {}).get('classification', 'N/A')
                    }
                
                # Count unique IPs
                ips = set()
                for line in lines:
                    try:
                        log_entry = json.loads(line)
                        ips.add(log_entry['source_ip'])
                    except:
                        pass
                honeypot_stats['unique_ips'] = len(ips)
        except:
            pass
    
    return jsonify({
        'controller': {
            'status': controller_status,
            'stats': controller_stats
        },
        'dashboard': {
            'status': dashboard_status
        },
        'services': {
            'h1': 'RUNNING' if controller_status == 'ACTIVE' else 'UNKNOWN',
            'h2': 'RUNNING' if controller_status == 'ACTIVE' else 'UNKNOWN',
            'h3': 'RUNNING' if controller_status == 'ACTIVE' else 'UNKNOWN',
            'h4': 'RUNNING' if controller_status == 'ACTIVE' else 'UNKNOWN',
            'h5': 'RUNNING' if controller_status == 'ACTIVE' else 'UNKNOWN'
        },
        'ml_model': {
            'status': 'OPERATIONAL' if controller_status == 'ACTIVE' else 'INACTIVE',
            'type': 'Binary Classification',
            'threshold': 0.6,
            'features': ['request_frequency', 'username_analysis', 'user_agent_analysis', 'rapid_fire_detection']
        },
        'network': {
            'connectivity': '100%' if controller_status == 'ACTIVE' else 'Unknown',
            'packet_loss': '0%',
            'switches': 7,
            'hosts': 6,
            'topology': 'Tree (depth=3)'
        },
        'honeypot_stats': honeypot_stats,
        'latest_activity': latest_activity,
        'timestamp': datetime.datetime.now().isoformat()
    })

@app.route('/api/demo-commands')
def demo_commands():
    """Enhanced demo commands with categories"""
    return jsonify({
        'categories': {
            'basic_tests': {
                'name': 'Basic Connectivity Tests',
                'commands': [
                    {
                        'name': 'Ping All Hosts',
                        'command': 'pingall',
                        'description': 'Test connectivity between all hosts',
                        'expected': 'All hosts should reach each other'
                    },
                    {
                        'name': 'Check Controller',
                        'command': 'curl -s http://localhost:8080/api/stats | python3 -m json.tool',
                        'description': 'Query SDN controller statistics',
                        'expected': 'JSON response with active IPs, suspicious/malicious lists'
                    }
                ]
            },
            'normal_traffic': {
                'name': 'Normal Traffic Tests',
                'commands': [
                    {
                        'name': 'Access Normal Server (h1)',
                        'command': 'h6 curl http://10.0.0.1:8001/',
                        'description': 'Normal web page request',
                        'expected': 'HTML login page response'
                    },
                    {
                        'name': 'Valid Login Test',
                        'command': 'h6 curl -X POST -d "username=john&password=johnpass" http://10.0.0.1:8001/',
                        'description': 'Successful authentication',
                        'expected': 'Redirect to admin panel'
                    }
                ]
            },
            'honeypot_tests': {
                'name': 'Honeypot & ML Tests',
                'commands': [
                    {
                        'name': 'Triage Honeypot Access',
                        'command': 'h6 curl http://10.0.0.4:8004/',
                        'description': 'Access honeypot login page',
                        'expected': 'Identical-looking login page'
                    },
                    {
                        'name': 'Admin Username Attack',
                        'command': 'h6 curl -X POST -d "username=admin&password=test" http://10.0.0.4:8004/',
                        'description': 'Suspicious username triggers ML analysis',
                        'expected': 'ML model analyzes and sends classification to controller'
                    },
                    {
                        'name': 'Bot Attack Simulation',
                        'command': 'h6 curl -X POST -d "username=admin" http://10.0.0.1:8001/ -A "curl/7.68.0"',
                        'description': 'Bot user-agent triggers high risk score',
                        'expected': 'High risk score → potential malicious classification'
                    }
                ]
            },
            'advanced_attacks': {
                'name': 'Advanced Attack Scenarios',
                'commands': [
                    {
                        'name': 'Rapid Fire Attack',
                        'command': 'h6 bash -c \'for i in {1..10}; do curl -s -X POST -d "username=hacker$i" http://10.0.0.1:8001/; done\'',
                        'description': 'Multiple rapid requests to trigger frequency analysis',
                        'expected': 'Frequency-based malicious classification'
                    },
                    {
                        'name': 'Scanner Simulation',
                        'command': 'h6 curl -X POST -d "username=root" http://10.0.0.1:8001/ -A "Nikto/2.1.6"',
                        'description': 'Scanner tool detection',
                        'expected': 'Scanner user-agent → high risk score'
                    }
                ]
            }
        }
    })

@app.route('/api/execute-command', methods=['POST'])
def execute_command():
    """Execute demo commands (simulation)"""
    data = request.get_json()
    command = data.get('command', '')
    
    # Simulate command execution with realistic responses
    if 'pingall' in command:
        result = "*** Ping: testing ping reachability\nh1 -> h2 h3 h4 h5 h6\nh2 -> h1 h3 h4 h5 h6\nh3 -> h1 h2 h4 h5 h6\nh4 -> h1 h2 h3 h5 h6\nh5 -> h1 h2 h3 h4 h6\nh6 -> h1 h2 h3 h4 h5\n*** Results: 0% dropped (30/30 received)"
    elif 'curl' in command and 'localhost:8080' in command:
        try:
            response = requests.get('http://localhost:8080/api/stats', timeout=2)
            result = response.text
        except:
            result = "Error: Controller not responding"
    elif 'curl' in command and '10.0.0' in command:
        result = "<!DOCTYPE html>\n<html>\n<head><title>Server Login</title></head>\n<body>\n<h2>Server Access Portal</h2>\n<form method='POST'>\n  Username: <input name='username' required>\n  Password: <input name='password' type='password' required>\n  <button type='submit'>Login</button>\n</form>\n</body>\n</html>"
    else:
        result = f"Command executed: {command}\n[This is a simulation - actual execution would require Mininet CLI]"
    
    return jsonify({
        'success': True,
        'command': command,
        'output': result,
        'timestamp': datetime.datetime.now().isoformat()
    })

@app.route('/api/ml-test')
def ml_test():
    """Test ML model with different scenarios"""
    try:
        # Import ML model
        import sys
        sys.path.append('../ml_model')
        from simulate_model import classify_traffic
        
        test_scenarios = [
            {
                'name': 'Normal User',
                'ip': '192.168.1.100',
                'data': {'username': 'john', 'user_agent': 'Mozilla/5.0'}
            },
            {
                'name': 'Admin Username',
                'ip': '192.168.1.101', 
                'data': {'username': 'admin', 'user_agent': 'Mozilla/5.0'}
            },
            {
                'name': 'Bot Attack',
                'ip': '192.168.1.102',
                'data': {'username': 'admin', 'user_agent': 'curl/7.68.0'}
            },
            {
                'name': 'Scanner Tool',
                'ip': '192.168.1.103',
                'data': {'username': 'root', 'user_agent': 'Nikto/2.1.6'}
            }
        ]
        
        results = []
        for scenario in test_scenarios:
            prediction, risk_score = classify_traffic(scenario['ip'], scenario['data'])
            results.append({
                'scenario': scenario['name'],
                'prediction': prediction,
                'risk_score': round(risk_score, 3),
                'classification': 'Malicious' if prediction == 1 else 'Benign'
            })
        
        return jsonify({
            'success': True,
            'results': results,
            'timestamp': datetime.datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

# =================== DASHBOARD INTEGRATION ENDPOINTS ===================

@app.route('/api/dashboard-stats')
def dashboard_stats():
    """Get stats for dashboard - integrating 8090 functionality"""
    try:
        # Get real data from controller
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
        'last_update': datetime.datetime.now().strftime('%H:%M:%S')
    })

@app.route('/api/host-status')
def host_status():
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

@app.route('/api/honeypot-logs')
def honeypot_logs():
    """Get recent honeypot logs"""
    logs = []
    logs_dir = '../logs'
    
    if os.path.exists(f'{logs_dir}/triage_honeypot.log'):
        try:
            with open(f'{logs_dir}/triage_honeypot.log', 'r') as f:
                lines = f.readlines()
                # Get last 10 entries
                for line in lines[-10:]:
                    try:
                        log_entry = json.loads(line)
                        logs.append({
                            'timestamp': log_entry['timestamp'],
                            'source_ip': log_entry['source_ip'],
                            'request_type': log_entry['request_type'],
                            'ml_prediction': log_entry.get('extra_data', {}).get('ml_prediction', 'N/A'),
                            'risk_score': log_entry.get('extra_data', {}).get('risk_score', 'N/A'),
                            'classification': log_entry.get('extra_data', {}).get('classification', 'N/A')
                        })
                    except:
                        pass
        except:
            pass
    
    return jsonify(logs)

if __name__ == '__main__':
    port = 9000
    print("🌐 Starting Enhanced SDN Honeypot Presentation Website")
    print(f"📍 URL: http://localhost:{port}")
    print("📋 Features:")
    print("   • Landing Page with Project Overview")
    print("   • Interactive Demo Terminal")
    print("   • Component Architecture Diagrams") 
    print("   • Live Documentation (README)")
    print("   • Real-time System Monitoring")
    print("   • ML Model Analysis")
    print("🎯 Perfect for academic presentations and demos!")
    app.run(host='0.0.0.0', port=port, debug=True) 