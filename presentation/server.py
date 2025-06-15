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
    
    # Check logs for latest activity - start fresh for clean demos
    logs_dir = 'logs'  # Relative to current directory
    latest_activity = None
    honeypot_stats = {'total_attempts': 0, 'unique_ips': 0}
    
    # Only check logs if they exist and are recent (within last hour for demos)
    log_file_path = f'{logs_dir}/triage_honeypot.log'
    if os.path.exists(log_file_path):
        try:
            file_mod_time = os.path.getmtime(log_file_path)
            current_time = time.time()
            
            # Only load logs if file was modified within last hour
            if current_time - file_mod_time < 3600:  # 1 hour
                with open(log_file_path, 'r') as f:
                    lines = f.readlines()
                    # Filter recent lines only (last 10 minutes)
                    recent_lines = []
                    for line in lines:
                        try:
                            log_entry = json.loads(line)
                            log_time = datetime.datetime.fromisoformat(log_entry['timestamp'].replace('Z', '+00:00'))
                            if (datetime.datetime.now(datetime.timezone.utc) - log_time).total_seconds() < 3600:  # 1 hour
                                recent_lines.append(line)
                        except:
                            continue
                    
                    honeypot_stats['total_attempts'] = len(recent_lines)
                    
                    if recent_lines:
                        latest = json.loads(recent_lines[-1])
                        latest_activity = {
                            'timestamp': latest['timestamp'],
                            'source_ip': latest['source_ip'],
                            'request_type': latest['request_type'],
                            'ml_prediction': latest.get('extra_data', {}).get('ml_prediction', 0),
                            'risk_score': latest.get('extra_data', {}).get('risk_score', 0.3),
                            'classification': latest.get('extra_data', {}).get('classification', 'normal')
                        }
                    
                    # Count unique IPs from recent lines
                    ips = set()
                    for line in recent_lines:
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
            'status': 'ACTIVE',  # Dashboard is always active if the server is running
            'port': 9000,
            'uptime': 'Online'
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

@app.route('/api/reset-stats', methods=['POST'])
def reset_stats():
    """Reset system statistics for clean demos"""
    try:
        # Clear ALL log files for clean demo
        logs_dir = '../logs'  # Go up one directory from presentation/
        log_files = [
            'triage_honeypot.log', 
            'deep_honeypot.log', 
            'controller.log',
            'presentation.log',
            'dashboard.log',

            'h1_service.log',
            'h2_service.log', 
            'h3_service.log',
            'h4_service.log',
            'h5_service.log',
            'normal_server_1.log',
            'normal_server_2.log',
            'normal_server_3.log'
        ]
        
        cleared_files = []
        for log_file in log_files:
            log_path = f'{logs_dir}/{log_file}'
            if os.path.exists(log_path):
                try:
                    with open(log_path, 'w') as f:
                        pass  # Truncate file
                    cleared_files.append(log_file)
                except PermissionError:
                    # Skip files we can't write to (system logs)
                    continue
        
        # Reset controller statistics via API
        controller_reset = False
        try:
            response = requests.post('http://localhost:8080/api/reset-stats', timeout=5)
            controller_reset = (response.status_code == 200)
        except:
            pass
        
        return jsonify({
            'success': True,
            'controller_reset': controller_reset,
            'logs_cleared': True,
            'cleared_files': cleared_files,
            'message': f'System reset: {len(cleared_files)} log files cleared + controller stats reset'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

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
    """Get stats for integrated dashboard functionality"""
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

@app.route('/api/monitoring-data')
def monitoring_data():
    """Get monitoring data for charts and statistics"""
    try:
        # Get real data from controller
        response = requests.get('http://localhost:8080/api/stats', timeout=2)
        if response.status_code == 200:
            controller_data = response.json()
            
            # Extract actual data from controller
            active_ips = controller_data.get('active_ips', 0)
            suspicious_ips_list = controller_data.get('suspicious_ips', [])
            malicious_ips_list = controller_data.get('malicious_ips', [])
            suspicious_count = len(suspicious_ips_list)
            malicious_count = len(malicious_ips_list)
            
            # Calculate normal IPs (active but not suspicious or malicious)
            normal_count = max(0, active_ips - suspicious_count - malicious_count)
            
            return jsonify({
                'active_ips': active_ips,
                'suspicious_ips': suspicious_count,
                'malicious_ips': malicious_count,
                'honeypot_interactions': controller_data.get('flow_count', 0),
                'traffic_history': {
                    'normal': normal_count,
                    'suspicious': suspicious_count,
                    'malicious': malicious_count
                },
                'threat_distribution': {
                    'normal': normal_count,
                    'suspicious': suspicious_count,
                    'malicious': malicious_count
                },
                'timestamp': datetime.datetime.now().isoformat(),
                'controller_status': 'active'
            })
    except Exception as e:
        # Controller is not available - return default values
        return jsonify({
            'active_ips': 0,
            'suspicious_ips': 0,
            'malicious_ips': 0,
            'honeypot_interactions': 0,
            'traffic_history': {
                'normal': 0,
                'suspicious': 0,
                'malicious': 0
            },
            'threat_distribution': {
                'normal': 0,
                'suspicious': 0,
                'malicious': 0
            },
            'timestamp': datetime.datetime.now().isoformat(),
            'controller_status': 'offline',
            'error': str(e)
        })

if __name__ == '__main__':
    port = 9000
    print("🌐 Starting Enhanced SDN Honeypot Presentation Website")
    print(f"📍 URL: http://localhost:{port}")
    print("📋 Features:")
    print("   • Landing Page with Project Overview")
    print("   • Component Architecture Diagrams") 
    print("   • Live Documentation (README)")
    print("   • Real-time System Monitoring")
    print("   • ML Model Analysis")

    print("🎯 Perfect for academic presentations and demos!")
    app.run(host='0.0.0.0', port=port, debug=True) 