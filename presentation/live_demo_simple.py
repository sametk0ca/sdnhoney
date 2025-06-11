#!/usr/bin/env python3

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import os
import json
import datetime
import requests
import subprocess
import time
import threading

app = Flask(__name__)
app.template_folder = 'templates'
app.static_folder = 'static'
app.config['SECRET_KEY'] = 'live-demo-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Terminal session storage
terminals = {}

# Demo commands and responses
demo_responses = {
    'h6 curl 10.0.0.4:8004': '''<!DOCTYPE html>
<html><head><title>Server Login - smtkoca.com</title></head>
<body>
<div class="login-container">
<h2>🍯 smtkoca.com - Server Portal</h2>
<p>Secure Server Access</p>
<form method="POST">
<input type="text" name="username" placeholder="Username" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">🔐 Login</button>
</form>
</div>
</body>
</html>''',

    'h6 curl -X POST -d "username=admin&password=admin" 10.0.0.4:8004': '''<!DOCTYPE html>
<html><head><title>Server Login - smtkoca.com</title></head>
<body>
<div class="login-container">
<div class="error" style="color: red; border: 2px solid red; padding: 10px; background: #ffe6e6;">
⚠️ SECURITY ALERT: Suspicious login attempt detected!<br><br>
<strong>Risk Analysis:</strong><br>
• Username: admin (High Risk)<br>
• Password: admin (Dictionary Attack)<br>
• ML Risk Score: 0.87 (HIGH)<br>
• Classification: MALICIOUS<br>
• Action: Request logged and monitored<br>
• Source IP: 10.0.0.6 (Flagged)<br><br>
<strong>Honeypot Status:</strong> ACTIVE ✅<br>
<strong>SDN Controller:</strong> Traffic redirected to honeypot
</div>
</div>
</body>
</html>''',

    'h6 curl -X POST -d "username=hacker&password=123" 10.0.0.4:8004': '''<!DOCTYPE html>
<html><head><title>Server Login - smtkoca.com</title></head>
<body>
<div class="login-container">
<div class="error" style="color: red; border: 2px solid red; padding: 10px; background: #ffe6e6;">
🚨 CRITICAL SECURITY ALERT 🚨<br><br>
<strong>Threat Detected:</strong><br>
• Username: hacker (CRITICAL)<br>
• Rapid fire attempt detected<br>
• ML Risk Score: 0.94 (CRITICAL)<br>
• Classification: MALICIOUS<br>
• Threat Level: HIGH<br><br>
<strong>Automated Response:</strong><br>
✅ IP 10.0.0.6 flagged as malicious<br>
✅ Traffic redirected to deep honeypot<br>
✅ Security team notified<br>
✅ Enhanced monitoring activated
</div>
</div>
</body>
</html>''',

    'h6 curl 10.0.0.5:8005': '''🍯 Deep Honeypot Environment v2.1 🍯
=====================================
Welcome to Advanced Interaction Analysis System

> System Status: ACTIVE
> Sensors: ONLINE  
> ML Engine: RUNNING
> Threat Level: MONITORING
> Advanced Honeypot: ENGAGED

🔍 ANALYSIS ACTIVE:
- Behavioral pattern recognition
- Command injection detection  
- Privilege escalation monitoring
- Data exfiltration analysis

Type 'help' for available commands
WARNING: All activities are monitored and logged''',

    'h6 curl 10.0.0.1:8001': '''<!DOCTYPE html>
<html><head><title>Normal Server 1</title></head>
<body>
<h1>✅ Normal Web Server 1</h1>
<p>Service Status: RUNNING</p>
<p>Server Time: ''' + time.strftime('%Y-%m-%d %H:%M:%S') + '''</p>
<p>Uptime: 99.9%</p>
<p>Load: Normal</p>
</body>
</html>''',

    'h6 curl 10.0.0.2:8002': '''<!DOCTYPE html>
<html><head><title>Normal Server 2</title></head>
<body>
<h1>✅ Normal Web Server 2</h1>
<p>Service Status: RUNNING</p>
<p>Server Time: ''' + time.strftime('%Y-%m-%d %H:%M:%S') + '''</p>
<p>Uptime: 99.8%</p>
<p>Load: Normal</p>
</body>
</html>''',

    'h6 curl 10.0.0.3:8003': '''<!DOCTYPE html>
<html><head><title>Normal Server 3</title></head>
<body>
<h1>✅ Normal Web Server 3</h1>
<p>Service Status: RUNNING</p>
<p>Server Time: ''' + time.strftime('%Y-%m-%d %H:%M:%S') + '''</p>
<p>Uptime: 99.7%</p>
<p>Load: Normal</p>
</body>
</html>''',

    'pingall': '''*** Ping: testing ping reachability
h1 -> h2 h3 h4 h5 h6 
h2 -> h1 h3 h4 h5 h6 
h3 -> h1 h2 h4 h5 h6 
h4 -> h1 h2 h3 h5 h6 
h5 -> h1 h2 h3 h4 h6 
h6 -> h1 h2 h3 h4 h5 
*** Results: 0% dropped (30/30 received)''',

    'h1 ping h4': '''PING 10.0.0.4 (10.0.0.4) 56(84) bytes of data.
64 bytes from 10.0.0.4: icmp_seq=1 ttl=64 time=0.156 ms
64 bytes from 10.0.0.4: icmp_seq=2 ttl=64 time=0.091 ms
64 bytes from 10.0.0.4: icmp_seq=3 ttl=64 time=0.085 ms

--- 10.0.0.4 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2045ms
rtt min/avg/max/mdev = 0.085/0.110/0.156/0.032 ms''',

    'status': '''🐳 SDN Honeypot System Status:

🎮 SDN Controller: ✅ ACTIVE
📡 REST API: ✅ RUNNING (Port 8080)
🌐 Network: ✅ CONNECTED (100% uptime)

🖥️  Services Status:
- h1 (Normal Server): ✅ PORT 8001
- h2 (Normal Server): ✅ PORT 8002
- h3 (Normal Server): ✅ PORT 8003
- h4 (Triage Honeypot): ✅ PORT 8004
- h5 (Deep Honeypot): ✅ PORT 8005

🧠 ML Model: ✅ OPERATIONAL
• Type: Binary Classification
• Threshold: 0.6 risk score
• Features: Request frequency, user agents, patterns
• Last training: 2024-12-30

📊 Recent Activity:
• Benign requests: 147
• Suspicious requests: 23
• Malicious requests: 5
• Total honeypot interactions: 28''',

    'help': '''🍯 SDN Honeypot Demo Commands:

📡 Network Testing:
  pingall                         - Test connectivity between all hosts
  h1 ping h4                      - Test specific host connectivity

🌐 Service Access:
  h6 curl 10.0.0.1:8001          - Normal server 1
  h6 curl 10.0.0.2:8002          - Normal server 2  
  h6 curl 10.0.0.3:8003          - Normal server 3
  h6 curl 10.0.0.4:8004          - Triage honeypot
  h6 curl 10.0.0.5:8005          - Deep honeypot

🚨 Malicious Traffic Demo:
  h6 curl -X POST -d "username=admin&password=admin" 10.0.0.4:8004
  h6 curl -X POST -d "username=hacker&password=123" 10.0.0.4:8004

📊 System Commands:
  status                          - System status
  help                            - This help message'''
}

@app.route('/')
def live_demo():
    """Live demo page with real terminal interface"""
    return render_template('live_terminal.html')

@app.route('/api/system-status')
def system_status():
    """Get system status"""
    return jsonify({
        'controller': {
            'status': 'ACTIVE',
            'stats': {
                'active_flows': 15,
                'packet_count': 1247,
                'byte_count': 892456
            }
        },
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
            'threshold': 0.6,
            'features': ['request_frequency', 'username_analysis', 'user_agent_analysis', 'rapid_fire_detection']
        },
        'network': {
            'connectivity': '100%',
            'packet_loss': '0%',
            'switches': 7,
            'hosts': 6,
            'topology': 'Tree (depth=3)'
        },
        'timestamp': datetime.datetime.now().isoformat()
    })

# =================== TERMINAL SOCKET HANDLERS ===================

@socketio.on('create_terminal')
def create_terminal(data):
    """Create a new terminal session"""
    try:
        session_id = request.sid
        
        terminals[session_id] = {
            'type': 'demo',
            'ready': True
        }
        
        print(f"DEBUG: Connected session {session_id} to demo terminal")
        emit('terminal_created', {'success': True})
        
        # Send welcome message
        welcome_msg = '''🍯 SDN Honeypot Live Demo Terminal (Simulation Mode)
Connected to simulated Mininet environment

✨ This is a demonstration environment with realistic responses
📚 Type 'help' to see available commands

Available demo commands:
  h6 curl 10.0.0.4:8004           # Test triage honeypot
  h6 curl 10.0.0.5:8005           # Test deep honeypot  
  h6 curl 10.0.0.1:8001           # Test normal server 1
  
  # Malicious traffic examples:
  h6 curl -X POST -d "username=admin&password=admin" 10.0.0.4:8004
  h6 curl -X POST -d "username=hacker&password=123" 10.0.0.4:8004
  
  pingall                         # Test connectivity
  status                          # System status
  help                            # Show all commands
  
mininet> '''
        emit('terminal_output', {'output': welcome_msg})
        
    except Exception as e:
        print(f"DEBUG: Error creating terminal: {e}")
        emit('terminal_created', {'success': False, 'error': str(e)})

@socketio.on('terminal_input')
def terminal_input(data):
    """Handle terminal input"""
    session_id = request.sid
    input_data = data.get('input', '').strip()
    
    print(f"DEBUG: Terminal input received from {session_id}: {repr(input_data)}")
    
    if session_id in terminals:
        try:
            handle_demo_command(session_id, input_data)
        except Exception as e:
            print(f"DEBUG: Error handling command: {e}")
            emit('terminal_error', {'error': str(e)})

@socketio.on('disconnect')
def disconnect():
    """Clean up terminal session on disconnect"""
    session_id = request.sid
    if session_id in terminals:
        del terminals[session_id]

# =================== COMMAND HANDLING ===================

def handle_demo_command(session_id, command):
    """Handle demo commands"""
    if not command:
        return
    
    try:
        # Add typing delay for realism
        time.sleep(0.5)
        
        # Find matching command
        response = None
        for cmd_pattern, cmd_response in demo_responses.items():
            if command == cmd_pattern or command.startswith(cmd_pattern):
                response = cmd_response
                break
        
        if not response:
            # Handle partial matches or similar commands
            if 'curl 10.0.0' in command and '8004' in command:
                if 'POST' in command:
                    if 'admin' in command:
                        response = demo_responses['h6 curl -X POST -d "username=admin&password=admin" 10.0.0.4:8004']
                    else:
                        response = demo_responses['h6 curl -X POST -d "username=hacker&password=123" 10.0.0.4:8004']
                else:
                    response = demo_responses['h6 curl 10.0.0.4:8004']
            elif 'curl 10.0.0' in command:
                # Default response for other servers
                response = "curl: (7) Failed to connect to server - connection refused\n"
            else:
                response = f"Command '{command}' not recognized. Type 'help' for available commands.\n"
        
        # Send output with realistic timing
        emit('terminal_output', {'output': response + '\n'}, room=session_id)
        
        # Simulate ML processing for malicious commands
        if 'POST' in command and ('admin' in command or 'hacker' in command):
            time.sleep(1)
            ml_output = '''
📊 ML Model Analysis:
⚙️  Processing request features...
🧠 Binary classification result: MALICIOUS (confidence: 94.2%)
📈 Risk score: 0.87/1.0
🚨 Automated honeypot redirection: ACTIVE
📝 Incident logged to security database

'''
            emit('terminal_output', {'output': ml_output}, room=session_id)
        
        # Send prompt
        emit('terminal_output', {'output': 'mininet> '}, room=session_id)
        
    except Exception as e:
        error_msg = f"Error: {str(e)}\nmininet> "
        emit('terminal_output', {'output': error_msg}, room=session_id)

if __name__ == '__main__':
    port = 9001
    print("🍯 Starting SDN Honeypot Live Demo Terminal (Simple Mode)")
    print(f"📍 URL: http://localhost:{port}")
    print("📋 Features:")
    print("   • Simulated Mininet Environment")
    print("   • Realistic Command Responses")
    print("   • ML Detection Demonstrations")
    print("   • Interactive Security Scenarios")
    print("🎯 Perfect for live demonstrations without Docker!")
    
    socketio.run(app, host='0.0.0.0', port=port, debug=True) 