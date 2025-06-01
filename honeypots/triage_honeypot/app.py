#!/usr/bin/env python3

from flask import Flask, request, render_template_string, redirect, url_for, session, jsonify
import sys
import os
import json
import datetime
import requests
from collections import defaultdict

app = Flask(__name__)
app.secret_key = 'triage_honeypot_secret_key_999'

# Logging directory
LOG_DIR = '/home/samet/Desktop/sdnhoney/logs'
os.makedirs(LOG_DIR, exist_ok=True)

# Track failed attempts per IP
failed_attempts = defaultdict(int)
request_times = defaultdict(list)

def log_request(request_type, source_ip, success=False, username=None, extra_data=None):
    """Enhanced logging for honeypot analysis"""
    log_entry = {
        'timestamp': datetime.datetime.now().isoformat(),
        'server': 'triage_honeypot',
        'source_ip': source_ip,
        'request_type': request_type,
        'success': success,
        'username': username,
        'user_agent': request.headers.get('User-Agent', ''),
        'method': request.method,
        'failed_attempts_count': failed_attempts[source_ip],
        'request_headers': dict(request.headers),
        'form_data': dict(request.form) if request.form else None,
        'extra_data': extra_data
    }
    
    log_file = os.path.join(LOG_DIR, 'triage_honeypot.log')
    with open(log_file, 'a') as f:
        f.write(json.dumps(log_entry) + '\n')

def analyze_traffic(source_ip, username=None):
    """Simulate ML model to classify traffic as normal/malicious"""
    current_time = datetime.datetime.now()
    
    # Track request timing
    request_times[source_ip].append(current_time)
    
    # Clean old requests (older than 1 hour)
    request_times[source_ip] = [
        t for t in request_times[source_ip] 
        if (current_time - t).seconds < 3600
    ]
    
    # Simple rule-based "ML" classification
    risk_score = 0
    
    # High frequency requests
    if len(request_times[source_ip]) > 10:  # More than 10 requests in an hour
        risk_score += 30
    
    # Multiple failed attempts
    if failed_attempts[source_ip] > 3:
        risk_score += 40
    
    # Common attack usernames
    attack_usernames = ['admin', 'root', 'administrator', 'user', 'test', 'guest']
    if username and username.lower() in attack_usernames:
        risk_score += 20
    
    # Suspicious user agents
    user_agent = request.headers.get('User-Agent', '').lower()
    if any(bot in user_agent for bot in ['bot', 'crawler', 'scanner', 'curl', 'wget']):
        risk_score += 25
    
    # Classification
    if risk_score >= 60:
        classification = 'malicious'
    elif risk_score >= 30:
        classification = 'suspicious'
    else:
        classification = 'normal'
    
    return classification, risk_score

def send_to_controller(classification, source_ip, risk_score):
    """Send classification result to SDN controller"""
    try:
        controller_url = 'http://127.0.0.1:8080/honeypot/classification'
        data = {
            'source_ip': source_ip,
            'classification': classification,
            'risk_score': risk_score,
            'honeypot_type': 'triage',
            'timestamp': datetime.datetime.now().isoformat()
        }
        requests.post(controller_url, json=data, timeout=2)
    except:
        pass  # Controller might not be running yet

# HTML Templates (same as normal servers to appear legitimate)
LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Server Login - smtkoca.com</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 50px; background-color: #f0f0f0; }
        .login-container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="password"] { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        button { background-color: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; width: 100%; }
        button:hover { background-color: #0056b3; }
        .error { color: red; margin-top: 10px; }
        .header { text-align: center; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="header">
            <h2>smtkoca.com - Server Access</h2>
            <p>Server Portal</p>
        </div>
        <form method="POST">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
            {% if error %}
                <div class="error">{{ error }}</div>
            {% endif %}
        </form>
    </div>
</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def login():
    client_ip = request.remote_addr
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Always fail authentication in triage honeypot
        failed_attempts[client_ip] += 1
        
        # Analyze traffic patterns
        classification, risk_score = analyze_traffic(client_ip, username)
        
        # Log everything
        log_request('login_attempt', client_ip, username=username, 
                   extra_data={'classification': classification, 'risk_score': risk_score})
        
        # Send results to controller
        send_to_controller(classification, client_ip, risk_score)
        
        # Always show invalid credentials error
        return render_template_string(LOGIN_TEMPLATE, 
                                    error="Invalid credentials. Please try again.")
    
    # Log page visits
    classification, risk_score = analyze_traffic(client_ip)
    log_request('page_visit', client_ip, 
               extra_data={'classification': classification, 'risk_score': risk_score})
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/admin')
def admin():
    """Admin endpoint that should never be reached"""
    client_ip = request.remote_addr
    log_request('admin_attempt', client_ip, extra_data={'note': 'Direct admin access attempt'})
    return redirect(url_for('login'))

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'server': 'triage_honeypot'})

@app.route('/api/stats')
def stats():
    """API endpoint to get honeypot statistics"""
    return jsonify({
        'failed_attempts_by_ip': dict(failed_attempts),
        'total_attempts': sum(failed_attempts.values()),
        'unique_ips': len(failed_attempts)
    })

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8004
    print(f"Starting Triage Honeypot on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False) 