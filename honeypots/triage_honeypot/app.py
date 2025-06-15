#!/usr/bin/env python3

from flask import Flask, request, render_template_string, redirect, url_for, session, jsonify
import sys
import os
import json
import datetime
import requests
from collections import defaultdict
import logging

# Import the simplified ML model
sys.path.append(os.path.join(os.path.dirname(__file__), '../../ml_model'))
from simulate_model import classify_traffic

app = Flask(__name__)
app.secret_key = 'triage_honeypot_secret_key_999'

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/home/samet/Desktop/sdnhoney/logs/h4_debug.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Logging directory
LOG_DIR = os.path.join(os.path.dirname(__file__), '../../logs')
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

def analyze_traffic_with_ml(source_ip, username=None):
    """
    Use simplified ML model to classify traffic
    Returns: classification, risk_score, ml_prediction (1 or 0)
    """
    # Prepare request data for ML model
    request_data = {
        'username': username or '',
        'user_agent': request.headers.get('User-Agent', ''),
        'failed_attempts': failed_attempts[source_ip]
    }
    
    # Get ML prediction (1 = malicious, 0 = benign)
    ml_prediction, risk_score = classify_traffic(source_ip, request_data)
    
    # Convert to traditional classification for backward compatibility
    if ml_prediction == 1:
        classification = 'malicious'
    elif risk_score > 0.3:  # Middle ground
        classification = 'suspicious'  
    else:
        classification = 'normal'
    
    return classification, risk_score, ml_prediction

def send_to_controller(classification, source_ip, risk_score, ml_prediction=None):
    """Send classification result to SDN controller"""
    logger.info(f"🔄 FUNCTION CALLED: send_to_controller({classification}, {source_ip}, {risk_score}, {ml_prediction})")
    
    # Simple localhost-focused approach
    controller_ips = [
        '127.0.0.1',       # Primary - localhost controller
        '192.168.1.100',   # Host system IP fallback
        '10.0.0.1',        # Default gateway fallback
    ]
    
    for host_ip in controller_ips:
        try:
            controller_url = f'http://{host_ip}:8080/honeypot/classification'
            data = {
                'source_ip': source_ip,
                'classification': classification,
                'risk_score': risk_score * 100,  # Convert to 0-100 scale
                'honeypot_type': 'triage',
                'ml_prediction': ml_prediction,  # Include binary ML prediction
                'timestamp': datetime.datetime.now().isoformat()
            }
            
            logger.debug(f"[DEBUG] Attempting to send to controller: {controller_url}")
            logger.debug(f"[DEBUG] Data: {data}")
            
            response = requests.post(controller_url, json=data, timeout=1)
            logger.debug(f"[DEBUG] Response status: {response.status_code}")
            logger.debug(f"[DEBUG] Response text: {response.text}")
            logger.info(f"✅ SUCCESS: Sent to controller via {host_ip} - IP={source_ip}, Class={classification}, ML={ml_prediction}, Risk={risk_score:.3f}")
            return response.status_code == 200
        except Exception as e:
            logger.debug(f"[DEBUG] Failed to reach controller at {host_ip}: {e}")
            continue
    
    logger.error(f"[ERROR] Could not reach controller at any IP: {controller_ips}")
    return False

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
    logger.info(f"📥 REQUEST RECEIVED: {request.method} from {client_ip}")
    
    if request.method == 'POST':
        logger.info("📝 Processing POST request...")
        username = request.form.get('username')
        password = request.form.get('password')
        logger.info(f"👤 Login attempt: {username}/{password}")
        
        # Always fail authentication in triage honeypot
        failed_attempts[client_ip] += 1
        logger.info(f"📊 Failed attempts for {client_ip}: {failed_attempts[client_ip]}")
        
        # Analyze traffic patterns using ML model
        logger.info("🤖 Starting ML analysis...")
        classification, risk_score, ml_prediction = analyze_traffic_with_ml(client_ip, username)
        logger.info(f"✅ ML analysis complete: {classification}, {risk_score}, {ml_prediction}")
        
        # Log everything with ML results
        logger.info("📋 Logging request...")
        log_request('login_attempt', client_ip, username=username, 
                   extra_data={
                       'classification': classification, 
                       'risk_score': risk_score,
                       'ml_prediction': ml_prediction,
                       'password_length': len(password) if password else 0
                   })
        logger.info("✅ Logging complete")
        
        # Send results to controller
        logger.info("🔄 About to call send_to_controller...")
        send_to_controller(classification, client_ip, risk_score, ml_prediction)
        logger.info("✅ send_to_controller call complete")
        
        # Always show invalid credentials error
        return render_template_string(LOGIN_TEMPLATE, 
                                    error="Invalid credentials. Please try again.")
    
    # Log page visits with ML analysis
    classification, risk_score, ml_prediction = analyze_traffic_with_ml(client_ip)
    log_request('page_visit', client_ip, 
               extra_data={
                   'classification': classification, 
                   'risk_score': risk_score,
                   'ml_prediction': ml_prediction
               })
    
    # Send results to controller for GET requests too
    send_to_controller(classification, client_ip, risk_score, ml_prediction)
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/admin')
def admin():
    """Admin endpoint that should never be reached"""
    client_ip = request.remote_addr
    classification, risk_score, ml_prediction = analyze_traffic_with_ml(client_ip)
    
    log_request('admin_attempt', client_ip, extra_data={
        'note': 'Direct admin access attempt',
        'classification': classification,
        'ml_prediction': ml_prediction
    })
    
    # This is highly suspicious - send immediate update to controller
    send_to_controller('malicious', client_ip, 1.0, 1)
    
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

@app.route('/api/ml_status')
def ml_status():
    """API endpoint to check ML model status"""
    try:
        # Test the ML model
        test_prediction, test_score = classify_traffic('127.0.0.1', {'username': 'test', 'user_agent': 'test'})
        return jsonify({
            'status': 'operational',
            'test_prediction': test_prediction,
            'test_score': test_score,
            'model_type': 'simplified_binary'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8004
    logger.info(f"Starting Triage Honeypot on port {port}")
    logger.info(f"Using simplified ML model for binary classification (1=malicious, 0=benign)")
    
    # Test ML model on startup
    try:
        test_pred, test_score = classify_traffic('test.ip', {'username': 'admin', 'user_agent': 'curl'})
        logger.info(f"ML Model test: prediction={test_pred}, score={test_score:.3f}")
    except Exception as e:
        logger.error(f"ML Model error: {e}")
    
    app.run(host='0.0.0.0', port=port, debug=False) 