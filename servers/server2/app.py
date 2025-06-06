#!/usr/bin/env python3

from flask import Flask, request, render_template_string, redirect, url_for, session, jsonify
import sys
import os
import json
import datetime

app = Flask(__name__)
app.secret_key = 'normal_server_secret_key_67890'

# Valid credentials for normal servers
VALID_CREDENTIALS = {
    'admin': 'password123',
    'user': 'user123',
    'test': 'test123'
}

# Logging directory
LOG_DIR = os.path.join(os.path.dirname(__file__), '../../logs')
os.makedirs(LOG_DIR, exist_ok=True)

def log_request(request_type, source_ip, success=False, username=None):
    """Log requests to file"""
    log_entry = {
        'timestamp': datetime.datetime.now().isoformat(),
        'server': 'normal_server_2',
        'source_ip': source_ip,
        'request_type': request_type,
        'success': success,
        'username': username,
        'user_agent': request.headers.get('User-Agent', ''),
        'method': request.method
    }
    
    log_file = os.path.join(LOG_DIR, 'normal_server_2.log')
    with open(log_file, 'a') as f:
        f.write(json.dumps(log_entry) + '\n')

# HTML Templates
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
            <p>Normal Server 2</p>
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

ADMIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel - smtkoca.com</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f0f0f0; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { border-bottom: 1px solid #ddd; padding-bottom: 10px; margin-bottom: 20px; }
        .logout { float: right; }
        .logout a { color: #dc3545; text-decoration: none; }
        .section { margin-bottom: 20px; padding: 15px; background-color: #f8f9fa; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>smtkoca.com - Admin Panel</h2>
            <div class="logout">
                <a href="/logout">Logout</a>
            </div>
            <div style="clear: both;"></div>
        </div>
        
        <div class="section">
            <h3>Server Status</h3>
            <p><strong>Server:</strong> Normal Server 2</p>
            <p><strong>Status:</strong> <span style="color: green;">Online</span></p>
            <p><strong>Current User:</strong> {{ username }}</p>
        </div>
        
        <div class="section">
            <h3>Server Management</h3>
            <p>This is a legitimate server admin panel. You have successfully authenticated.</p>
            <ul>
                <li>Server Monitoring</li>
                <li>User Management</li>
                <li>System Logs</li>
                <li>Configuration</li>
            </ul>
        </div>
        
        <div class="section">
            <h3>Recent Activity</h3>
            <p>Login successful from {{ client_ip }}</p>
            <p>System running normally</p>
        </div>
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
        
        log_request('login_attempt', client_ip, username=username)
        
        if username in VALID_CREDENTIALS and VALID_CREDENTIALS[username] == password:
            session['username'] = username
            log_request('login_success', client_ip, success=True, username=username)
            return redirect(url_for('admin'))
        else:
            log_request('login_failure', client_ip, success=False, username=username)
            return render_template_string(LOGIN_TEMPLATE, error="Invalid credentials")
    
    log_request('page_visit', client_ip)
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/admin')
def admin():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    client_ip = request.remote_addr
    log_request('admin_access', client_ip, success=True, username=session['username'])
    
    return render_template_string(ADMIN_TEMPLATE, 
                                username=session['username'],
                                client_ip=client_ip)

@app.route('/logout')
def logout():
    client_ip = request.remote_addr
    username = session.get('username')
    session.pop('username', None)
    log_request('logout', client_ip, username=username)
    return redirect(url_for('login'))

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'server': 'normal_server_2'})

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8002
    print(f"Starting Normal Server 2 on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False) 