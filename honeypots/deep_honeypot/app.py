#!/usr/bin/env python3

from flask import Flask, request, render_template_string, redirect, url_for, session, jsonify, send_file
import sys
import os
import json
import datetime
import io
import time
from collections import defaultdict

app = Flask(__name__)
app.secret_key = 'deep_honeypot_secret_key_666'

# Logging directory
LOG_DIR = '/home/samet/Desktop/sdnhoney/logs'
os.makedirs(LOG_DIR, exist_ok=True)

# Track attacker sessions
attacker_sessions = defaultdict(dict)

def log_extensive(action, source_ip, data=None):
    """Extensive logging for deep honeypot"""
    log_entry = {
        'timestamp': datetime.datetime.now().isoformat(),
        'server': 'deep_honeypot',
        'source_ip': source_ip,
        'action': action,
        'session_id': session.get('session_id'),
        'user_agent': request.headers.get('User-Agent', ''),
        'method': request.method,
        'url': request.url,
        'referrer': request.referrer,
        'request_headers': dict(request.headers),
        'form_data': dict(request.form) if request.form else None,
        'args': dict(request.args) if request.args else None,
        'data': data
    }
    
    log_file = os.path.join(LOG_DIR, 'deep_honeypot.log')
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
            <p>Secure Portal</p>
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

FAKE_ADMIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel - smtkoca.com</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f0f0f0; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { border-bottom: 1px solid #ddd; padding-bottom: 10px; margin-bottom: 20px; }
        .logout { float: right; }
        .logout a { color: #dc3545; text-decoration: none; }
        .section { margin-bottom: 20px; padding: 15px; background-color: #f8f9fa; border-radius: 4px; }
        .file-list { list-style: none; padding: 0; }
        .file-list li { padding: 8px; border-bottom: 1px solid #eee; }
        .file-list a { color: #007bff; text-decoration: none; }
        .sidebar { float: left; width: 200px; margin-right: 20px; }
        .main-content { margin-left: 220px; }
        .warning { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin: 10px 0; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>smtkoca.com - Admin Control Panel</h2>
            <div class="logout">
                <a href="/logout">Logout</a>
            </div>
            <div style="clear: both;"></div>
        </div>
        
        <div class="sidebar">
            <h3>Navigation</h3>
            <ul style="list-style: none; padding: 0;">
                <li><a href="/admin">Dashboard</a></li>
                <li><a href="/admin/files">File Manager</a></li>
                <li><a href="/admin/users">User Management</a></li>
                <li><a href="/admin/logs">System Logs</a></li>
                <li><a href="/admin/config">Configuration</a></li>
                <li><a href="/admin/database">Database</a></li>
            </ul>
        </div>
        
        <div class="main-content">
            <div class="section">
                <h3>🎯 System Status</h3>
                <p><strong>Server:</strong> Production Server Alpha</p>
                <p><strong>Status:</strong> <span style="color: green;">Online</span></p>
                <p><strong>Current User:</strong> {{ username }} (Administrator)</p>
                <p><strong>Last Login:</strong> {{ last_login }}</p>
                
                <div class="warning">
                    <strong>⚠️ Security Notice:</strong> Unauthorized access detected. Please review security logs immediately.
                </div>
            </div>
            
            <div class="section">
                <h3>📊 Quick Stats</h3>
                <ul>
                    <li>Active Users: 24</li>
                    <li>Database Size: 2.4 GB</li>
                    <li>Uptime: 45 days</li>
                    <li>Security Level: Maximum</li>
                </ul>
            </div>
            
            <div class="section">
                <h3>📁 Recent Files</h3>
                <ul class="file-list">
                    <li><a href="/admin/download/passwords.txt">passwords.txt</a> - 2KB</li>
                    <li><a href="/admin/download/customer_data.xlsx">customer_data.xlsx</a> - 450KB</li>
                    <li><a href="/admin/download/financial_report.pdf">financial_report.pdf</a> - 1.2MB</li>
                    <li><a href="/admin/download/backup_keys.zip">backup_keys.zip</a> - 15KB</li>
                </ul>
            </div>
        </div>
        <div style="clear: both;"></div>
    </div>
</body>
</html>
'''

FAKE_FILE_MANAGER = '''
<!DOCTYPE html>
<html>
<head>
    <title>File Manager - smtkoca.com</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f0f0f0; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }
        .file-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 15px; }
        .file-item { padding: 15px; border: 1px solid #ddd; border-radius: 4px; text-align: center; }
        .file-item:hover { background-color: #f8f9fa; }
    </style>
</head>
<body>
    <div class="container">
        <h2>File Manager</h2>
        <div class="file-grid">
            <div class="file-item">
                <h4>📄 Important Documents</h4>
                <a href="/admin/download/secret_plans.pdf">secret_plans.pdf</a>
            </div>
            <div class="file-item">
                <h4>🔑 Access Keys</h4>
                <a href="/admin/download/api_keys.txt">api_keys.txt</a>
            </div>
            <div class="file-item">
                <h4>💾 Database Backup</h4>
                <a href="/admin/download/db_backup.sql">db_backup.sql</a>
            </div>
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
        
        # Create fake session ID
        session_id = f"session_{int(time.time())}_{client_ip.replace('.', '')}"
        session['session_id'] = session_id
        session['username'] = username
        
        # Log the login attempt
        log_extensive('fake_login_success', client_ip, {
            'username': username,
            'password': password,  # Log the actual password attempt
            'session_id': session_id
        })
        
        # Always "succeed" after a delay to seem realistic
        time.sleep(1)  # Simulate processing time
        return redirect(url_for('admin'))
    
    log_extensive('page_visit', client_ip)
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/admin')
def admin():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    client_ip = request.remote_addr
    log_extensive('fake_admin_access', client_ip, {
        'username': session['username'],
        'admin_dashboard_viewed': True
    })
    
    return render_template_string(FAKE_ADMIN_TEMPLATE,
                                username=session['username'],
                                last_login="2024-01-15 14:30:22")

@app.route('/admin/files')
def files():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    client_ip = request.remote_addr
    log_extensive('fake_file_manager_access', client_ip, {
        'attempted_file_access': True
    })
    
    return render_template_string(FAKE_FILE_MANAGER)

@app.route('/admin/download/<filename>')
def download_fake_file(filename):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    client_ip = request.remote_addr
    log_extensive('fake_file_download_attempt', client_ip, {
        'filename': filename,
        'highly_suspicious': True
    })
    
    # Generate fake file content
    fake_content = f"""
    CONFIDENTIAL - {filename}
    Generated on: {datetime.datetime.now()}
    
    This appears to be sensitive data but is actually a honeypot.
    The attacker has attempted to download: {filename}
    
    [Fake data content would go here...]
    """
    
    # Return fake file
    return send_file(
        io.BytesIO(fake_content.encode()),
        as_attachment=True,
        download_name=filename,
        mimetype='text/plain'
    )

@app.route('/admin/<path:path>')
def fake_admin_pages(path):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    client_ip = request.remote_addr
    log_extensive('fake_admin_page_access', client_ip, {
        'path': path,
        'exploring_admin_functions': True
    })
    
    fake_page = f'''
    <!DOCTYPE html>
    <html>
    <head><title>{path.title()} - Admin Panel</title></head>
    <body>
        <h2>{path.title()} Management</h2>
        <p>Loading {path} interface...</p>
        <p>Access granted to: {session['username']}</p>
        <a href="/admin">Back to Dashboard</a>
    </body>
    </html>
    '''
    return fake_page

@app.route('/logout')
def logout():
    client_ip = request.remote_addr
    username = session.get('username')
    
    log_extensive('fake_logout', client_ip, {
        'username': username,
        'session_ended': True
    })
    
    session.clear()
    return redirect(url_for('login'))

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'server': 'deep_honeypot'})

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8005
    print(f"Starting Deep Honeypot on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False) 