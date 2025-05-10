#!/usr/bin/env python3
from http.server import HTTPServer, SimpleHTTPRequestHandler
import logging
import sys
import os
import socket
import time
import json
import random
import datetime

# Configure logging
log_dir = "logs"
os.makedirs(log_dir, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(log_dir, "host8_honeypot.log")),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class HoneypotHTTPRequestHandler(SimpleHTTPRequestHandler):
    """HTTP Honeypot that mimics a real server but logs everything"""
    
    server_version = "Apache/2.4.41 (Ubuntu)"  # Fake server version
    sys_version = ""  # Hide Python version
    
    # List of fake directories and files to simulate a real server
    fake_dirs = [
        '/admin', '/login', '/dashboard', '/wp-admin', '/phpmyadmin',
        '/api', '/user', '/account', '/profile', '/settings'
    ]
    
    fake_files = [
        'index.php', 'login.php', 'admin.php', 'config.php', 'wp-login.php',
        'wp-config.php', '.env', '.git/HEAD', 'README.md', 'robots.txt'
    ]
    
    # Track IP connections to detect scanning and DoS
    ip_connections = {}
    
    def __init__(self, *args, **kwargs):
        # Call the parent constructor first to ensure client_address is available
        super().__init__(*args, **kwargs)
        
        # Initialize connection tracking for this request after parent init is done
        client_ip = self.client_address[0] if hasattr(self, 'client_address') else "unknown"
        if client_ip not in self.ip_connections:
            self.ip_connections[client_ip] = {
                "first_seen": time.time(),
                "last_seen": time.time(),
                "request_count": 0,
                "paths": set()
            }
    
    def log_message(self, format, *args):
        """Override to log all requests to our file"""
        msg = format % args
        # Log with more visibility at WARNING level instead of INFO
        logger.warning(f"HONEYPOT: {self.client_address[0]}:{self.client_address[1]} - {msg}")
    
    def log_attack(self, attack_type, details):
        """Log potential attack with additional details"""
        attack_data = {
            'timestamp': datetime.datetime.now().isoformat(),
            'client_ip': self.client_address[0],
            'client_port': self.client_address[1],
            'attack_type': attack_type,
            'path': self.path,
            'headers': dict(self.headers),
            'details': details,
        }
        
        # Log the attack data
        logger.warning(f"ATTACK DETECTED - {attack_type}: {json.dumps(attack_data)}")
        
        # Also save to a structured file for ML training
        with open(os.path.join(log_dir, "attack_data.json"), 'a') as f:
            f.write(json.dumps(attack_data) + '\n')
    
    def track_connection(self):
        """Track connection patterns for this IP"""
        client_ip = self.client_address[0]
        
        # Ensure the IP is in our tracking dictionary
        if client_ip not in self.ip_connections:
            self.ip_connections[client_ip] = {
                "first_seen": time.time(),
                "last_seen": time.time(),
                "request_count": 0,
                "paths": set()
            }
        
        # Update tracking info
        self.ip_connections[client_ip]["last_seen"] = time.time()
        self.ip_connections[client_ip]["request_count"] += 1
        self.ip_connections[client_ip]["paths"].add(self.path)
        
        # Calculate request rate (requests per second)
        first_seen = self.ip_connections[client_ip]["first_seen"]
        last_seen = self.ip_connections[client_ip]["last_seen"]
        request_count = self.ip_connections[client_ip]["request_count"]
        
        time_diff = max(last_seen - first_seen, 0.001)  # Avoid division by zero
        request_rate = request_count / time_diff
        
        # Log high rate requests
        if request_rate > 2.0:  # More than 2 requests per second
            self.log_attack('high_request_rate', {
                'rate': request_rate,
                'count': request_count,
                'duration': time_diff
            })
        
        # Log scanning behavior (multiple different paths)
        path_count = len(self.ip_connections[client_ip]["paths"])
        if path_count > 5:
            self.log_attack('scanning_behavior', {
                'unique_paths': list(self.ip_connections[client_ip]["paths"]),
                'path_count': path_count
            })
    
    def do_GET(self):
        """Handle GET requests, detecting potential attacks"""
        # Track connection patterns
        self.track_connection()
        
        # Log the request details (log as WARNING to make it more visible)
        logger.warning(f"HONEYPOT GOT REQUEST: {self.client_address[0]}:{self.client_address[1]} - GET {self.path}")
        logger.warning(f"HONEYPOT HEADERS: {dict(self.headers)}")
        
        # Check for attack signatures with more patterns
        # Path traversal attacks
        if any(pattern in self.path.lower() for pattern in ['../', '..%2f', '..\\', '.htaccess', 'etc/passwd', 'wp-config', 'etc/', 'windows/', 'system32']):
            self.log_attack('path_traversal', {'path': self.path})
            
        # Command injection attacks
        if any(pattern in self.path.lower() for pattern in ['exec', 'eval', 'system', 'cmd', 'shell', 'passthru', 'bash', '`', '$(', '&&']):
            self.log_attack('command_injection', {'path': self.path})
        
        # SQL injection attacks
        if any(pattern in self.path.lower() for pattern in ['select', 'union', 'from', 'where', '1=1', '--', 'information_schema', 
                                                         "';", "' or", "' and", '%27', 'drop', 'insert', 'update']):
            self.log_attack('sql_injection', {'path': self.path})
        
        # XSS attacks
        if any(pattern in self.path.lower() for pattern in ['<script', 'javascript:', 'onerror', 'onload', 'alert(', 'document.cookie', 'img src', 'iframe']):
            self.log_attack('xss', {'path': self.path})
        
        # Check for port scanning (unusual ports in headers or connection)
        if self.client_address[1] < 1024 or self.client_address[1] > 50000:
            self.log_attack('unusual_port', {'client_port': self.client_address[1]})
        
        # Log any unusual HTTP methods
        method = self.command
        if method not in ['GET', 'POST']:
            self.log_attack('unusual_http_method', {'method': method})
        
        # Log any unusual User-Agent
        user_agent = self.headers.get('User-Agent', '')
        if not user_agent or user_agent in ['', 'curl', 'wget', 'python-requests']:
            self.log_attack('unusual_user_agent', {'user_agent': user_agent})
        
        # Detect DoS attacks by checking if we've seen too many requests from this IP
        if self.ip_connections[self.client_address[0]]["request_count"] > 50:
            self.log_attack('potential_dos', {
                'request_count': self.ip_connections[self.client_address[0]]["request_count"],
                'time_period': time.time() - self.ip_connections[self.client_address[0]]["first_seen"]
            })
        
        # Simulate a delay to seem like a real server (0.2-1.0 seconds)
        time.sleep(random.uniform(0.2, 1.0))
        
        # Handle some common paths to seem legitimate
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(self.get_index_page().encode())
            logger.warning(f"HONEYPOT SENT RESPONSE: 200 OK to {self.client_address[0]}:{self.client_address[1]}")
            return
        
        elif self.path == '/login' or self.path == '/login.php':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(self.get_login_page().encode())
            logger.warning(f"HONEYPOT SENT RESPONSE: 200 OK to {self.client_address[0]}:{self.client_address[1]}")
            return
        
        elif self.path == '/admin' or self.path == '/admin.php':
            self.send_response(401)
            self.send_header('Content-type', 'text/html')
            self.send_header('WWW-Authenticate', 'Basic realm="Admin Area"')
            self.end_headers()
            self.wfile.write(b'<html><body><h1>401 Unauthorized</h1><p>You need to authenticate to access this page.</p></body></html>')
            logger.warning(f"HONEYPOT SENT RESPONSE: 401 Unauthorized to {self.client_address[0]}:{self.client_address[1]}")
            return
        
        # For any 404 responses, still provide plausible content
        self.send_response(404)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(self.get_404_page().encode())
        logger.warning(f"HONEYPOT SENT RESPONSE: 404 Not Found to {self.client_address[0]}:{self.client_address[1]}")
    
    def do_POST(self):
        """Handle POST requests, detecting potential attacks"""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        # Log the POST request details
        logger.warning(f"HONEYPOT GOT REQUEST: {self.client_address[0]}:{self.client_address[1]} - POST {self.path}")
        logger.warning(f"HONEYPOT HEADERS: {dict(self.headers)}")
        logger.warning(f"HONEYPOT POST DATA: {post_data}")
        
        # Check for attack signatures in POST data
        # Path traversal attacks
        if any(pattern in post_data.lower() for pattern in ['../', '..%2f', '..\\', '.htaccess', 'etc/passwd', 'wp-config', 'etc/', 'windows/', 'system32']):
            self.log_attack('path_traversal', {'path': self.path, 'post_data': post_data})
            
        # Command injection attacks
        if any(pattern in post_data.lower() for pattern in ['exec', 'eval', 'system', 'cmd', 'shell', 'passthru', 'bash', '`', '$(', '&&']):
            self.log_attack('command_injection', {'path': self.path, 'post_data': post_data})
        
        # SQL injection attacks
        if any(pattern in post_data.lower() for pattern in ['select', 'union', 'from', 'where', '1=1', '--', 'information_schema', 
                                                         "';", "' or", "' and", '%27', 'drop', 'insert', 'update']):
            self.log_attack('sql_injection', {'path': self.path, 'post_data': post_data})
        
        # XSS attacks
        if any(pattern in post_data.lower() for pattern in ['<script', 'javascript:', 'onerror', 'onload', 'alert(', 'document.cookie', 'img src', 'iframe']):
            self.log_attack('xss', {'path': self.path, 'post_data': post_data})
            
        # CSRF attacks
        if 'csrf' not in post_data.lower() and self.path not in ['/login', '/logout', '/register']:
            self.log_attack('potential_csrf', {'path': self.path, 'post_data': post_data})
            
        # Simulate a delay to seem like a real server (0.2-1.0 seconds)
        time.sleep(random.uniform(0.2, 1.0))
        
        # Generic response for all POST requests
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'{"success": true, "message": "Request processed"}')
        logger.warning(f"HONEYPOT SENT RESPONSE: 200 OK to {self.client_address[0]}:{self.client_address[1]}")
    
    def get_index_page(self):
        """Generate a realistic-looking index page"""
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>Welcome to Company XYZ</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 0; }}
        header {{ background-color: #333; color: white; padding: 20px; }}
        nav {{ background-color: #444; padding: 10px; }}
        nav a {{ color: white; margin-right: 15px; text-decoration: none; }}
        .container {{ padding: 20px; max-width: 1200px; margin: 0 auto; }}
        footer {{ background-color: #333; color: white; padding: 20px; text-align: center; }}
    </style>
</head>
<body>
    <header>
        <h1>Company XYZ</h1>
    </header>
    <nav>
        <a href="/">Home</a>
        <a href="/about">About Us</a>
        <a href="/services">Services</a>
        <a href="/contact">Contact</a>
        <a href="/login">Login</a>
    </nav>
    <div class="container">
        <h2>Welcome to Our Website</h2>
        <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nullam auctor, nisl eget ultricies ultricies, nisl nisl ultricies nisl, eget ultricies nisl nisl eget.</p>
        <p>Server time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <h3>Our Services</h3>
        <ul>
            <li>Web Development</li>
            <li>Mobile Apps</li>
            <li>Cloud Solutions</li>
            <li>Consulting</li>
        </ul>
    </div>
    <footer>
        &copy; {datetime.datetime.now().year} Company XYZ. All rights reserved.
    </footer>
</body>
</html>"""
    
    def get_login_page(self):
        """Generate a realistic-looking login page"""
        error_msg = '<p style="color: red;">Invalid username or password. Please try again.</p>' if 'error=1' in self.path else ''
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>Login - Company XYZ</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 0; }}
        header {{ background-color: #333; color: white; padding: 20px; }}
        .container {{ padding: 20px; max-width: 400px; margin: 0 auto; }}
        .form-group {{ margin-bottom: 15px; }}
        label {{ display: block; margin-bottom: 5px; }}
        input {{ width: 100%; padding: 8px; box-sizing: border-box; }}
        button {{ background-color: #4CAF50; color: white; padding: 10px 15px; border: none; cursor: pointer; }}
    </style>
</head>
<body>
    <header>
        <h1>Company XYZ</h1>
    </header>
    <div class="container">
        <h2>Login</h2>
        {error_msg}
        <form method="post" action="/login">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
        <p><a href="/forgot-password">Forgot Password?</a></p>
    </div>
</body>
</html>"""
    
    def get_404_page(self):
        """Generate a realistic-looking 404 page"""
        return """<!DOCTYPE html>
<html>
<head>
    <title>404 Not Found</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; text-align: center; }
        .container { padding: 50px; }
        h1 { font-size: 48px; margin-bottom: 20px; }
        p { font-size: 18px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>404</h1>
        <h2>Page Not Found</h2>
        <p>The page you are looking for does not exist or has been moved.</p>
        <p><a href="/">Return to Homepage</a></p>
    </div>
</body>
</html>"""

def run(port=8080, server_class=HTTPServer, handler_class=HoneypotHTTPRequestHandler):
    """Run the HTTP honeypot server"""
    server_address = ('0.0.0.0', port)  # Bind to all interfaces
    httpd = server_class(server_address, handler_class)
    logger.warning(f"Starting HTTP honeypot on 0.0.0.0:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logger.warning("HTTP honeypot stopped")

if __name__ == '__main__':
    # Create logs directory if it doesn't exist
    os.makedirs(log_dir, exist_ok=True)
    
    print("Starting HTTP honeypot (h8)")
    logger.warning("HONEYPOT STARTING")
    try:
        run()
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1) 