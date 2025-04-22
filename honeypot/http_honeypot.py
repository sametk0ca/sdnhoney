#!/usr/bin/env python3
import http.server
import socketserver
import logging
import json
import os
import time
import threading
import random
import socket
import re
from datetime import datetime
from urllib.parse import urlparse, parse_qs

# Loglama dizini
LOG_DIR = "/home/samet/capstone/logs"
os.makedirs(LOG_DIR, exist_ok=True)

# Log dosyası ayarları
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [HONEYPOT] - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'{LOG_DIR}/honeypot.log'),
        logging.StreamHandler()
    ]
)

# İzlenen saldırganlar için veri yapısı
ATTACKERS = {}
SUSPICIOUS_PATHS = [
    '/wp-admin', '/wp-login', '/admin', '/login', '/phpmyadmin', 
    '/xmlrpc.php', '/cgi-bin', '/config', '/.git', '/.env',
    '/shell', '/cmd', '/exec', '/passwd', '/index.php',
    '/setup.php', '/install', '/backup'
]

# Olası SQL injection saldırılarını tespit et
SQL_INJECTION_PATTERNS = [
    r"('|\").*OR.*('|\")",
    r"('|\").*UNION.*SELECT.*('|\")",
    r".*DROP TABLE.*",
    r".*--.*",
    r".*SELECT.*FROM.*"
]

# Olası XSS saldırılarını tespit et
XSS_PATTERNS = [
    r"<script.*>",
    r"javascript:",
    r"onerror=",
    r"onload=",
    r"eval\(",
    r"document\.cookie"
]

# Zaman aşımı eklenerek sunucu gerçekçi görünsün
def random_delay():
    time.sleep(random.uniform(0.05, 0.3))

class HoneypotHTTPHandler(http.server.SimpleHTTPRequestHandler):
    server_version = "Apache/2.4.41 (Ubuntu)"
    sys_version = ""
    
    def version_string(self):
        # Server başlığını gerçekçi göster
        return self.server_version
    
    def log_message(self, format, *args):
        # Normal HTTP server log formatını engelle
        pass
    
    def detect_attack(self, path, query, headers, method):
        """Saldırı tespiti yap"""
        attack_types = []
        
        # SQL Injection tespiti
        if query:
            query_str = '&'.join([f"{k}={v[0]}" for k, v in query.items()])
            for pattern in SQL_INJECTION_PATTERNS:
                if re.search(pattern, query_str, re.IGNORECASE):
                    attack_types.append("SQL Injection")
                    break
        
        # XSS tespiti
        for pattern in XSS_PATTERNS:
            if query and any(re.search(pattern, v[0], re.IGNORECASE) for k, v in query.items()):
                attack_types.append("XSS")
                break
        
        # Şüpheli yollar
        for susp_path in SUSPICIOUS_PATHS:
            if susp_path in path:
                attack_types.append("Path Traversal")
                break
                
        # Admin paneli veya sisteme erişim girişimleri
        if '/admin' in path or '/login' in path or '/wp-admin' in path:
            attack_types.append("Admin Access Attempt")
        
        return attack_types if attack_types else None
    
    def log_attack(self, client_ip, attack_types, path, method):
        """Saldırı ve saldırganı logla"""
        timestamp = datetime.now()
        
        if client_ip not in ATTACKERS:
            ATTACKERS[client_ip] = {
                'first_seen': timestamp,
                'attacks': []
            }
        
        ATTACKERS[client_ip]['attacks'].append({
            'timestamp': timestamp,
            'method': method,
            'path': path,
            'type': attack_types
        })
        
        ATTACKERS[client_ip]['last_seen'] = timestamp
        
        # Log olarak kaydet
        attack_type_str = ', '.join(attack_types)
        logging.warning(f"SALDIRI TESPİT EDİLDİ - IP: {client_ip}, Yöntem: {method}, Yol: {path}, Tip: {attack_type_str}")
    
    def do_GET(self):
        client_ip = self.client_address[0]
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        query = parse_qs(parsed_url.query)
        
        # İsteği logla
        logging.info(f"GET isteği alındı: {self.path} from {client_ip}")
        
        # Saldırı tespit et
        attack_types = self.detect_attack(path, query, self.headers, 'GET')
        if attack_types:
            self.log_attack(client_ip, attack_types, path, 'GET')
        
        # Rastgele gecikme ekle
        random_delay()
        
        # Yanıtları hazırla
        if path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            html = f'''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Web Server</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
                    .container {{ max-width: 800px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }}
                    h1 {{ color: #4285f4; }}
                    .info {{ background-color: #f8f9fa; padding: 15px; border-radius: 4px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Welcome to Our Web Server</h1>
                    <div class="info">
                        <p><strong>Server Information:</strong></p>
                        <ul>
                            <li>Server: {self.server_version}</li>
                            <li>Hostname: server8</li>
                            <li>Current Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</li>
                            <li>Client IP: {client_ip}</li>
                        </ul>
                    </div>
                    <p>This is a secure web server running on the SDN network.</p>
                    <div>
                        <p>Quick Links:</p>
                        <ul>
                            <li><a href="/api/status">Server Status</a></li>
                            <li><a href="/login">Admin Login</a></li>
                        </ul>
                    </div>
                </div>
            </body>
            </html>
            '''
            
            self.wfile.write(html.encode())
            
        elif path == '/api/status':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            status = {
                "status": "ok",
                "server": "server8",
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "uptime": "3 days, 14 hours",
                "connections": random.randint(5, 25)
            }
            
            self.wfile.write(json.dumps(status).encode())
            
        elif path == '/login':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            html = '''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Login - Web Server</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
                    .container { max-width: 500px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
                    h1 { color: #4285f4; }
                    .form-group { margin-bottom: 15px; }
                    label { display: block; margin-bottom: 5px; }
                    input[type="text"], input[type="password"] { width: 100%; padding: 8px; box-sizing: border-box; }
                    button { background-color: #4285f4; color: white; border: none; padding: 10px 15px; cursor: pointer; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Admin Login</h1>
                    <form action="/api/login" method="post">
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
                </div>
            </body>
            </html>
            '''
            
            self.wfile.write(html.encode())
            
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            html = '''
            <!DOCTYPE html>
            <html>
            <head>
                <title>404 Not Found</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
                    .container { max-width: 500px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
                    h1 { color: #d93025; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>404 Not Found</h1>
                    <p>The requested resource was not found on this server.</p>
                    <p><a href="/">Return to Homepage</a></p>
                </div>
            </body>
            </html>
            '''
            
            self.wfile.write(html.encode())
    
    def do_POST(self):
        client_ip = self.client_address[0]
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8', 'ignore')
        
        # POST isteğini logla
        logging.info(f"POST isteği alındı: {self.path} from {client_ip}")
        logging.info(f"POST veri: {post_data}")
        
        # Saldırı tespiti
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        
        # POST verilerini analiz et
        attack_types = self.detect_attack(path, None, self.headers, 'POST')
        
        # Post içeriğindeki saldırıları tespit et
        for pattern in SQL_INJECTION_PATTERNS:
            if re.search(pattern, post_data, re.IGNORECASE):
                if attack_types is None:
                    attack_types = []
                if "SQL Injection" not in attack_types:
                    attack_types.append("SQL Injection")
        
        for pattern in XSS_PATTERNS:
            if re.search(pattern, post_data, re.IGNORECASE):
                if attack_types is None:
                    attack_types = []
                if "XSS" not in attack_types:
                    attack_types.append("XSS")
        
        if attack_types:
            self.log_attack(client_ip, attack_types, path, 'POST')
        
        # Rastgele gecikme ekle
        random_delay()
        
        if path == '/api/login':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            # Eğer bu bir saldırı ise, başarısız login yanıtı ver
            if attack_types:
                response = {
                    "success": False,
                    "message": "Invalid username or password"
                }
            else:
                response = {
                    "success": True,
                    "message": "Login successful",
                    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
                }
            
            self.wfile.write(json.dumps(response).encode())
        else:
            self.send_response(404)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            response = {
                "success": False,
                "message": "Endpoint not found"
            }
            
            self.wfile.write(json.dumps(response).encode())

def report_thread():
    """Düzenli olarak saldırı raporu oluştur"""
    while True:
        if ATTACKERS:
            logging.info(f"--- Honeypot Saldırı Özeti ({len(ATTACKERS)} saldırgan) ---")
            for ip, data in ATTACKERS.items():
                attack_count = len(data['attacks'])
                last_seen = data['last_seen'].strftime('%Y-%m-%d %H:%M:%S')
                logging.info(f"IP: {ip}, Saldırı Sayısı: {attack_count}, Son Görülme: {last_seen}")
        
        time.sleep(300)  # 5 dakikada bir rapor

def run_server():
    port = 80
    handler = HoneypotHTTPHandler
    
    # IPv4 adresi ile bağlan
    httpd = socketserver.TCPServer(("", port), handler)
    
    # Arka planda raporlama işlemini başlat
    report_timer = threading.Thread(target=report_thread, daemon=True)
    report_timer.start()
    
    logging.info(f"Honeypot HTTP sunucusu başlatıldı: http://localhost:{port}")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    
    httpd.server_close()
    logging.info("Honeypot HTTP sunucusu durduruldu")

if __name__ == "__main__":
    run_server() 