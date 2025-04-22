#!/usr/bin/env python3
import http.server
import socketserver
import logging
import socket
import os
import json
from datetime import datetime

# Loglamayı ayarla
LOG_DIR = "/home/samet/capstone/logs"
os.makedirs(LOG_DIR, exist_ok=True)

# Harici IP adresi tespiti
def get_hostname():
    try:
        host_name = socket.gethostname()
        return host_name
    except:
        return "unknown"

HOST_NAME = get_hostname()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [' + HOST_NAME + '] - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'{LOG_DIR}/web_server_{HOST_NAME}.log'),
        logging.StreamHandler()
    ]
)

PORT = 80
SERVER_NAME = f"WebServer-{HOST_NAME}"

class RealWebHandler(http.server.SimpleHTTPRequestHandler):
    server_version = "Apache/2.4.41 (Ubuntu)"
    sys_version = ""
    
    def log_message(self, format, *args):
        logging.info(f"{self.client_address[0]} - {format%args}")
    
    def version_string(self):
        return self.server_version
    
    def do_GET(self):
        """GET isteklerini işle"""
        client_ip = self.client_address[0]
        logging.info(f"GET isteği alındı: {self.path} from {client_ip}")
        
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            
            # HTML içeriği oluştur
            html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Web Server {HOST_NAME}</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
                    .container {{ max-width: 800px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }}
                    h1 {{ color: #4285f4; }}
                    .info {{ background-color: #f8f9fa; padding: 15px; border-radius: 4px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Welcome to {SERVER_NAME}</h1>
                    <div class="info">
                        <p><strong>Server Information:</strong></p>
                        <ul>
                            <li>Server: {self.server_version}</li>
                            <li>Hostname: {HOST_NAME}</li>
                            <li>Current Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</li>
                            <li>Client IP: {client_ip}</li>
                        </ul>
                    </div>
                    <p>This is a secure web server running on the SDN network.</p>
                </div>
            </body>
            </html>
            """
            
            self.wfile.write(html.encode())
        
        elif self.path == "/api/status":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            
            status = {
                "status": "ok",
                "server": HOST_NAME,
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "uptime": "1 day, 3 hours"
            }
            
            self.wfile.write(json.dumps(status).encode())
        
        else:
            self.send_response(404)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>404 Not Found</h1><p>The requested resource was not found on this server.</p>")

    def do_POST(self):
        """POST isteklerini işle"""
        client_ip = self.client_address[0]
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        logging.info(f"POST isteği alındı: {self.path} from {client_ip}")
        logging.debug(f"POST veri: {post_data.decode('utf-8', 'ignore')}")
        
        if self.path == "/api/login":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            
            response = {
                "success": True,
                "message": "Login successful",
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
            }
            
            self.wfile.write(json.dumps(response).encode())
        else:
            self.send_response(404)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            
            response = {
                "success": False,
                "message": "Endpoint not found"
            }
            
            self.wfile.write(json.dumps(response).encode())

def run_server():
    handler = RealWebHandler
    httpd = socketserver.TCPServer(("", PORT), handler)
    logging.info(f"{SERVER_NAME} başlatıldı: http://localhost:{PORT}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info(f"{SERVER_NAME} durduruldu")

if __name__ == "__main__":
    run_server() 