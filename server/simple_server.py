import http.server
import socketserver
import logging

# Loglamayı ayarla
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/home/samet/capstone/logs/simple_server.log'),
        logging.StreamHandler()
    ]
)

PORT = 80

class SimpleHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        logging.info(f"GET isteği alındı: {self.path} from {self.client_address}")
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"Hello from normal server!")

    def do_POST(self):
        logging.info(f"POST isteği alındı: {self.path} from {self.client_address}")
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"Hello from normal server!")

Handler = SimpleHandler

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    logging.info(f"Sunucu başlatıldı: {('', PORT)}")
    httpd.serve_forever()