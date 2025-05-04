#!/usr/bin/env python3
from http.server import HTTPServer, SimpleHTTPRequestHandler
import logging
import sys
import os
import socket

# Get hostname for logging
hostname = socket.gethostname()

# Configure logging - fixed to avoid using %(hostname)s in the format string
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO,
)

logger = logging.getLogger('web_server')
logger.info(f"Starting real web server on {hostname}")

class CustomHTTPRequestHandler(SimpleHTTPRequestHandler):
    """Custom HTTP request handler that logs all requests in detail"""
    
    def log_message(self, format, *args):
        """Override to send logs to our logger instead of stderr"""
        logger.info("%s - %s", self.address_string(), format % args)
    
    def do_GET(self):
        """Handle GET request and log details"""
        logger.info(f"Received GET request - Path: {self.path}")
        logger.info(f"Headers: {self.headers}")
        
        # Check if this is a potential attack (just for demonstration)
        if '../' in self.path or '\\' in self.path or 'passwd' in self.path or 'etc' in self.path:
            logger.warning(f"Potential path traversal attack detected: {self.path}")
        
        # Normal response - serve static content
        return SimpleHTTPRequestHandler.do_GET(self)
    
    def do_POST(self):
        """Handle POST request and log details"""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        logger.info(f"Received POST request - Path: {self.path}")
        logger.info(f"Headers: {self.headers}")
        logger.info(f"Body: {post_data}")
        
        # Send a simple response
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(f"<html><body><h1>Hello from {hostname}</h1><p>POST received!</p></body></html>".encode())

def run(port=8080, server_class=HTTPServer, handler_class=CustomHTTPRequestHandler):
    """Run the HTTP server"""
    # Create an example index.html if it doesn't exist
    if not os.path.exists('index.html'):
        with open('index.html', 'w') as f:
            f.write(f"""<!DOCTYPE html>
<html>
<head>
    <title>Real Web Server - {hostname}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .container {{ max-width: 800px; margin: 0 auto; }}
        h1 {{ color: #0066cc; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to {hostname}</h1>
        <p>This is a legitimate web server running on the SDN network.</p>
        <p>Current time: <span id="time"></span></p>
        
        <h2>Test Form</h2>
        <form method="post" action="/submit">
            <div>
                <label for="name">Name:</label>
                <input type="text" id="name" name="name">
            </div>
            <div style="margin-top: 10px;">
                <label for="message">Message:</label>
                <textarea id="message" name="message" rows="4" cols="50"></textarea>
            </div>
            <div style="margin-top: 10px;">
                <input type="submit" value="Submit">
            </div>
        </form>
    </div>
    
    <script>
        function updateTime() {{
            document.getElementById('time').textContent = new Date().toLocaleString();
        }}
        updateTime();
        setInterval(updateTime, 1000);
    </script>
</body>
</html>""")
    
    server_address = ('0.0.0.0', port)
    httpd = server_class(server_address, handler_class)
    logger.info(f"Starting HTTP server on 0.0.0.0:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logger.info("HTTP server stopped")

if __name__ == '__main__':
    # Create a directory for this host in the current directory instead of /tmp
    os.makedirs(f"./{hostname}", exist_ok=True)
    os.chdir(f"./{hostname}")
    
    try:
        # Ensure we're binding to all interfaces (0.0.0.0)
        run(port=8080, server_class=HTTPServer, handler_class=CustomHTTPRequestHandler)
    except Exception as e:
        logging.error(f"Server error: {e}")
        sys.exit(1) 