from flask import Flask, request
import sys
import datetime
import os

app = Flask(__name__)

# Define log file path within the app
LOG_FILE_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "logs", "triage_honeypot.log")

def log_activity(ip_address: str, reason: str):
    """Logs activity to the triage honeypot's log file."""
    timestamp = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    log_message = f"{timestamp} -- {ip_address} -- {reason}\n"
    os.makedirs(os.path.dirname(LOG_FILE_PATH), exist_ok=True)
    with open(LOG_FILE_PATH, "a") as f:
        f.write(log_message)

@app.route('/')
def hello():
    # Log the request
    # For now, using a generic reason. This should be updated based on actual detection logic.
    log_activity(request.remote_addr, "Connection to triage honeypot")
    return "Hello from Triage Honeypot\n"

if __name__ == '__main__':
    port_num = 80 # Default port
    if len(sys.argv) > 1:
        try:
            port_num = int(sys.argv[1])
        except ValueError:
            print(f"Invalid port number: {sys.argv[1]}. Using default port {port_num}.")
    app.run(host='0.0.0.0', port=port_num) 