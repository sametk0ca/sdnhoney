from flask import Flask
import sys

app = Flask(__name__)

@app.route('/')
def hello():
    return "Hello from Triage Honeypot\n"

if __name__ == '__main__':
    port_num = 80 # Default port
    if len(sys.argv) > 1:
        try:
            port_num = int(sys.argv[1])
        except ValueError:
            print(f"Invalid port number: {sys.argv[1]}. Using default port {port_num}.")
    app.run(host='0.0.0.0', port=port_num) 