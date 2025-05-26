from flask import Flask, render_template, jsonify, current_app
import os
import requests
import logging

app = Flask(__name__)

# Configure basic logging for the app
logging.basicConfig(level=logging.INFO)

# Define the base directory for logs relative to this app.py file
LOGS_BASE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)))
MININET_TOPOLOGY_API_URL = "http://localhost:8081/topology"

LOG_FILES = {
    "controller": os.path.join(LOGS_BASE_DIR, "logs", "controller.log"),
    "triage_honeypot": os.path.join(LOGS_BASE_DIR, "logs", "triage_honeypot.log"),
    "deep_honeypot": os.path.join(LOGS_BASE_DIR, "logs", "deep_honeypot.log")
}

@app.route('/')
def index():
    return render_template('index.html', log_types=LOG_FILES.keys())

@app.route('/logs/<log_type>')
def get_log(log_type):
    if log_type in LOG_FILES:
        log_file_path = LOG_FILES[log_type]
        try:
            with open(log_file_path, 'r') as f:
                lines = f.readlines()
                content = "".join(lines[-50:]) 
            return jsonify({"log_type": log_type, "content": content})
        except FileNotFoundError:
            return jsonify({"log_type": log_type, "error": f"Log file not found at {log_file_path}."}), 404
        except Exception as e:
            current_app.logger.error(f"Error reading log {log_file_path}: {str(e)}")
            return jsonify({"log_type": log_type, "error": str(e)}), 500
    else:
        return jsonify({"error": "Invalid log type."}), 404

@app.route('/api/mininet_topology')
def get_mininet_topology():
    current_app.logger.info(f"Attempting to fetch topology from: {MININET_TOPOLOGY_API_URL}")
    try:
        response = requests.get(MININET_TOPOLOGY_API_URL, timeout=5)
        current_app.logger.info(f"Mininet API response status: {response.status_code}")
        response.raise_for_status()
        topology_data = response.json()
        current_app.logger.info(f"Successfully fetched and parsed topology data.")
        return jsonify(topology_data)
    except requests.exceptions.ConnectionError as e:
        current_app.logger.error(f"ConnectionError when fetching topology: {str(e)}")
        return jsonify({"error": "Failed to connect to Mininet topology API. Is Mininet running and API server active on port 8081?"}), 503
    except requests.exceptions.Timeout as e:
        current_app.logger.error(f"Timeout when fetching topology: {str(e)}")
        return jsonify({"error": "Request to Mininet topology API timed out."}), 504
    except requests.exceptions.HTTPError as e:
        current_app.logger.error(f"HTTPError when fetching topology: {str(e)} - Response: {e.response.text}")
        return jsonify({"error": f"Mininet topology API returned an error: {e.response.status_code}"}), e.response.status_code
    except requests.exceptions.RequestException as e:
        current_app.logger.error(f"RequestException when fetching topology: {str(e)}")
        return jsonify({"error": f"Error fetching Mininet topology: {str(e)}"}), 500
    except Exception as e:
        current_app.logger.error(f"Unexpected error in get_mininet_topology: {str(e)}", exc_info=True)
        return jsonify({"error": f"An unexpected error occurred while fetching topology: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)