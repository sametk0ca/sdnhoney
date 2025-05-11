import requests
from flask import Flask, jsonify, render_template, current_app
import logging
import os
import time
from requests.exceptions import ConnectionError, Timeout

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('dashboard')

# Configuration: URL for the Ryu controller's REST API
# Allows override from environment variable
RYU_API_URL = os.environ.get('RYU_API_URL', 'http://localhost:8080')

# Track controller status
controller_status = {
    'last_seen': None,
    'last_logs': [],
    'is_shutdown': False
}

def check_controller_running():
    """Check if the controller is running and update status"""
    try:
        # Add cache-busting parameter
        response = requests.get(f'{RYU_API_URL}/api/status', timeout=1, 
                              params={'_': int(time.time())})
        response.raise_for_status()
        controller_status['last_seen'] = time.time()
        controller_status['is_shutdown'] = False
        return True
    except Exception as e:
        logger.error(f"Controller check error: {e}")
        # If we previously had connection but now don't, mark as shutdown
        if controller_status['last_seen'] is not None:
            controller_status['is_shutdown'] = True
        return False

@app.route('/')
def index():
    """Serve the main dashboard page."""
    return render_template('index.html')

@app.route('/data')
def get_data():
    """Fetch data from Ryu API and return as JSON."""
    data = {
        'status': 'Error',
        'switches': [],
        'mac_table': {},
        'hosts': {},
        'logs': [],
        'ml_logs': [],
        'host15_honeypot_logs': [],
        'error': None
    }
    
    # Check if controller is running first
    controller_running = check_controller_running()
    
    if not controller_running and controller_status['is_shutdown']:
        # If controller was running but now isn't, it's likely been shut down
        data['status'] = 'Shutdown'
        data['error'] = "Controller appears to have been shut down."
        # Return the last known logs if we have them
        if controller_status['last_logs']:
            data['logs'] = controller_status['last_logs']
            # Add shutdown message to logs
            data['logs'].append("*** CONTROLLER SHUTDOWN DETECTED ***")
        # Add placeholder for host15 logs on shutdown?
        data['host15_honeypot_logs'] = ["*** CONTROLLER SHUTDOWN - Host15 logs unavailable ***"]
        return jsonify(data)
        
    try:
        # Cache busting timestamp to ensure fresh data
        cache_buster = {'_': int(time.time())}
        
        # Fetch status
        status_resp = requests.get(f'{RYU_API_URL}/api/status', 
                                 timeout=2, params=cache_buster)
        status_resp.raise_for_status() # Raise exception for bad status codes
        data['status'] = status_resp.json().get('status', 'Unknown')

        # Fetch switches
        switches_resp = requests.get(f'{RYU_API_URL}/api/switches', 
                                   timeout=2, params=cache_buster)
        switches_resp.raise_for_status()
        data['switches'] = switches_resp.json().get('switches', [])

        # Fetch MAC table
        mac_table_resp = requests.get(f'{RYU_API_URL}/api/mac_table', 
                                    timeout=2, params=cache_buster)
        mac_table_resp.raise_for_status()
        data['mac_table'] = mac_table_resp.json().get('mac_table', {})

        # Fetch Hosts
        hosts_resp = requests.get(f'{RYU_API_URL}/api/hosts', 
                                timeout=2, params=cache_buster)
        hosts_resp.raise_for_status()
        data['hosts'] = hosts_resp.json().get('hosts', {})

        # Fetch Logs - use a unique timestamp for each request
        logs_resp = requests.get(f'{RYU_API_URL}/api/logs', 
                               timeout=2, params={'_': int(time.time() * 1000)})
        logs_resp.raise_for_status()
        data['logs'] = logs_resp.json().get('logs', [])
        logger.info(f"Fetched {len(data['logs'])} log entries")
        
        # Save the last known logs in case controller shuts down
        if data['logs']:
            controller_status['last_logs'] = data['logs']

        # Fetch ML Logs
        ml_logs_resp = requests.get(f'{RYU_API_URL}/api/ml_logs', 
                                  timeout=2, params={'_': int(time.time() * 1000)})
        ml_logs_resp.raise_for_status()
        data['ml_logs'] = ml_logs_resp.json().get('ml_logs', [])

        # Fetch Host15 Honeypot Logs
        host15_logs_resp = requests.get(f'{RYU_API_URL}/api/host15_honeypot_logs', 
                                     timeout=2, params={'_': int(time.time() * 1000)})
        host15_logs_resp.raise_for_status()
        data['host15_honeypot_logs'] = host15_logs_resp.json().get('host15_honeypot_logs', [])

    except (ConnectionError, Timeout) as e:
        logger.warning(f"Connection error to Ryu API: {e}")
        data['error'] = "Cannot connect to the Ryu controller API. Make sure the controller is running."
        # If connection fails, still try to return last known controller logs
        if controller_status['last_logs']:
             data['logs'] = controller_status['last_logs']
        data['host15_honeypot_logs'] = ["*** ERROR: Cannot connect to controller to fetch Host15 logs ***"]
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching data from Ryu API: {e}")
        data['error'] = str(e)
        data['host15_honeypot_logs'] = [f"*** ERROR: Failed to fetch Host15 logs: {e} ***"]
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        data['error'] = 'An unexpected error occurred.'
        data['host15_honeypot_logs'] = ["*** UNEXPECTED ERROR fetching Host15 logs ***"]

    return jsonify(data)

@app.route('/health')
def health_check():
    """Simple health check endpoint."""
    return jsonify({"status": "healthy"})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    logger.info(f"Starting dashboard on port {port}")
    logger.info(f"Using Ryu API URL: {RYU_API_URL}")
    # Run on port 5001 to avoid conflict with ML service (50051) or Ryu (8080)
    app.run(debug=True, host='0.0.0.0', port=port) 