#!/usr/bin/env python3
"""
Script to check honeypot logs and verify if the honeypot is receiving redirected traffic.
"""

import os
import time
import logging
import subprocess
import sys

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Define paths
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(PROJECT_ROOT, 'logs')
HONEYPOT_LOG = os.path.join(LOGS_DIR, 'host8_honeypot.log')
CONTROLLER_LOG = os.path.join(LOGS_DIR, 'controller.log')

def ensure_logs_directory():
    """Ensure logs directory exists"""
    if not os.path.exists(LOGS_DIR):
        os.makedirs(LOGS_DIR)
        logger.info(f"Created logs directory at {LOGS_DIR}")
    else:
        logger.info(f"Logs directory already exists at {LOGS_DIR}")

def check_log_file(log_path, description):
    """Check if log file exists and has content"""
    if not os.path.exists(log_path):
        logger.error(f"{description} log file not found at {log_path}")
        return False
    
    size = os.path.getsize(log_path)
    if size == 0:
        logger.warning(f"{description} log file exists but is empty")
        return False
    
    logger.info(f"{description} log file exists with size {size} bytes")
    return True

def tail_log(log_path, lines=10):
    """Display the last n lines of a log file"""
    if not os.path.exists(log_path):
        logger.error(f"Log file not found: {log_path}")
        return
    
    try:
        with open(log_path, 'r') as f:
            log_lines = f.readlines()
            if not log_lines:
                logger.warning(f"Log file is empty: {log_path}")
                return
            
            last_lines = log_lines[-lines:]
            print(f"\nLast {lines} lines of {os.path.basename(log_path)}:")
            print("=" * 50)
            for line in last_lines:
                print(line.strip())
            print("=" * 50)
    except Exception as e:
        logger.error(f"Error reading log file: {e}")

def check_controller_redirection():
    """Check if controller is redirecting traffic to honeypot"""
    if not os.path.exists(CONTROLLER_LOG):
        logger.error(f"Controller log not found at {CONTROLLER_LOG}")
        return False
    
    try:
        redirection_count = 0
        with open(CONTROLLER_LOG, 'r') as f:
            for line in f:
                if "REDIRECTING SUSPICIOUS TRAFFIC" in line:
                    redirection_count += 1
        
        if redirection_count > 0:
            logger.info(f"Found {redirection_count} redirection events in controller log")
            return True
        else:
            logger.warning("No redirection events found in controller log")
            return False
    except Exception as e:
        logger.error(f"Error checking controller log: {e}")
        return False

def find_honeypot_log():
    """Try to find honeypot log file as it might have a different name"""
    # Try common honeypot log patterns
    potential_logs = [
        os.path.join(LOGS_DIR, 'host8_honeypot.log'),
        os.path.join(LOGS_DIR, 'honeypot.log'),
        os.path.join(PROJECT_ROOT, 'honeypot', 'log', 'glastopf.log'),
        os.path.join(PROJECT_ROOT, 'honeypot', 'honeypot.log')
    ]
    
    for log_path in potential_logs:
        if os.path.exists(log_path):
            logger.info(f"Found honeypot log at {log_path}")
            return log_path
    
    # If none of the expected paths work, try to find any log file in the honeypot directory
    honeypot_dir = os.path.join(PROJECT_ROOT, 'honeypot')
    if os.path.exists(honeypot_dir):
        for root, dirs, files in os.walk(honeypot_dir):
            for file in files:
                if file.endswith('.log'):
                    log_path = os.path.join(root, file)
                    logger.info(f"Found potential honeypot log at {log_path}")
                    return log_path
    
    logger.error("Could not find honeypot log file")
    return None

def check_honeypot_traffic_reception():
    """Check if honeypot is receiving traffic"""
    honeypot_log = find_honeypot_log()
    if not honeypot_log:
        return False
    
    # Check if the log file has been modified in the last minute
    current_time = time.time()
    last_modified = os.path.getmtime(honeypot_log)
    if current_time - last_modified > 60:
        logger.warning(f"Honeypot log hasn't been modified in the last minute")
    
    # Check content
    try:
        with open(honeypot_log, 'r') as f:
            content = f.read()
            if "request" in content.lower() or "attack" in content.lower():
                logger.info("Honeypot log contains request/attack indicators")
                return True
            else:
                logger.warning("No clear indicators of traffic in honeypot log")
                return False
    except Exception as e:
        logger.error(f"Error checking honeypot log: {e}")
        return False

def main():
    """Main function to check honeypot operation"""
    logger.info("Checking honeypot operation...")
    
    # Ensure logs directory exists
    ensure_logs_directory()
    
    # Check controller log
    controller_log_ok = check_log_file(CONTROLLER_LOG, "Controller")
    if controller_log_ok:
        tail_log(CONTROLLER_LOG, 15)
        redirects_found = check_controller_redirection()
        if not redirects_found:
            logger.warning("Controller doesn't seem to be redirecting traffic to honeypot")
    
    # Find and check honeypot log
    honeypot_log = find_honeypot_log()
    if honeypot_log:
        honeypot_log_ok = check_log_file(honeypot_log, "Honeypot")
        if honeypot_log_ok:
            tail_log(honeypot_log, 15)
            traffic_received = check_honeypot_traffic_reception()
            if not traffic_received:
                logger.warning("Honeypot doesn't seem to be receiving traffic")
    
    # Check on the Mininet side if we can run commands
    logger.info("Checking honeypot behavior inside Mininet...")
    try:
        result = subprocess.run(
            "ps -ef | grep mininet", 
            shell=True, 
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if "mininet-cli" in result.stdout:
            logger.info("Mininet CLI is running. You can manually test with commands like:")
            logger.info("  - external1 ping h8")
            logger.info("  - external1 python3 test_attack.py h8")
            logger.info("  - h8 tail -f /tmp/honeypot.log (or whatever log path is being used)")
    except Exception as e:
        logger.error(f"Error checking Mininet status: {e}")

if __name__ == "__main__":
    main() 