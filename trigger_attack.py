#!/usr/bin/env python3
"""
Very simple attack simulator to directly test honeypot redirection.
"""

import socket
import requests
import sys
import time
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Default values
DEFAULT_TARGET = '10.0.0.1'
HONEYPOT_IP = '10.0.0.8'

def check_target_reachable(target_ip):
    """Check if target is reachable via HTTP"""
    try:
        response = requests.get(f"http://{target_ip}:8080/", timeout=2)
        logging.info(f"Target {target_ip} is reachable. Response: {response.status_code}")
        return True
    except Exception as e:
        logging.error(f"Cannot reach target {target_ip}: {e}")
        return False

def check_honeypot_reachable():
    """Check if honeypot is directly reachable"""
    try:
        response = requests.get(f"http://{HONEYPOT_IP}:8080/", timeout=2)
        logging.info(f"Honeypot is reachable. Response: {response.status_code}")
        return True
    except Exception as e:
        logging.error(f"Cannot reach honeypot: {e}")
        return False

def test_attack(target_ip):
    """Test an attack against the target IP"""
    logging.info(f"Testing attack against {target_ip}")
    
    # Test 1: SQL Injection
    try:
        logging.info("Test 1: SQL Injection attack")
        response = requests.get(f"http://{target_ip}:8080/?id=1' OR '1'='1", timeout=5)
        logging.info(f"Response: {response.status_code} - {len(response.content)} bytes")
        
        # Check if this looks like a honeypot response
        if "honeypot" in response.text.lower() or response.status_code == 404:
            logging.info("POSSIBLE HONEYPOT: Response may be from the honeypot!")
        else:
            logging.info("Regular response - doesn't appear to be redirected")
    except Exception as e:
        logging.error(f"Error in SQL Injection test: {e}")
    
    # Test 2: Try to trigger rule-based detection with unusual port
    try:
        logging.info("Test 2: Connecting to SSH port (should trigger rule-based detection)")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        result = s.connect_ex((target_ip, 22))
        if result == 0:
            logging.info("SSH port is open!")
        else:
            logging.info(f"SSH port is closed/filtered (result: {result})")
        s.close()
    except Exception as e:
        logging.error(f"Error in SSH port test: {e}")
    
    # Let's try a direct attack on port 8080
    try:
        logging.info("Test 3: Direct HTTP attack with suspicious path")
        response = requests.get(f"http://{target_ip}:8080/../../../etc/passwd", timeout=5)
        logging.info(f"Response: {response.status_code} - {len(response.content)} bytes")
        if len(response.content) < 200:
            logging.info(f"Response content: {response.text}")
    except Exception as e:
        logging.error(f"Error in direct HTTP attack: {e}")

def main():
    """Main function"""
    # Determine target IP
    target_ip = DEFAULT_TARGET
    if len(sys.argv) > 1:
        target_ip = sys.argv[1]
        # If target is a hostname like 'h1', try to convert to IP
        if target_ip.startswith('h') and target_ip[1:].isdigit():
            host_num = int(target_ip[1:])
            target_ip = f"10.0.0.{host_num}"
            logging.info(f"Converted {sys.argv[1]} to IP: {target_ip}")
    
    logging.info(f"Target set to: {target_ip}")
    
    # Check connectivity
    if not check_target_reachable(target_ip):
        logging.error("Cannot reach target IP. Exiting.")
        return
    
    # Run attack tests
    test_attack(target_ip)
    
    # Also try to reach honeypot directly
    if check_honeypot_reachable():
        logging.info("Honeypot is directly reachable. You can try direct tests against it.")
    
    logging.info("Tests completed")

if __name__ == "__main__":
    main() 