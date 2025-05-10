#!/usr/bin/env python3
"""
Simple attack simulator to test if suspicious traffic is redirected to the honeypot.
This script should be run from the host directory and will be invoked by the Mininet CLI.
"""

import sys
import requests
import time
import random
import socket
import logging
from urllib.parse import quote

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("attack_test.log"),
        logging.StreamHandler()
    ]
)

TARGET_IP = "10.0.0.1"  # Default target is h1
HTTP_PORT = 8080

def perform_attacks():
    """Perform a series of attacks against the target"""
    logging.info(f"Starting attack simulation against {TARGET_IP}:{HTTP_PORT}")
    logging.info(f"If redirection is working, these requests should be captured by the honeypot (h8)")
    
    # Test 1: Regular HTTP request (should be normal)
    try:
        url = f"http://{TARGET_IP}:{HTTP_PORT}/"
        logging.info(f"Test 1: Regular HTTP request to {url}")
        response = requests.get(url, timeout=5)
        logging.info(f"Response: {response.status_code} ({len(response.content)} bytes)")
        # Check if this might be a honeypot response
        if len(response.content) < 100 or "honeypot" in response.text.lower():
            logging.info("Response looks like it might be from the honeypot!")
        else:
            logging.info("Response looks like it's from the real web server")
    except Exception as e:
        logging.error(f"Error in Test 1: {e}")
    
    time.sleep(1)
    
    # Test the following attacks:
    attacks = [
        # SQL Injection attempt
        {
            "name": "SQL Injection",
            "url": f"http://{TARGET_IP}:{HTTP_PORT}/?id=1' OR '1'='1",
            "method": "GET"
        },
        # Path traversal attempt
        {
            "name": "Path Traversal",
            "url": f"http://{TARGET_IP}:{HTTP_PORT}/../../../etc/passwd",
            "method": "GET"
        },
        # Command injection attempt
        {
            "name": "Command Injection",
            "url": f"http://{TARGET_IP}:{HTTP_PORT}/?cmd={quote('cat /etc/passwd')}",
            "method": "GET"
        },
        # XSS attempt
        {
            "name": "XSS Attack",
            "url": f"http://{TARGET_IP}:{HTTP_PORT}/?search=<script>alert(1)</script>",
            "method": "GET"
        }
    ]
    
    # Run each attack
    for i, attack in enumerate(attacks, start=2):
        try:
            logging.info(f"Test {i}: {attack['name']} - {attack['url']}")
            response = requests.request(
                attack['method'], 
                attack['url'], 
                timeout=5
            )
            logging.info(f"Response: {response.status_code} ({len(response.content)} bytes)")
            logging.info(f"Content: {response.text[:100]}...")  # Show first 100 chars of response
            
            # Check if this might be a honeypot response
            if len(response.content) < 100 or "honeypot" in response.text.lower():
                logging.info("Response looks like it might be from the honeypot!")
            else:
                logging.info("Response looks like it's from the real web server")
        except Exception as e:
            logging.error(f"Error in Test {i}: {e}")
        
        time.sleep(1)
    
    # Test 6: Suspicious port scan (try to connect to port 22 - SSH)
    try:
        logging.info(f"Test 6: Port scan - Attempting to connect to SSH port on {TARGET_IP}:22")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        result = s.connect_ex((TARGET_IP, 22))
        if result == 0:
            logging.info(f"Port 22 is open")
        else:
            logging.info(f"Port 22 is closed or filtered (result: {result})")
        s.close()
    except Exception as e:
        logging.error(f"Error in Test 6: {e}")
    
    logging.info("Attack simulation completed")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        TARGET_IP = sys.argv[1]
        # If target is a hostname like 'h1', try to convert to IP
        if TARGET_IP.startswith('h') and TARGET_IP[1:].isdigit():
            host_num = int(TARGET_IP[1:])
            TARGET_IP = f"10.0.0.{host_num}"
            logging.info(f"Converted {sys.argv[1]} to IP: {TARGET_IP}")
    
    logging.info(f"Target set to: {TARGET_IP}")
    perform_attacks() 