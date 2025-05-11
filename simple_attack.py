#!/usr/bin/env python3
"""
Simple attack script for testing the SDN honeypot with the large topology.
This script should be run from an external host within Mininet.
"""

import sys
import requests
import time
import random
import socket
import logging
import argparse

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

# Default target is h1
DEFAULT_TARGET = "10.0.0.8"
HONEYPOT_IP = "10.0.0.15"  # h15 is the honeypot in large topology
HTTP_PORT = 8080

def test_regular_request(target_ip):
    """Test a regular HTTP request (should not be redirected)"""
    try:
        url = f"http://{target_ip}:{HTTP_PORT}/"
        logging.info(f"Regular HTTP request to {url}")
        response = requests.get(url, timeout=5)
        logging.info(f"Response: {response.status_code} ({len(response.content)} bytes)")
        
        # Check if this might be a honeypot response
        if "honeypot" in response.text.lower():
            logging.warning("⚠️ This looks like a honeypot response!")
        else:
            logging.info("✓ This looks like a normal web server response")
    except Exception as e:
        logging.error(f"Error: {e}")

def test_attack_patterns(target_ip):
    """Test various attack patterns that should trigger redirection"""
    
    attacks = [
        # SQL Injection attempt
        {
            "name": "SQL Injection",
            "url": f"http://{target_ip}:{HTTP_PORT}/?id=1' OR '1'='1",
            "method": "GET"
        },
        # Path traversal attempt
        {
            "name": "Path Traversal",
            "url": f"http://{target_ip}:{HTTP_PORT}/../../../etc/passwd",
            "method": "GET"
        },
        # Command injection attempt
        {
            "name": "Command Injection",
            "url": f"http://{target_ip}:{HTTP_PORT}/?cmd=cat%20/etc/passwd",
            "method": "GET"
        },
        # XSS attempt
        {
            "name": "XSS Attack",
            "url": f"http://{target_ip}:{HTTP_PORT}/?search=<script>alert(1)</script>",
            "method": "GET"
        }
    ]
    
    # Run each attack
    for i, attack in enumerate(attacks, start=1):
        try:
            logging.info(f"Attack {i}: {attack['name']} - {attack['url']}")
            response = requests.request(
                attack['method'], 
                attack['url'], 
                timeout=5
            )
            logging.info(f"Response: {response.status_code} ({len(response.content)} bytes)")
            
            # Check if this might be a honeypot response
            if "honeypot" in response.text.lower():
                logging.warning(f"⚠️ Attack {i}: REDIRECTED TO HONEYPOT!")
            else:
                logging.info(f"Attack {i}: Not redirected")
        except Exception as e:
            logging.error(f"Error in Attack {i}: {e}")
        
        time.sleep(1)

def test_port_scan(target_ip):
    """Perform a simple port scan that should trigger ML detection"""
    logging.info(f"Starting port scan on {target_ip}")
    
    # Ports to scan
    ports = [21, 22, 23, 80, 443, 8080, 3306]
    
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                logging.info(f"Port {port} is open")
            else:
                logging.info(f"Port {port} is closed")
            sock.close()
        except Exception as e:
            logging.error(f"Error scanning port {port}: {e}")
        
        time.sleep(0.5)

def run_sustained_attack(target_ip, duration=30):
    """Run a sustained attack with mixed requests to trigger ML detection"""
    logging.info(f"Starting sustained attack on {target_ip} for {duration} seconds")
    
    start_time = time.time()
    request_count = 0
    
    while time.time() - start_time < duration:
        try:
            # Randomly choose between normal and attack requests
            if random.random() < 0.3:  # 30% normal requests
                url = f"http://{target_ip}:{HTTP_PORT}/"
            else:  # 70% attack requests
                attack_paths = [
                    "/?id=1%20OR%201=1",
                    "/../../etc/passwd",
                    "/?cmd=ls%20-la",
                    "/?search=<script>alert(1)</script>"
                ]
                url = f"http://{target_ip}:{HTTP_PORT}{random.choice(attack_paths)}"
            
            response = requests.get(url, timeout=2)
            request_count += 1
            
            # Don't log every request to avoid cluttering the output
            if request_count % 10 == 0:
                logging.info(f"Sent {request_count} requests so far")
            
            # Check occasionally if we're being redirected
            if request_count % 20 == 0:
                if "honeypot" in response.text.lower():
                    logging.warning("⚠️ DETECTED HONEYPOT REDIRECTION")
            
            # Small delay between requests
            time.sleep(random.uniform(0.1, 0.5))
            
        except Exception as e:
            logging.error(f"Error during sustained attack: {e}")
    
    logging.info(f"Sustained attack completed. Sent {request_count} requests.")

def test_honeypot_directly():
    """Test direct connection to the honeypot"""
    try:
        url = f"http://{HONEYPOT_IP}:{HTTP_PORT}/"
        logging.info(f"Directly connecting to honeypot at {url}")
        response = requests.get(url, timeout=5)
        logging.info(f"Response: {response.status_code} ({len(response.content)} bytes)")
        
        # Check if this is actually a honeypot response
        if "honeypot" in response.text.lower():
            logging.info("✓ Successfully connected to honeypot")
        else:
            logging.warning("⚠️ Connected to host but response doesn't look like a honeypot")
            
        # Try a malicious request directly to the honeypot
        attack_url = f"http://{HONEYPOT_IP}:{HTTP_PORT}/?id=1%20OR%201=1"
        logging.info(f"Sending attack pattern directly to honeypot: {attack_url}")
        response = requests.get(attack_url, timeout=5)
        logging.info(f"Attack response: {response.status_code} ({len(response.content)} bytes)")
        
    except Exception as e:
        logging.error(f"Error connecting to honeypot: {e}")

def main():
    parser = argparse.ArgumentParser(description="Test attacks against the SDN honeypot system")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="Target IP address")
    parser.add_argument("--regular", action="store_true", help="Test regular HTTP request")
    parser.add_argument("--attacks", action="store_true", help="Test attack patterns")
    parser.add_argument("--portscan", action="store_true", help="Test port scanning")
    parser.add_argument("--sustained", action="store_true", help="Run sustained attack")
    parser.add_argument("--all", action="store_true", help="Run all tests")
    parser.add_argument("--honeypot", action="store_true", help="Test direct connection to honeypot")
    
    args = parser.parse_args()
    
    target_ip = args.target
    logging.info(f"Target set to: {target_ip}")
    
    # If no specific test is selected, run them all
    if not (args.regular or args.attacks or args.portscan or args.sustained or args.honeypot or args.all):
        args.all = True
    
    if args.regular or args.all:
        test_regular_request(target_ip)
        time.sleep(1)
    
    if args.attacks or args.all:
        test_attack_patterns(target_ip)
        time.sleep(1)
    
    if args.portscan or args.all:
        test_port_scan(target_ip)
        time.sleep(1)
    
    if args.honeypot or args.all:
        # Test direct connection to honeypot
        test_honeypot_directly()
        time.sleep(1)
    
    if args.sustained or args.all:
        run_sustained_attack(target_ip)
    
    logging.info("All tests completed")

if __name__ == "__main__":
    main() 