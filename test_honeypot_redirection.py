#!/usr/bin/env python3
"""
Simple script to test honeypot redirection without ML model.
Run this after starting the SDN honeypot system.
"""

import time
import logging
import argparse
import subprocess
import random

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def run_command(cmd):
    """Run a command and return output"""
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return output.decode('utf-8')
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output.decode('utf-8')}"

def test_attack(attack_host, target_host):
    """Test an attack from attack_host to target_host"""
    
    # Run commands on the attack host using Mininet's command interface
    cmd_prefix = f"sudo mn -c && cd ~/Desktop/sdnhoney && ./start.sh &"
    logger.info("Starting Mininet...")
    subprocess.run(cmd_prefix, shell=True)
    
    # Wait for Mininet to start
    time.sleep(10)
    
    # Run commands in Mininet CLI
    attack_cmds = [
        # Ping to test basic connectivity
        f"{attack_host} ping -c 3 {target_host}",
        
        # HTTP request to test web access
        f"{attack_host} wget -O - http://{target_host}:8080/ 2>&1",
        
        # Test some suspicious patterns
        f"{attack_host} nmap -p 22,23,80,8080,443 {target_host}",
        
        # Test an SQL injection attempt
        f"{attack_host} curl -s 'http://{target_host}:8080/?id=1%20OR%201=1'",
        
        # Test a path traversal attempt
        f"{attack_host} curl -s 'http://{target_host}:8080/../../../etc/passwd'"
    ]
    
    # Run each attack command
    for cmd in attack_cmds:
        logger.info(f"Running: {cmd}")
        mininet_cmd = f"echo '{cmd}' | sudo mn -c"
        result = run_command(mininet_cmd)
        logger.info(f"Result: {result}")
        time.sleep(1)
    
    logger.info("Attack simulation completed")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test honeypot redirection")
    parser.add_argument('--attack-host', default='external1', help='Host to launch attacks from')
    parser.add_argument('--target-host', default='10.0.0.1', help='Host to attack')
    args = parser.parse_args()
    
    test_attack(args.attack_host, args.target_host) 