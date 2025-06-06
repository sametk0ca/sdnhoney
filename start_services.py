#!/usr/bin/env python3

import os
import sys
import subprocess
import time

def start_service_on_host(host_name, port, service_path, service_type):
    """Start a service on a specific host"""
    print(f"Starting {service_type} on {host_name} at port {port}")
    print(f"Service path: {service_path}")
    
    if not os.path.exists(service_path):
        print(f"❌ Error: Service path {service_path} does not exist!")
        return False
    
    # Create command to start service
    cmd = f"cd {service_path} && python3 app.py {port}"
    print(f"Command: {cmd}")
    
    try:
        # Start the service in background
        subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(2)  # Give service time to start
        
        # Check if it's running
        result = subprocess.run(f"netstat -ln | grep :{port}", shell=True, capture_output=True, text=True)
        if result.stdout.strip():
            print(f"✅ {host_name} service running on port {port}")
            return True
        else:
            print(f"❌ {host_name} service failed to start on port {port}")
            return False
    except Exception as e:
        print(f"❌ Error starting {host_name}: {e}")
        return False

def main():
    """Start all services"""
    # Get project root directory
    project_root = os.path.dirname(os.path.abspath(__file__))
    
    # Create logs directory
    logs_dir = os.path.join(project_root, 'logs')
    os.makedirs(logs_dir, exist_ok=True)
    
    # Define services
    services = [
        ('h1', 8001, os.path.join(project_root, 'servers', 'server1'), 'normal_server'),
        ('h2', 8002, os.path.join(project_root, 'servers', 'server2'), 'normal_server'),
        ('h3', 8003, os.path.join(project_root, 'servers', 'server3'), 'normal_server'),
        ('h4', 8004, os.path.join(project_root, 'honeypots', 'triage_honeypot'), 'triage_honeypot'),
        ('h5', 8005, os.path.join(project_root, 'honeypots', 'deep_honeypot'), 'deep_honeypot'),
    ]
    
    print("Starting SDN Honeypot Services...")
    print("=" * 50)
    
    # Start each service
    success_count = 0
    for host_name, port, service_path, service_type in services:
        if start_service_on_host(host_name, port, service_path, service_type):
            success_count += 1
        print()
    
    print(f"Successfully started {success_count}/{len(services)} services")
    
    if success_count == len(services):
        print("✅ All services started successfully!")
        print("\nYou can now test with:")
        print("curl http://10.0.0.4:8004/  # Triage honeypot")
        print("curl http://10.0.0.1:8001/  # Normal server")
    else:
        print("❌ Some services failed to start. Check logs for details.")

if __name__ == '__main__':
    main() 