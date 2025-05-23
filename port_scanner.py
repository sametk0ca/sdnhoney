import socket
import sys

def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1) # Timeout for connection attempt
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(f"Port {port}: Open")
        # else:
        #     print(f"Port {port}: Closed or filtered")
        sock.close()
    except socket.error as e:
        # print(f"Port {port}: Error ({e})")
        pass # Suppress errors for closed/filtered ports for cleaner output

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python port_scanner.py <target_ip> <start_port>-<end_port>")
        sys.exit(1)

    target_ip = sys.argv[1]
    try:
        port_range_str = sys.argv[2]
        start_port, end_port = map(int, port_range_str.split('-'))
        if not (0 < start_port <= 65535 and 0 < end_port <= 65535 and start_port <= end_port):
            raise ValueError("Invalid port range.")
    except ValueError as e:
        print(f"Error: Invalid port range format or value. Use 1-1024. Details: {e}")
        sys.exit(1)
        
    print(f"Scanning {target_ip} from port {start_port} to {end_port}...")
    for port_num in range(start_port, end_port + 1):
        scan_port(target_ip, port_num)
    print("Scan complete.") 