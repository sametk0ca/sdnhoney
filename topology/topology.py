from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import threading
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.log import setLogLevel
from mininet.cli import CLI
import os

class SDNTopo(Topo):
    def build(self):
        # Create switches
        root_switch = self.addSwitch('s1')
        level1_switches = [self.addSwitch(f's2{i}') for i in range(1, 3)]
        level2_switches = [self.addSwitch(f's3{i}') for i in range(1, 5)]

        # Create hosts
        normal_hosts = [self.addHost(f'h{i}') for i in range(1, 9)]
        triage_honeypot = self.addHost('h9')
        deep_honeypot = self.addHost('h10')

        # Connect switches
        for sw in level1_switches:
            self.addLink(root_switch, sw)
        for i, sw in enumerate(level2_switches):
            self.addLink(level1_switches[i // 2], sw)

        # Connect hosts
        for i, host in enumerate(normal_hosts):
            self.addLink(level2_switches[i % len(level2_switches)], host)
        self.addLink(level2_switches[0], triage_honeypot)
        self.addLink(level2_switches[1], deep_honeypot)

def start_mininet_services(net):
    print("Starting HTTP servers on hosts...")
    # Calculate the absolute path to the project root
    # __file__ is the path to the current script (topology.py)
    # os.path.dirname(__file__) is the directory of topology.py (e.g., /path/to/project/topology)
    # os.path.abspath(os.path.join(os.path.dirname(__file__), '..')) is /path/to/project
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

    server_app_path = os.path.join(project_root, 'servers/server_app.py')
    triage_app_path = os.path.join(project_root, 'honeypots/triage_honeypot/triage_app.py')
    deep_app_path = os.path.join(project_root, 'honeypots/deep_honeypot/deep_app.py')

    standard_backend_port = 8000 # Define a standard port for h1-h8

    for i in range(1, 9):
        host = net.get(f'h{i}')
        # Use the standard_backend_port for h1-h8
        host.cmd(f'python3 {server_app_path} {standard_backend_port} > /tmp/h{i}_server.log 2>&1 &')
        print(f"Started server on h{i} on port {standard_backend_port}")

    h9 = net.get('h9')
    h9_port = 8009
    h9.cmd(f'python3 {triage_app_path} {h9_port} > /tmp/h9_server.log 2>&1 &')
    print(f"Started server on h9 (Triage Honeypot) on port {h9_port}")

    h10 = net.get('h10')
    h10_port = 8010
    h10.cmd(f'python3 {deep_app_path} {h10_port} > /tmp/h10_server.log 2>&1 &')
    print(f"Started server on h10 (Deep Honeypot) on port {h10_port}")

class RequestHandler(BaseHTTPRequestHandler):
    net_instance = None # Class variable to hold the Mininet instance

    def do_GET(self):
        if self.path == '/topology':
            if RequestHandler.net_instance is None:
                self.send_response(503) # Service Unavailable
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b"Mininet instance not ready for topology API")
                print("Error: Topology API called but Mininet instance not set.")
                return

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            nodes_data = []
            for node_name in RequestHandler.net_instance.nameToNode:
                node = RequestHandler.net_instance.nameToNode[node_name]
                node_info = {"id": node_name, "type": "unknown", "ip": None, "mac": None}

                # Get MAC address - all nodes should have at least one interface
                # Using the MAC of the first interface for simplicity
                try:
                    node_info["mac"] = node.MAC()
                except AttributeError: # Some node types might not have a simple MAC() method
                    # Try to get MAC from the first interface if available
                    if node.intfList():
                        node_info["mac"] = node.intfList()[0].mac

                if node_name.startswith('h'):
                    node_info["type"] = "host"
                    try:
                        node_info["ip"] = node.IP()
                    except AttributeError: # In case a host somehow doesn't have an IP directly
                        pass 
                elif node_name.startswith('s'):
                    node_info["type"] = "switch"
                    # Switches don't typically have an IP in the same way hosts do in Mininet
                    # Their MAC is usually their datapath ID (DPID), but node.MAC() might give a base MAC.
                elif node_name == 'nat0':
                    node_info["type"] = "nat"
                    # NAT node might have multiple interfaces with IPs, getting the primary one if possible
                    if node.intfList():
                         # This is a heuristic, NAT interface names can vary.
                         # We're looking for an interface that is not the local one (e.g., nat0-eth0 vs lo)
                        for intf in node.intfList():
                            if intf.name != 'lo' and hasattr(intf, 'ip') and intf.ip:
                                node_info["ip"] = intf.ip
                                break
                elif node_name.startswith('c'): 
                    node_info["type"] = "controller"
                    # Controllers in Mininet don't have IP/MAC in the context of the topology data plane
                
                if node_info["type"] in ["host", "switch", "nat", "controller"]:
                    nodes_data.append(node_info)

            links_data = []
            for link in RequestHandler.net_instance.links:
                links_data.append({"source": link.intf1.node.name, "target": link.intf2.node.name})
            
            topology_data = {"nodes": nodes_data, "links": links_data}
            self.wfile.write(json.dumps(topology_data).encode())
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"API endpoint not found")

def run_topology_api_server_thread_target(net):
    RequestHandler.net_instance = net
    server_address = ('', 8081)
    httpd = HTTPServer(server_address, RequestHandler)
    print(f"Topology API server listening on port {server_address[1]} in a background thread...")
    httpd.serve_forever() # This will block the thread
    # When thread is stopped (e.g. main program exits if daemon), this might not be reached directly
    # httpd.server_close() # Proper cleanup if serve_forever could be interrupted gracefully

if __name__ == '__main__':
    setLogLevel('info')

    topo = SDNTopo()
    # Use RemoteController, assuming Ryu is running on localhost:6653
    c0 = RemoteController('c0', ip='127.0.0.1', port=6653)
    net = Mininet(topo=topo, controller=c0) # Pass the controller instance
    
    print("Adding NAT to the network...")
    nat_node = net.addNAT(name='nat0') # addNAT returns the NAT node itself
    nat_node.configDefault() 
    print("NAT added and configured.")

    print("Starting Mininet network...")
    net.start()
    
    print("Testing connectivity to internet from h1 (via NAT)...")
    h1 = net.get('h1')
    result = h1.cmd('ping -c 1 8.8.8.8')
    if '1 received' in result:
        print("h1 can ping 8.8.8.8 - Internet connectivity via NAT looks OK.")
    else:
        print("h1 cannot ping 8.8.8.8 - NAT/Internet connectivity issue. Result:", result)

    start_mininet_services(net) # Start Flask servers on hosts
    
    # Start the API server in a daemon thread
    api_thread = threading.Thread(target=run_topology_api_server_thread_target, args=(net,), daemon=True)
    api_thread.start()
    print("Topology API server thread started.")

    CLI(net) # This is blocking until CLI is exited
    
    print("CLI exited. Stopping Mininet network...")
    net.stop()
    print("Mininet network stopped.")
    # The daemon API thread will terminate automatically when the main program exits. 