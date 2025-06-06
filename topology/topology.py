#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch, Host, OVSController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from mininet.topo import Topo
from mininet.util import dumpNodeConnections
import time
import sys
import os

class HoneypotSDNTopo(Topo):
    """Tree topology with depth=3 for honeypot SDN project"""
    
    def __init__(self):
        # Initialize topology
        Topo.__init__(self)
        
        # Create switches for tree topology (depth=3)
        # Root switch
        root_switch = self.addSwitch('s1')
        
        # Level 2 switches
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        
        # Level 3 switches  
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5')
        s6 = self.addSwitch('s6')
        s7 = self.addSwitch('s7')
        
        # Connect switches in tree structure
        self.addLink(root_switch, s2)
        self.addLink(root_switch, s3)
        self.addLink(s2, s4)
        self.addLink(s2, s5)
        self.addLink(s3, s6)
        self.addLink(s3, s7)
        
        # Add hosts
        # Normal servers
        h1 = self.addHost('h1', ip='10.0.0.1/24')  # Normal server 1
        h2 = self.addHost('h2', ip='10.0.0.2/24')  # Normal server 2
        h3 = self.addHost('h3', ip='10.0.0.3/24')  # Normal server 3
        
        # Honeypots
        triage_hp = self.addHost('h4', ip='10.0.0.4/24')  # Triage honeypot
        deep_hp = self.addHost('h5', ip='10.0.0.5/24')    # Deep honeypot
        
        # External source host for testing
        external_source = self.addHost('h6', ip='10.0.0.6/24')     # External source for testing
        
        # Connect hosts to leaf switches
        self.addLink(h1, s4)
        self.addLink(h2, s5) 
        self.addLink(h3, s6)
        self.addLink(triage_hp, s7)
        self.addLink(deep_hp, s7)
        self.addLink(external_source, s4)

def setup_network():
    """Setup and run the honeypot SDN network"""
    topo = HoneypotSDNTopo()
    
    # Create network with custom controller (will be Ryu)
    net = Mininet(
        topo=topo,
        controller=RemoteController,
        switch=OVSKernelSwitch,
        host=Host,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=True
    )
    
    # No NAT - h6 is treated as external source
    
    info("*** Starting network\n")
    net.start()
    info("*** Waiting for controller to settle...\n")
    time.sleep(5)

    
    
    info("*** Network topology:\n")
    dumpNodeConnections(net.hosts)
    
    info("*** Setting up host routes and services...\n")
    setup_host_services(net)
    
    info("*** Starting CLI (type 'exit' to quit)\n")
    CLI(net)
    
    info("*** Stopping network\n")
    net.stop()

def setup_host_services(net):
    """Setup services on each host"""
    hosts = net.hosts
    
    # Get the current working directory (should be the project root)
    project_root = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(project_root)  # Go up one level from topology/ to sdnhoney/
    
    # Create logs directory
    logs_dir = os.path.join(project_root, 'logs')
    os.makedirs(logs_dir, exist_ok=True)
    
    # Start web services on each host
    for host in hosts:
        # h6 is external source - no services needed
        if host.name == 'h6':
            continue
            
        # Define service ports (unique for each host)
        if host.name == 'h1':
            port = 8001
            service_type = 'normal'
            service_path = f'{project_root}/servers/server1'
        elif host.name == 'h2': 
            port = 8002
            service_type = 'normal'
            service_path = f'{project_root}/servers/server2'
        elif host.name == 'h3':
            port = 8003 
            service_type = 'normal'
            service_path = f'{project_root}/servers/server3'
        elif host.name == 'h4':
            port = 8004
            service_type = 'triage_honeypot'
            service_path = f'{project_root}/honeypots/triage_honeypot'
        elif host.name == 'h5':
            port = 8005
            service_type = 'deep_honeypot'
            service_path = f'{project_root}/honeypots/deep_honeypot'
        else:  # Unknown host
            continue
            
        info(f"Starting {service_type} service on {host.name} at port {port}\n")
        info(f"Service path: {service_path}\n")
        
        # Start the appropriate service with proper path and output redirection
        if os.path.exists(service_path):
            # Use absolute path and redirect output to logs
            log_file = f"{logs_dir}/{host.name}_service.log"
            cmd = f'cd {service_path} && python3 app.py {port} > {log_file} 2>&1 &'
            info(f"Command: {cmd}\n")
            host.cmd(cmd)
        else:
            info(f"Warning: Service path {service_path} does not exist!\n")
    
    # Give services more time to start
    info("Waiting for services to start...\n")
    time.sleep(5)  # Increased to 5 seconds
    
    # Check if services started successfully
    info("*** Checking service status...\n")
    for host in hosts:
        if host.name == 'h6':
            continue
        
        if host.name == 'h1':
            port = 8001
        elif host.name == 'h2':
            port = 8002
        elif host.name == 'h3':
            port = 8003
        elif host.name == 'h4':
            port = 8004
        elif host.name == 'h5':
            port = 8005
        else:
            continue
            
        # Test if the service is listening using the host's network namespace
        result = host.cmd(f'netstat -ln | grep :{port}')
        if result.strip():
            info(f"✅ {host.name} service running on port {port}\n")
        else:
            info(f"❌ {host.name} service failed to start on port {port}\n")
            # Show any error logs
            log_file = f"{logs_dir}/{host.name}_service.log"
            if os.path.exists(log_file):
                info(f"Log file content for {host.name}:\n")
                with open(log_file, 'r') as f:
                    log_content = f.read()[-500:]  # Show last 500 characters
                    info(f"{log_content}\n")

if __name__ == '__main__':
    # Ensure script is run with sudo
    if os.geteuid() != 0:
        print("This script must be run with sudo privileges!")
        sys.exit(1)
        
    setLogLevel('info')
    setup_network() 