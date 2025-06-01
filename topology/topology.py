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
        
        # External client host for testing
        client = self.addHost('h6', ip='10.0.0.6/24')     # Client for testing
        
        # Connect hosts to leaf switches
        self.addLink(h1, s4)
        self.addLink(h2, s5) 
        self.addLink(h3, s6)
        self.addLink(triage_hp, s7)
        self.addLink(deep_hp, s7)
        self.addLink(client, s4)

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
    
    # Add NAT for external connectivity
    net.addNAT().configDefault()
    
    info("*** Starting network\n")
    net.start()
    
    info("*** Testing connectivity\n")
    net.pingAll()
    
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
    
    # Start web services on each host
    for host in hosts:
        if host.name == 'nat0':  # Skip NAT
            continue
            
        # Define service ports (unique for each host)
        if host.name == 'h1':
            port = 8001
            service_type = 'normal'
        elif host.name == 'h2': 
            port = 8002
            service_type = 'normal'
        elif host.name == 'h3':
            port = 8003 
            service_type = 'normal'
        elif host.name == 'h4':
            port = 8004
            service_type = 'triage_honeypot'
        elif host.name == 'h5':
            port = 8005
            service_type = 'deep_honeypot'
        else:  # h6 client
            continue
            
        info(f"Starting {service_type} service on {host.name} at port {port}\n")
        
        # Start the appropriate service
        if service_type == 'normal':
            host.cmd(f'cd /home/samet/Desktop/sdnhoney/servers/server{host.name[-1]} && python3 app.py {port} &')
        elif service_type == 'triage_honeypot':
            host.cmd(f'cd /home/samet/Desktop/sdnhoney/honeypots/triage_honeypot && python3 app.py {port} &')
        elif service_type == 'deep_honeypot':
            host.cmd(f'cd /home/samet/Desktop/sdnhoney/honeypots/deep_honeypot && python3 app.py {port} &')
    
    # Give services time to start
    time.sleep(2)

if __name__ == '__main__':
    # Ensure script is run with sudo
    if os.geteuid() != 0:
        print("This script must be run with sudo privileges!")
        sys.exit(1)
        
    setLogLevel('info')
    setup_network() 