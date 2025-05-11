from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import os
import json
import configparser

# Configuration path (avoid hardcoding paths)
PROJECT_ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
CONFIG_DIR = os.path.join(PROJECT_ROOT, 'config')
LOGS_DIR = os.path.join(PROJECT_ROOT, 'logs')

# Ensure directories exist
os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

# Config file paths
HONEYPOT_CONFIG_PATH = os.path.join(CONFIG_DIR, 'honeypot_config.json')
CONTROLLER_CONFIG_PATH = os.path.join(PROJECT_ROOT, 'controller', 'controller_config.ini')

# IP configuration (centralized)
NETWORK_CONFIG = {
    'internal_hosts': {
        'start_ip': 1,  # 10.0.0.1
        'count': 14     # h1-h14
    },
    'honeypot': {
        'ip': 15,       # 10.0.0.15 (h15)
    },
    'external_hosts': {
        'start_ip': 9,  # starts at 10.0.0.9 (external1) instead of 16
        'count': 4      # external1-external4
    }
}

class LargeTopo(Topo):
    def build(self, **_opts):
        # Core switches (Level 1)
        s1 = self.addSwitch('s1')  # Core switch 1
        s2 = self.addSwitch('s2')  # Core switch 2
        
        # Aggregation switches (Level 2)
        s3 = self.addSwitch('s3')  # Aggregation switch 1
        s4 = self.addSwitch('s4')  # Aggregation switch 2
        s5 = self.addSwitch('s5')  # Aggregation switch 3
        s6 = self.addSwitch('s6')  # Aggregation switch 4
        
        # Edge switches (Level 3)
        s7 = self.addSwitch('s7')  # Edge switch 1
        s8 = self.addSwitch('s8')  # Edge switch 2
        s9 = self.addSwitch('s9')  # Edge switch 3
        s10 = self.addSwitch('s10')  # Edge switch 4
        s11 = self.addSwitch('s11')  # Edge switch 5
        s12 = self.addSwitch('s12')  # Edge switch 6
        s13 = self.addSwitch('s13')  # Edge switch 7
        s14 = self.addSwitch('s14')  # Edge switch 8

        # Regular hosts with HTTP servers (h1-h14)
        http_server_cmd = f'mkdir -p {LOGS_DIR} && cd {PROJECT_ROOT} && python3 server/real_web_server.py > {LOGS_DIR}/web_server_{{0}}.log 2>&1 &'
        
        # Internal hosts with web servers
        hosts = []
        for i in range(1, NETWORK_CONFIG['internal_hosts']['count'] + 1):
            ip = f"10.0.0.{i}/24"
            host = self.addHost(f'h{i}', ip=ip, cmd=http_server_cmd.format(f'h{i}'))
            hosts.append(host)
        
        # Honeypot host (h15) running a fake HTTP server
        honeypot_ip = f"10.0.0.{NETWORK_CONFIG['honeypot']['ip']}/24"
        honeypot_cmd = f'mkdir -p {LOGS_DIR} && cd {PROJECT_ROOT} && python3 honeypot/http_honeypot.py > {LOGS_DIR}/host15_honeypot.log 2>&1 &'
        h15 = self.addHost('h15', ip=honeypot_ip, cmd=honeypot_cmd)

        # External hosts (potential attackers) - updated to use 10.0.0.9-10.0.0.12
        external_hosts = []
        external_start_ip = NETWORK_CONFIG['external_hosts']['start_ip']
        for i in range(1, NETWORK_CONFIG['external_hosts']['count'] + 1):
            ip = f"10.0.0.{external_start_ip + i - 1}/24"
            external = self.addHost(f'external{i}', ip=ip)
            external_hosts.append(external)

        # Core to Aggregation connections (Level 1 to Level 2)
        self.addLink(s1, s3)
        self.addLink(s1, s4)
        self.addLink(s2, s5)
        self.addLink(s2, s6)
        self.addLink(s1, s2)  # Connect core switches

        # Aggregation to Edge connections (Level 2 to Level 3)
        self.addLink(s3, s7)
        self.addLink(s3, s8)
        self.addLink(s4, s9)
        self.addLink(s4, s10)
        self.addLink(s5, s11)
        self.addLink(s5, s12)
        self.addLink(s6, s13)
        self.addLink(s6, s14)

        # Host-switch connections (Level 3)
        # Connect hosts to edge switches in pairs
        edge_switches = [s7, s7, s8, s8, s9, s9, s10, s10, s11, s11, s12, s12, s13, s13]
        for i, host in enumerate(hosts):
            self.addLink(host, edge_switches[i])
            
        # Connect honeypot to its switch
        self.addLink(h15, s14)  # Honeypot connected to s14

        # External hosts connections to core switches
        for i, external in enumerate(external_hosts):
            switch = s1 if i < 2 else s2  # first 2 to s1, rest to s2
            self.addLink(external, switch)

def run():
    # Create topology with linear MAC addresses
    topo = LargeTopo()
    net = Mininet(
        topo=topo, 
        controller=RemoteController('c0', ip='127.0.0.1', port=6653),
        autoSetMacs=True,  # Use sequential MAC addresses
        listenPort=6634
    )
    net.addNAT().configDefault()
    net.start()
    
    # Start all web servers manually to ensure they're running
    start_web_servers(net)
    
    # Configure honeypot info for controller
    configure_honeypot(net)
    
    CLI(net)
    net.stop()

def configure_honeypot(net):
    """Configure honeypot information for the controller"""
    # Get honeypot's MAC and port
    h15 = net.get('h15')
    h15_mac = h15.MAC()
    h15_ip = f"10.0.0.{NETWORK_CONFIG['honeypot']['ip']}"
    
    # Print the MAC address for verification
    print(f"Actual honeypot MAC address: {h15_mac}")
    
    # Save to JSON config
    honeypot_config = {
        'honeypot_ip': h15_ip,
        'honeypot_mac': h15_mac,
        'honeypot_port': 1  # Default port, will be updated by controller
    }
    
    with open(HONEYPOT_CONFIG_PATH, 'w') as f:
        json.dump(honeypot_config, f, indent=4)
    
    # Also save to INI config for backward compatibility
    config = configparser.ConfigParser()
    if os.path.exists(CONTROLLER_CONFIG_PATH):
        config.read(CONTROLLER_CONFIG_PATH)
    
    if not config.has_section('Network'):
        config.add_section('Network')
    
    config.set('Network', 'honeypot_mac', h15_mac)
    config.set('Network', 'honeypot_ip', h15_ip)
    config.set('Network', 'honeypot_port', '1')
    
    with open(CONTROLLER_CONFIG_PATH, 'w') as configfile:
        config.write(configfile)
    
    print(f"Honeypot MAC address saved to config: {h15_mac}")

def start_web_servers(net):
    """Manually start all web servers to ensure they're running"""
    print("Starting web servers on all hosts...")
    
    # Start regular web servers on h1-h14
    for i in range(1, NETWORK_CONFIG['internal_hosts']['count'] + 1):
        host = net.get(f'h{i}')
        print(f"Starting web server on h{i}...")
        host.cmd(f'cd {PROJECT_ROOT} && python3 server/real_web_server.py > {LOGS_DIR}/web_server_h{i}.log 2>&1 &')
    
    # Start honeypot on h15
    host15 = net.get('h15')
    print(f"Starting honeypot on h15...")
    host15.cmd(f'cd {PROJECT_ROOT} && python3 honeypot/http_honeypot.py > {LOGS_DIR}/host15_honeypot.log 2>&1 &')
    
    # Give servers time to start
    import time
    time.sleep(2)
    print("All web servers started")

# Required by Mininet for --custom flag
topos = { 'large_topo': ( lambda: LargeTopo() ) }

if __name__ == '__main__':
    setLogLevel('info')
    run()