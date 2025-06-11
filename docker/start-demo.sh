#!/bin/bash

echo "🚀 Starting SDN Honeypot Demo Environment"

# Wait for controller to be ready
echo "⏳ Waiting for SDN Controller..."
for i in {1..30}; do
    if netstat -ln | grep :6653 > /dev/null; then
        echo "✅ SDN Controller is ready"
        break
    fi
    sleep 1
done

# Wait a bit more for controller to fully initialize
sleep 3

# Start OVS
echo "🔧 Starting Open vSwitch..."
service openvswitch-switch start

# Start Mininet topology
echo "🌐 Starting Mininet topology..."
cd /app/topology

# Create the topology with services
python3 -c "
import sys
sys.path.append('/app/topology')
from topology import HoneypotSDNTopo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
import time
import os
import subprocess

# Create topology
topo = HoneypotSDNTopo()
net = Mininet(topo=topo, controller=RemoteController, autoSetMacs=True, autoStaticArp=True)

print('*** Starting network')
net.start()

print('*** Waiting for controller to settle...')
time.sleep(5)

print('*** Starting host services...')
# Start services on hosts using supervisor
subprocess.run(['supervisorctl', 'start', 'h1-service'])
subprocess.run(['supervisorctl', 'start', 'h2-service'])
subprocess.run(['supervisorctl', 'start', 'h3-service'])
subprocess.run(['supervisorctl', 'start', 'h4-service'])
subprocess.run(['supervisorctl', 'start', 'h5-service'])

time.sleep(3)

print('*** Demo environment ready!')
print('*** Network is running. Container will stay alive.')

# Keep the network alive - this keeps the container running
while True:
    time.sleep(10)
"

echo "❌ Mininet topology stopped" 