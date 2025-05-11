# SDN Honeypot Testing Instructions

This document provides instructions for testing the SDN honeypot system.

## System Overview

The SDN honeypot system consists of:

1. A Ryu SDN controller that manages network traffic
2. A machine learning model that classifies traffic as benign or malicious
3. A honeypot that simulates vulnerable services
4. A Mininet network with regular hosts and attackers

The system detects malicious traffic using the ML model and redirects it to the honeypot.

## Testing with the Large Topology

The large topology consists of:
- 2 core switches (s1, s2)
- 4 aggregation switches (s3, s4, s5, s6)
- 8 edge switches (s7-s14) 
- 14 regular hosts with web servers (h1-h14)
- 1 honeypot (h15)
- 4 external hosts/attackers (external1-external4)

### Starting the System

To start the system:

```bash
./start.sh
```

This will:
1. Train the ML model
2. Start the Ryu controller
3. Start the ML model service
4. Start the dashboard
5. Create the Mininet network with the large topology

### Running Attack Tests

Once the system is running, you can execute various attacks to test if the detection and redirection are working properly.

#### Using the Simple Attack Script

From the Mininet CLI, you can run the simple attack script from an external host:

```
mininet> external1 python3 /home/samet/Desktop/sdnhoney/simple_attack.py --target 10.0.0.1
```

Options for simple_attack.py:
- `--target IP`: Target IP address (default: 10.0.0.1)
- `--regular`: Test regular HTTP request
- `--attacks`: Test attack patterns
- `--portscan`: Test port scanning
- `--sustained`: Run sustained attack
- `--honeypot`: Test direct connection to honeypot
- `--all`: Run all tests (default)

#### Using the ML Attack Simulation

For more advanced attack simulation:

```
mininet> external1 python3 /home/samet/Desktop/sdnhoney/ml_attack_simulation.py --target 10.0.0.1
```

Options for ml_attack_simulation.py:
- `--target IP`: Target IP address 
- `--scan`: Perform port scan
- `--dos`: Perform HTTP request flood
- `--hopping`: Perform port hopping
- `--tcp-to-udp`: Send TCP to UDP ports
- `--udp-to-tcp`: Send UDP to TCP ports
- `--slow`: Perform low and slow attack
- `--structured`: Perform structured multi-stage attack (default)
- `--all`: Perform all attack types

### Verification

To verify if traffic is being redirected to the honeypot:

1. Watch the controller logs:
   ```
   tail -f logs/controller.log
   ```

2. Watch the honeypot logs:
   ```
   tail -f logs/host15_honeypot.log
   ```

3. Check the dashboard at http://localhost:5001

### Expected Behavior

- Regular, non-malicious traffic should reach the intended host
- Suspicious traffic detected by the ML model should be redirected to the honeypot
- The controller logs should show when traffic is redirected
- The honeypot logs should show incoming attack attempts

## Troubleshooting

- If the ML model is not detecting attacks, check if it was trained correctly
- If traffic is not being redirected, check the controller logs for errors
- If hosts are not reachable, check that they're running the web servers correctly

## Cleaning Up

Press Ctrl+C in the terminal running the Mininet CLI to stop the system. The script will automatically clean up all processes. 