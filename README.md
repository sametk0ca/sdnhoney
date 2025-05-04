# SDN-based Honeypot System

This project implements an intelligent SDN-based honeypot system that uses machine learning to detect malicious traffic and redirect it to a honeypot for further analysis.

## System Architecture

The system consists of several components:

1. **SDN Controller**: A Ryu-based controller that makes decisions about packet routing based on ML model predictions
2. **Machine Learning Service**: Analyzes packet data to predict if traffic is malicious
3. **HTTP Honeypot**: A custom HTTP honeypot that simulates vulnerable web applications
4. **Mininet Network**: Provides the virtualized network infrastructure
5. **Dashboard**: Web-based dashboard for monitoring system activity

## Requirements

- Python 3.7 or newer
- Mininet
- Open vSwitch
- Ryu SDN Controller

## Installation

Clone the repository and set up the required dependencies:

```bash
# Install system dependencies
sudo apt update
sudo apt install -y mininet python3-pip openvswitch-switch

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

## Project Structure

```
sdnhoney/
├── controller/            # SDN controller code
│   ├── my_controller.py   # Main controller logic
│   └── flow_rules.py      # Flow rule definitions
├── ml_model/              # Machine learning model and service
│   ├── model_service.py   # gRPC service for ML predictions
│   ├── train_model.py     # Model training script
│   └── generate_dataset.py # Dataset generation tool
├── honeypot/              # Honeypot configuration and services
│   └── http_honeypot.py   # Simple HTTP honeypot implementation
├── dashboard/             # Web-based monitoring dashboard
│   ├── app.py             # Flask-based dashboard backend
│   └── templates/         # Dashboard HTML templates
├── proto/                 # Protocol buffer definitions for gRPC
├── topology/              # Mininet topology definition
│   └── large_topo.py      # Network topology setup
├── server/                # Web server implementations
│   └── real_web_server.py # Actual web server for testing
├── logs/                  # System logs directory
├── start.sh               # Main startup script
├── ml_attack_simulation.py # Script to simulate attacks
└── requirements.txt       # Python dependencies
```

## Getting Started

1. Start the entire system:

```bash
./start.sh
```

This will start the Ryu controller, Mininet network, ML model service, and deploy the honeypot.

2. To generate attack traffic for testing:

```bash
python ml_attack_simulation.py
```

3. Access the dashboard at http://localhost:5000 to monitor system activity.

## Features

- **Intelligent Traffic Analysis**: Uses machine learning to identify suspicious traffic patterns
- **Dynamic Traffic Redirection**: Suspicious traffic is automatically redirected to the honeypot
- **Real-time Monitoring**: Web-based dashboard provides visibility into system activity
- **Deterministic Testing Mode**: Allows for reproducible testing with pre-defined traffic patterns
- **HTTP Honeypot**: Custom implementation for capturing and analyzing suspicious HTTP traffic

## System Architecture Diagram

```
                            +---------------+
                            |    Dashboard  |
                            +-------^-------+
                                    |
                                    |
+----------------+          +-------v-------+         +-----------------+
| Mininet Network|<-------->| SDN Controller|<------->| ML Model Service|
+----------------+          +---------------+         +-----------------+
        |                          |
        |                          |
+-------v-------+          +-------v-------+
|  Web Servers  |          |    Honeypot   |
+---------------+          +---------------+
```

## License

[MIT License]

## Acknowledgements

This project was developed as a research project for network security using SDN principles.
