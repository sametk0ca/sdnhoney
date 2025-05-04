# SDN-based Honeypot System

This project implements an intelligent SDN-based honeypot system that uses machine learning to detect malicious traffic and redirect it to a honeypot for further analysis.

## System Architecture

The system consists of several components:

1. **SDN Controller**: A Ryu-based controller that makes decisions about packet routing based on ML model predictions
2. **Machine Learning Service**: Analyzes packet data to predict if traffic is malicious
3. **Honeypot**: A Glastopf-based honeypot that simulates vulnerable web applications
4. **Mininet Network**: Provides the virtualized network infrastructure

## Requirements

- Python 3.7 or newer
- Mininet
- Open vSwitch
- Ryu SDN Controller
- Glastopf Honeypot

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
├── controller/          # SDN controller code
│   └── my_controller.py # Main controller logic
├── ml_model/            # Machine learning model and service
│   └── model_service.py # gRPC service for ML predictions
├── honeypot/            # Honeypot configuration and services
├── large_topo.py        # Mininet topology definition
├── deploy_services.py   # Script to deploy services in Mininet
├── test_system.py       # System testing utilities
├── start_system.py      # Main startup script
└── requirements.txt     # Python dependencies
```

## Getting Started

1. Install and configure the Glastopf honeypot:

```bash
# Clone the Glastopf repository (if not already cloned)
git clone https://github.com/mushorg/glastopf.git

# Run the installation script
./scripts/install_honeypot.sh
```

2. Start the entire system:

```bash
python start_system.py
```

This will start the Ryu controller, Mininet network, ML model service, and deploy the honeypot.

2. To start only specific components:

```bash
# Start only the controller
python start_system.py --controller-only

# Start only Mininet
python start_system.py --mininet-only

# Start only the ML service
python start_system.py --ml-only

# Start only the honeypot
python start_system.py --honeypot-only
```

3. Test the system:

```bash
python test_system.py
```

## Command-line Options

The `start_system.py` script accepts several command-line arguments:

- `--topology`: Specify the topology file to use (default: `large_topo.py`)
- `--controller-ip`: Controller IP address (default: `127.0.0.1`)
- `--controller-port`: Controller port (default: `6653`)
- `--ml-ip`: ML service IP address (default: `127.0.0.1`)
- `--ml-port`: ML service port (default: `50051`)
- `--honeypot-host`: Honeypot host in Mininet (default: `h8`)
- `--ml-host`: ML model host in Mininet (default: `h1`)

## System Testing

The `test_system.py` script verifies that all components are functioning correctly:

```bash
python test_system.py
```

## License

[License Information]

## Acknowledgements

This project was developed as a capstone project for [Your Institution/Course].
