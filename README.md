# SDN Honeypot Security System

This project implements a Software Defined Networking (SDN) environment with integrated honeypot systems and machine learning to detect and analyze suspicious traffic.

## Project Overview

The system creates a Mininet network with multiple hosts and a domain endpoint (smtkoca.com). At the controller level, it detects potentially malicious traffic and redirects it through a triage process using honeypots and machine learning.

### Key Features

- Tree topology network with depth = 3
- Ryu SDN controller with traffic classification and redirection
- Normal web servers with login panels
- Triage and Deep honeypots for detecting suspicious traffic
- Machine learning model to classify traffic as normal or malicious
- Monitoring dashboard with network visualization

## Project Structure

```
project/
│
├── controller/
│   └── controller.py         # Ryu SDN controller with traffic classification
│
├── topology/
│   └── topology.py           # Mininet network topology definition
│
├── honeypots/
│   ├── triage_honeypot/
│   │   └── app.py            # Triage honeypot with ML integration
│   └── deep_honeypot/
│       └── app.py            # Deep honeypot with extensive logging
│
├── servers/
│   ├── common/               # Shared web service code
│   │   ├── web_service.py
│   │   └── templates/        # HTML templates
│   ├── server1/
│   │   └── app.py            # Normal server 1
│   └── server2/
│       └── app.py            # Normal server 2
│
├── ml_model/
│   ├── simulate_model.py     # ML model simulator
│   ├── train_model.py        # ML model training pipeline
│   └── load_model.py         # ML model loader for predictions
│
├── dashboard/
│   ├── app.py                # Flask-based monitoring dashboard
│   ├── templates/            # Dashboard HTML templates
│   └── static/               # Dashboard static assets
│       └── js/
│           ├── dashboard.js
│           └── topology_visualization.js
│
└── logs/                     # Directory for storing logs
```

## Prerequisites

- Linux environment
- Python 3.6+
- Mininet
- Ryu SDN controller
- Flask (for web services and dashboard)
- Pandas, Scikit-learn (for ML model)

## Installation

1. Clone the repository:

   ```
   git clone https://github.com/yourusername/sdnhoney.git
   cd sdnhoney
   ```

2. Install the required packages:
   ```
   pip install ryu mininet flask pandas scikit-learn
   ```

## Usage

### Starting the Network

1. Start the Ryu controller:

   ```
   ryu-manager controller/controller.py
   ```

2. In a new terminal, start the Mininet topology:
   ```
   sudo python topology/topology.py
   ```

### Starting Web Services

After the network is up, start the web services on each host in the Mininet CLI:

```
mininet> server1 python /path/to/servers/server1/app.py &
mininet> server2 python /path/to/servers/server2/app.py &
mininet> triage_honeypot python /path/to/honeypots/triage_honeypot/app.py &
mininet> deep_honeypot python /path/to/honeypots/deep_honeypot/app.py &
```

### Accessing the Web Services

The web services will be accessible at `http://smtkoca.com` from your host machine or any machine that can reach the Mininet network.

### Starting the Dashboard

```
python dashboard/app.py
```

The dashboard will be accessible at `http://localhost:5000`.

### Training the ML Model

After collecting some logs, you can train the ML model:

```
python ml_model/train_model.py
```

The trained model will be saved to `ml_model/ml_model.pkl` and the scaler to `ml_model/scaler.pkl`. The triage honeypot will automatically use the trained model if available.

## Testing the System

1. Generate normal traffic by accessing the web login page and using valid credentials (for normal servers only).
2. Generate suspicious traffic by:
   - Making multiple rapid requests
   - Attempting multiple failed logins
   - Accessing multiple pages in a short time

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

This project was built based on the concepts of SDN security, honeypots, and machine learning for intrusion detection.
