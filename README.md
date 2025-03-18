# ML-Based Honeypot for SDN Datacenters

## Overview

This project implements a **Machine Learning-based Honeypot** for **Software-Defined Networking (SDN) Datacenters**. The system monitors network traffic, detects potential threats, and dynamically responds to malicious activities using ML algorithms.

## Features

- **SDN Integration**: Works with OpenFlow-enabled switches.
- **Honeypot Mechanism**: Captures and analyzes attacker behavior.
- **Machine Learning**: Detects anomalies and classifies network threats.
- **Modular Design**: Easily extensible for new ML models and network configurations.

## Installation

Ensure you have **Python 3.9.7** installed and set up a virtual environment:

```sh
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

Start the controller with Ryu:

```sh
ryu-manager my_controller.py
```

Run the Mininet topology:

```sh
sudo python3 large_topo.py
```

## Dependencies

- Python 3.9.7 (For Ryu)
- Ryu SDN Framework
- Mininet
- Scikit-learn (for ML)
- Eventlet (for concurrency)

##
