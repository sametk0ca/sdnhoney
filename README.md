# Honeypot-based SDN Security Project

A Software Defined Networking (SDN) environment using Mininet and Ryu controller, integrated with honeypot systems and machine learning to detect and analyze suspicious traffic.

## 🏗️ Architecture

- **SDN Controller**: Ryu-based controller with intelligent traffic classification
- **Network Topology**: Tree topology (depth=3) with 7 switches and 6 hosts
- **Honeypots**: Triage and Deep honeypots for traffic analysis
- **ML Integration**: Machine learning model for behavioral analysis
- **Real-time Monitoring**: Traffic classification and redirection

## 🔧 Components

### Network Topology (`topology/`)
- Tree topology with depth=3
- 7 OpenFlow switches (s1-s7)
- 6 hosts: 3 normal servers, 1 triage honeypot, 1 deep honeypot, 1 client

### SDN Controller (`controller/`)
- Ryu-based OpenFlow controller
- Traffic classification (normal/suspicious/malicious)
- Load balancing for normal traffic
- Intelligent redirection to honeypots
- REST API for honeypot feedback

### Services (`servers/`, `honeypots/`)
- **Normal Servers**: Flask web services with valid authentication
- **Triage Honeypot**: Rejects all credentials, classifies traffic
- **Deep Honeypot**: Accepts all credentials, elaborate fake environment

### Machine Learning (`ml_model/`)
- Traffic behavior analysis
- Risk scoring and classification
- Feature extraction from honeypot logs

## 🚀 Quick Start

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Start Controller**
   ```bash
   source venv/bin/activate
   ryu-manager controller/controller.py --wsapi-port 8080
   ```

3. **Launch Network**
   ```bash
   sudo python3 topology/topology.py
   ```

4. **Test Services**
   ```bash
   # In Mininet CLI
   h6 curl http://10.0.0.1:8001/
   h6 curl http://10.0.0.4:8004/
   ```

## 📊 Features

- ✅ Real-time traffic classification
- ✅ Intelligent honeypot redirection  
- ✅ Machine learning integration
- ✅ Comprehensive logging
- ✅ REST API for monitoring
- ✅ Load balancing
- 🔄 Dashboard (in progress)

## 🛡️ Security Features

- **Traffic Analysis**: Behavioral pattern detection
- **Honeypot Deception**: Multi-layered honeypot system
- **ML Classification**: Automated threat detection
- **Real-time Response**: Dynamic traffic redirection

## 📝 Host Configuration

| Host | IP | Port | Type | Description |
|------|----|----- |------|-------------|
| h1 | 10.0.0.1 | 8001 | Normal Server | Web service with auth |
| h2 | 10.0.0.2 | 8002 | Normal Server | Web service with auth |
| h3 | 10.0.0.3 | 8003 | Normal Server | Web service with auth |
| h4 | 10.0.0.4 | 8004 | Triage Honeypot | Traffic classifier |
| h5 | 10.0.0.5 | 8005 | Deep Honeypot | Advanced deception |
| h6 | 10.0.0.6 | - | Client | Test traffic source |

## 🔄 Traffic Flow

1. **Normal Traffic** → Load balanced to h1, h2, h3
2. **Suspicious Traffic** → Redirected to h4 (triage honeypot)
3. **Malicious Traffic** → Redirected to h5 (deep honeypot)

## 📋 Requirements

- Python 3.8+
- Mininet 2.3+
- Ryu SDN Framework
- OpenVSwitch
- Flask
- scikit-learn

## 🧪 Testing

```bash
# Normal traffic test
h6 curl http://10.0.0.1:8001/

# Generate suspicious traffic
h6 for i in {1..50}; do curl -s http://10.0.0.1:8001/; done

# Test honeypots
h6 curl -X POST -d "username=admin&password=wrong" http://10.0.0.4:8004/login
```

## 📊 Monitoring

- Controller logs: Real-time traffic classification
- Honeypot logs: `/logs/` directory
- REST API: `http://localhost:8080/honeypot/stats`

## 🏛️ Project Structure

```
sdnhoney/
├── controller/          # Ryu SDN controller
├── topology/           # Mininet network topology
├── servers/            # Normal web servers
├── honeypots/          # Triage & deep honeypots
├── ml_model/           # Machine learning components
├── logs/               # System logs
└── requirements.txt    # Python dependencies
```

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Create Pull Request

## 📄 License

This project is for educational and research purposes. 