# 🛡️ SDN Honeypot Security System

A comprehensive Software Defined Networking (SDN) security system with intelligent traffic analysis, ML-powered classification, and multi-layered honeypot deception. This project demonstrates real-time threat detection and automated traffic redirection in network environments.

## 🏗️ System Architecture

The system consists of **7 major components** working together to provide intelligent network security:

```
┌─────────────────────────────────────────────────────────────────┐
│                    SDN HONEYPOT SYSTEM                         │
├─────────────────────────────────────────────────────────────────┤
│  Dashboard (8090) ←→ Controller (8080) ←→ ML Model             │
│         ↕                    ↕                    ↕              │
│  Real-time Stats      Traffic Analysis     Classification       │
├─────────────────────────────────────────────────────────────────┤
│                    Mininet Topology                            │
│  h6 (Client) → s1 → [s2,s3] → [s4,s5,s6,s7] → [h1,h2,h3,h4,h5] │
│                                                                 │
│  Normal Servers: h1, h2, h3 (Load Balanced)                   │
│  Triage Honeypot: h4 (ML Classification)                      │
│  Deep Honeypot: h5 (Advanced Deception)                       │
└─────────────────────────────────────────────────────────────────┘
```

## 🔧 Components Overview

### 1. 🎮 SDN Controller (`controller/controller.py`)

**Advanced Ryu-based OpenFlow controller with intelligent traffic management**

#### Key Features:
- **Real-time Traffic Classification**: Analyzes packet patterns for threat detection
- **ML Integration**: Receives binary classifications (1=malicious, 0=benign) from honeypots
- **Dynamic Flow Installation**: Creates bidirectional flows for seamless redirection
- **Load Balancing**: Round-robin distribution across normal servers
- **Baseline Active IPs**: Maintains 6 active IPs for monitoring (all hosts)

#### Traffic Flow Logic:
```python
# Classification Logic
if classification == 'malicious':
    target = Deep_Honeypot     # h5 (10.0.0.5)
elif classification == 'suspicious':
    target = Triage_Honeypot   # h4 (10.0.0.4)
else:
    target = Normal_Server     # h1,h2,h3 (load balanced)
```

#### REST API Endpoints:
- `GET /api/stats` - System statistics
- `POST /honeypot/classification` - Receive ML classifications
- Traffic analysis with persistent IP tracking

### 2. 📊 Real-time Dashboard (`dashboard/app.py`)

**Flask-based monitoring dashboard with live statistics**

#### Features:
- **Live Traffic Monitoring**: Real-time active IP count and flow statistics
- **Threat Visualization**: Suspicious and malicious IP tracking
- **Service Status**: Health monitoring for all network components
- **Interactive Topology**: Visual network representation
- **Historical Data**: Traffic patterns and classification trends

#### Dashboard Endpoints:
- `http://localhost:8090` - Main dashboard interface
- `/api/host_status` - Service health check
- `/api/traffic_history` - Historical traffic data
- `/api/honeypot_alerts` - Security alerts from honeypots

### 3. 🖥️ Normal Servers (`servers/server1,2,3/app.py`)

**Legitimate web services with proper authentication**

#### Characteristics:
- **Valid Credentials**: Accept legitimate user logins
- **Full Web Interface**: Login forms, admin panels, logout functionality
- **Comprehensive Logging**: Track all access attempts
- **Health Endpoints**: `/health` for service monitoring

#### Valid Credentials:
```python
VALID_CREDENTIALS = {
    'admin': 'password123',
    'user': 'userpass', 
    'john': 'johnpass'
}
```

### 4. 🍯 Triage Honeypot (`honeypots/triage_honeypot/app.py`)

**ML-powered initial classification honeypot**

#### Core Function:
- **Rejects All Credentials**: No valid logins accepted
- **ML Integration**: Uses simplified ML model for traffic analysis
- **Real-time Classification**: Analyzes each request and sends results to controller
- **Binary Decision Making**: Returns 1 (malicious) or 0 (benign)

#### ML Classification Process:
```python
def analyze_traffic_with_ml(source_ip, username=None):
    # Prepare features for ML model
    request_data = {
        'username': username,
        'user_agent': request.headers.get('User-Agent'),
        'failed_attempts': failed_attempts[source_ip]
    }
    
    # Get ML prediction (1 or 0)
    ml_prediction, risk_score = classify_traffic(source_ip, request_data)
    
    # Send to controller for traffic redirection
    send_to_controller(classification, source_ip, risk_score, ml_prediction)
```

### 5. 🕳️ Deep Honeypot (`honeypots/deep_honeypot/app.py`)

**Advanced deception environment for malicious actors**

#### Features:
- **Accepts All Credentials**: Successful login with any credentials
- **Elaborate Fake Environment**: Realistic admin panels and system interfaces
- **Advanced Logging**: Detailed capture of all malicious activities
- **Prolonged Engagement**: Keeps attackers engaged for analysis

### 6. 🤖 ML Classification Model (`ml_model/simulate_model.py`)

**Simplified machine learning model for binary threat classification**

#### Risk Score Calculation:
```python
risk_score = 0.0

# Request Frequency Analysis
if request_frequency > 15:      # 15+ requests in 5 minutes
    risk_score += 0.4           # +40% risk
elif request_frequency > 5:     # 5+ requests in 5 minutes
    risk_score += 0.2           # +20% risk

# Rapid Fire Detection
if request_frequency > 10:      # Rapid succession
    risk_score += 0.3           # +30% risk

# Suspicious Username Detection
attack_usernames = ['admin', 'root', 'administrator', 'test', 'guest']
if username in attack_usernames:
    risk_score += 0.3           # +30% risk

# Bot/Scanner Detection
bot_agents = ['curl', 'wget', 'python', 'bot', 'scanner', 'exploit']
if any(bot in user_agent):
    risk_score += 0.2           # +20% risk

# Classification Decision
ml_prediction = 1 if risk_score >= 0.6 else 0  # 60% threshold
```

#### Features:
- **Feature Extraction**: Username, user agent, request patterns
- **Consistent Classification**: IP-based behavior tracking
- **Binary Output**: 1 (malicious) or 0 (benign)
- **Risk Score**: 0.0-1.0 confidence level

### 7. 🌐 Network Topology (`topology/topology.py`)

**Mininet tree topology with depth=3**

#### Network Structure:
```
                s1 (Root)
               /         \
            s2              s3
           / \             / \
         s4   s5         s6   s7
        /|    |         |    |\
      h1 h6  h2        h3   h4 h5
```

#### Host Configuration:
| Host | IP Address | Port | Type | Purpose |
|------|------------|------|------|---------|
| h1 | 10.0.0.1 | 8001 | Normal Server | Web service with authentication |
| h2 | 10.0.0.2 | 8002 | Normal Server | Web service with authentication |
| h3 | 10.0.0.3 | 8003 | Normal Server | Web service with authentication |
| h4 | 10.0.0.4 | 8004 | Triage Honeypot | ML-powered traffic classifier |
| h5 | 10.0.0.5 | 8005 | Deep Honeypot | Advanced deception environment |
| h6 | 10.0.0.6 | - | External Client | Simulates external traffic |

## 🔄 Traffic Flow & Classification Logic

### Step-by-Step Process:

1. **Initial Request**: h6 → h1/h2/h3 (normal server)
2. **Controller Analysis**: Packet inspection and initial classification
3. **Redirection Decision**:
   - **Normal**: Continue to requested server
   - **Suspicious**: Redirect to Triage Honeypot (h4)
   - **Malicious**: Redirect to Deep Honeypot (h5)

4. **Triage Honeypot Processing** (if suspicious):
   - Analyze request with ML model
   - Generate risk score (0.0-1.0)
   - Return binary classification (1 or 0)
   - Send results to controller

5. **Dynamic Classification Update**:
   - ML = 1 → Mark IP as malicious → Future requests → Deep Honeypot
   - ML = 0 → Keep current classification

### Example Scenarios:

**Scenario 1: Normal User**
```bash
h6 curl -X POST -d "username=john&password=johnpass" http://10.0.0.1:8001/
# Result: Successful login to normal server
```

**Scenario 2: Suspicious Activity**
```bash
h6 curl -X POST -d "username=admin&password=wrong" http://10.0.0.1:8001/
# Result: Redirected to triage honeypot → ML analysis → Classification
```

**Scenario 3: Automated Attack**
```bash
h6 curl -X POST -d "username=admin" http://10.0.0.1:8001/ --user-agent "curl/7.68.0"
# Result: High risk score → ML=1 → Malicious → Deep honeypot
```

## 🚀 Installation & Setup

### Prerequisites
```bash
# Install system dependencies
sudo apt update
sudo apt install python3 python3-pip python3-venv
sudo apt install mininet openvswitch-switch

# Install Ryu SDN framework
pip3 install ryu
```

### Project Setup
```bash
# Clone and setup project
git clone <repository-url>
cd sdnhoney

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

## 🎮 Running the System

### Method 1: Automated Startup
```bash
source venv/bin/activate
./start_system.sh
```

### Method 2: Manual Component Start

**Terminal 1 - SDN Controller:**
```bash
source venv/bin/activate
ryu-manager controller/controller.py --wsapi-port 8080 --observe-links --verbose
```

**Terminal 2 - Dashboard:**
```bash
source venv/bin/activate
cd dashboard && python3 app.py
```

**Terminal 3 - Network Topology:**
```bash
cd topology
sudo python3 topology.py
```

## 📊 System Monitoring

### Dashboard Access
- **Main Dashboard**: http://localhost:8090
- **Presentation**: http://localhost:9000
- **Controller API**: http://localhost:8080/api/stats

### Real-time Statistics
```bash
# Check controller stats
curl -s http://localhost:8080/api/stats | python3 -m json.tool

# Check dashboard stats  
curl -s http://localhost:8090/api/stats | python3 -m json.tool

# Monitor honeypot activity
tail -f logs/triage_honeypot.log
```

### System Status Check
```bash
./check_status.sh
```

## 🧪 Testing & Demo

### Basic Connectivity Test
```bash
# In Mininet CLI
mininet> pingall
mininet> iperf h1 h6
```

### Traffic Classification Tests

**Test 1: Normal Traffic**
```bash
mininet> h6 curl -X POST -d "username=john&password=johnpass" http://10.0.0.1:8001/
# Expected: Success, normal server response
```

**Test 2: Suspicious Username**
```bash
mininet> h6 curl -X POST -d "username=admin&password=test" http://10.0.0.1:8001/
# Expected: Redirect to triage honeypot
```

**Test 3: Automated Bot Attack**
```bash
mininet> h6 curl -X POST -d "username=admin" http://10.0.0.1:8001/ -A "curl/7.68.0"
# Expected: High risk score → Malicious classification
```

**Test 4: Rapid Fire Attack**
```bash
mininet> h6 bash -c 'for i in {1..20}; do curl -s -X POST -d "username=admin" http://10.0.0.1:8001/; done'
# Expected: Frequency-based malicious classification
```

## 📈 Performance Metrics

### Current Capabilities:
- **Active IP Tracking**: 6 baseline hosts + dynamic additions
- **Real-time Classification**: < 1 second response time
- **Concurrent Connections**: Supports multiple simultaneous attacks
- **Flow Rule Efficiency**: Bidirectional flows with 600s timeout
- **ML Processing**: Real-time feature extraction and classification

### Monitoring Data:
- Active IPs count
- Suspicious IP list
- Malicious IP list  
- Flow count statistics
- Request patterns and frequency

## 🗂️ Project Structure

```
sdnhoney/
├── 🎮 controller/
│   └── controller.py           # Main SDN controller
├── 📊 dashboard/
│   ├── app.py                  # Real-time monitoring dashboard
│   ├── templates/              # HTML templates
│   └── static/                 # CSS, JS assets
├── 🖥️ servers/
│   ├── server1/app.py          # Normal server 1
│   ├── server2/app.py          # Normal server 2  
│   └── server3/app.py          # Normal server 3
├── 🍯 honeypots/
│   ├── triage_honeypot/app.py  # ML-powered classifier
│   └── deep_honeypot/app.py    # Advanced deception
├── 🤖 ml_model/
│   └── simulate_model.py       # Binary classification model
├── 🌐 topology/
│   └── topology.py             # Mininet network setup
├── 📝 logs/                    # System logs
├── 🔧 scripts/
│   ├── start_system.sh         # Automated startup
│   ├── stop_system.sh          # Clean shutdown
│   └── check_status.sh         # System health check
└── 📋 requirements.txt         # Python dependencies
```

## 🛡️ Security Features

### Threat Detection
- **Behavioral Analysis**: Pattern recognition in user requests
- **ML Classification**: Automated threat scoring
- **Real-time Response**: Immediate traffic redirection
- **Persistent Tracking**: IP-based behavior monitoring

### Deception Techniques
- **Transparent Redirection**: Attackers unaware of honeypot interaction
- **Layered Honeypots**: Triage → Deep honeypot progression
- **Realistic Environments**: Authentic-looking services and responses

### Logging & Analysis
- **Comprehensive Logs**: All interactions recorded
- **JSON Format**: Structured data for analysis
- **Real-time Updates**: Live classification updates
- **Historical Tracking**: Long-term pattern analysis

## 🔮 Future Enhancements

- [ ] **Advanced ML Models**: Deep learning for better classification
- [ ] **Database Integration**: Persistent storage for analysis
- [ ] **Alert System**: Email/SMS notifications for critical threats
- [ ] **Geographic Analysis**: IP geolocation and reputation scoring
- [ ] **Automated Response**: Dynamic firewall rule generation
- [ ] **Multi-tenancy**: Support for multiple network segments

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📄 License

This project is for **educational and research purposes** only. Not intended for production deployment without proper security review.

## 🙏 Acknowledgments

- **Ryu SDN Framework** - OpenFlow controller foundation
- **Mininet** - Network emulation platform
- **Flask** - Web application framework
- **scikit-learn** - Machine learning tools

---

**⚡ Quick Start**: `source venv/bin/activate && ./start_system.sh`

**📊 Dashboard**: http://localhost:8090

**🔍 API**: http://localhost:8080/api/stats
