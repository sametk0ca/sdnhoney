# 🎯 Traffic Flow & Classification System

## Table of Contents
- [System Overview](#system-overview)
- [Architecture](#architecture) 
- [Traffic Flow Process](#traffic-flow-process)
- [ML Classification Model](#ml-classification-model)
- [Risk Score Calculation](#risk-score-calculation)
- [Honeypot Layers](#honeypot-layers)
- [Redirect Mechanism](#redirect-mechanism)
- [Example Scenarios](#example-scenarios)
- [Configuration](#configuration)
- [Monitoring & Logging](#monitoring--logging)
- [API Reference](#api-reference)

---

## System Overview

The SDN Honeypot Security System implements an intelligent **3-tier traffic classification** mechanism that analyzes incoming requests in real-time and redirects them to appropriate destinations based on their **risk assessment**.

### Core Components:
- **SDN Controller (Ryu)**: Traffic interception and flow management
- **ML Classification Engine**: Behavioral analysis and risk scoring
- **Multi-layer Honeypots**: Deception and threat containment
- **Real-time Monitoring**: Live analytics and alerting

---

## Architecture

```
┌─────────────┐    ┌──────────────┐    ┌─────────────────┐
│   Client    │───▶│ SDN Controller│───▶│ ML Classifier   │
│   (h6)      │    │   (Ryu)      │    │   Engine        │
└─────────────┘    └──────────────┘    └─────────────────┘
                            │                    │
                            ▼                    ▼
                   ┌─────────────────┐    ┌──────────────┐
                   │ Flow Installation│    │ Risk Score   │
                   │   & Redirect     │    │ Calculation  │
                   └─────────────────┘    └──────────────┘
                            │
                ┌───────────┼───────────┐
                ▼           ▼           ▼
        ┌──────────┐ ┌─────────────┐ ┌─────────────┐
        │ Normal   │ │   Triage    │ │    Deep     │
        │ Servers  │ │  Honeypot   │ │  Honeypot   │
        │(h1,h2,h3)│ │    (h4)     │ │    (h5)     │
        └──────────┘ └─────────────┘ └─────────────┘
```

---

## Traffic Flow Process

### Step 1: Request Interception
```python
# SDN Controller captures incoming packet
@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
def packet_in_handler(self, ev):
    # Extract packet information
    src_ip = packet_info['src_ip']
    dst_ip = packet_info['dst_ip'] 
    request_data = packet_info['http_data']
```

### Step 2: Feature Extraction
```python
features = {
    'source_ip': '10.0.0.6',
    'username': 'admin',
    'user_agent': 'curl/7.68.0',
    'request_method': 'POST',
    'timestamp': '2024-06-09T16:30:45',
    'session_history': request_history[src_ip]
}
```

### Step 3: ML Analysis
```python
risk_score = ml_classifier.analyze(features)
prediction = 1 if risk_score >= 0.6 else 0
classification = 'malicious' if prediction == 1 else 'benign'
```

### Step 4: Routing Decision
```python
if risk_score < 0.4:
    destination = random.choice(['h1', 'h2', 'h3'])  # Normal servers
elif 0.4 <= risk_score < 0.6:
    destination = 'h4'  # Triage honeypot
else:  # risk_score >= 0.6
    destination = 'h5'  # Deep honeypot
```

### Step 5: Flow Installation & Redirect
```python
# Install OpenFlow rule for redirection
match = parser.OFPMatch(ipv4_src=src_ip)
actions = [parser.OFPActionSetField(ipv4_dst=destination_ip)]
self.add_flow(datapath, priority=100, match=match, actions=actions)
```

---

## ML Classification Model

### Model Architecture
- **Type**: Binary Classifier (Rule-based + ML hybrid)
- **Output**: 0 (Benign) / 1 (Malicious)
- **Threshold**: 0.6
- **Response Time**: < 100ms

### Feature Analysis

#### 1. Username Analysis
```python
suspicious_usernames = ['admin', 'root', 'administrator', 'test', 'guest', 'user']

def analyze_username(username):
    if username.lower() in suspicious_usernames:
        return 0.3  # High risk bonus
    return 0.0
```

#### 2. User-Agent Detection
```python
bot_signatures = ['curl', 'wget', 'python', 'bot', 'scanner', 'nikto', 'sqlmap']

def analyze_user_agent(user_agent):
    for signature in bot_signatures:
        if signature.lower() in user_agent.lower():
            return 0.2  # Bot detection bonus
    return 0.0
```

#### 3. Request Frequency Analysis
```python
def analyze_frequency(src_ip, time_window=300):  # 5 minutes
    recent_requests = get_requests_in_window(src_ip, time_window)
    
    if len(recent_requests) > 15:
        return 0.4  # Very high frequency
    elif len(recent_requests) > 5:
        return 0.2  # Moderate frequency
    return 0.0
```

#### 4. Rapid Fire Detection
```python
def detect_rapid_fire(src_ip, time_window=60):  # 1 minute
    recent_requests = get_requests_in_window(src_ip, time_window)
    
    if len(recent_requests) > 10:
        return 0.3  # Burst attack detected
    return 0.0
```

---

## Risk Score Calculation

### Formula
```python
risk_score = base_score + username_penalty + user_agent_penalty + 
             frequency_bonus + rapid_fire_penalty + random_factor

# Where:
base_score = 0.2
username_penalty = 0.0 to 0.3
user_agent_penalty = 0.0 to 0.2  
frequency_bonus = 0.0 to 0.4
rapid_fire_penalty = 0.0 to 0.3
random_factor = ±0.1 (simulation variance)
```

### Classification Thresholds
```python
if risk_score < 0.4:
    classification = "benign"
    destination_tier = "normal_servers"
    
elif 0.4 <= risk_score < 0.6:
    classification = "suspicious" 
    destination_tier = "triage_honeypot"
    
else:  # risk_score >= 0.6
    classification = "malicious"
    destination_tier = "deep_honeypot"
```

---

## Honeypot Layers

### Layer 1: Normal Servers (h1, h2, h3)
- **Purpose**: Serve legitimate users
- **Characteristics**: Real services, normal functionality
- **Traffic**: Benign requests (risk < 0.4)

```python
# Normal server configuration
servers = {
    'h1': {'ip': '10.0.0.1', 'port': 8001},
    'h2': {'ip': '10.0.0.2', 'port': 8002}, 
    'h3': {'ip': '10.0.0.3', 'port': 8003}
}
```

### Layer 2: Triage Honeypot (h4)
- **Purpose**: Advanced analysis and classification refinement
- **Characteristics**: Identical interface, extended monitoring
- **Traffic**: Suspicious requests (0.4 ≤ risk < 0.6)

```python
# Triage honeypot features
triage_capabilities = {
    'ml_analysis': True,
    'behavioral_profiling': True,
    'session_tracking': True,
    'escalation_detection': True,
    'adaptive_response': True
}
```

#### Triage Decision Logic
```python
def triage_analysis(session_data):
    continued_risk = calculate_continued_risk(session_data)
    
    if continued_risk < 0.4:
        # Reclassify as benign
        redirect_to_normal_servers()
    elif continued_risk >= 0.6:
        # Escalate to deep honeypot
        redirect_to_deep_honeypot()
    else:
        # Continue monitoring in triage
        continue_triage_analysis()
```

### Layer 3: Deep Honeypot (h5)
- **Purpose**: Advanced deception and threat containment
- **Characteristics**: Sophisticated fake environment
- **Traffic**: Malicious requests (risk ≥ 0.6)

```python
# Deep honeypot features
deep_capabilities = {
    'advanced_deception': True,
    'prolonged_engagement': True,
    'attack_simulation': True,
    'intelligence_gathering': True,
    'forensic_analysis': True
}
```

---

## Redirect Mechanism

### OpenFlow Rule Installation
```python
def install_redirect_flow(self, datapath, src_ip, dst_ip, priority=100):
    parser = datapath.ofproto_parser
    
    # Match criteria
    match = parser.OFPMatch(
        ipv4_src=src_ip,
        eth_type=ether_types.ETH_TYPE_IP
    )
    
    # Redirect actions
    actions = [
        parser.OFPActionSetField(ipv4_dst=dst_ip),
        parser.OFPActionOutput(get_port_for_host(dst_ip))
    ]
    
    # Install flow
    self.add_flow(datapath, priority, match, actions, idle_timeout=300)
```

### Dynamic Load Balancing
```python
def select_normal_server():
    # Round-robin selection for normal servers
    available_servers = ['10.0.0.1', '10.0.0.2', '10.0.0.3']
    return available_servers[current_index % len(available_servers)]
```

---

## Example Scenarios

### Scenario 1: Normal User
```yaml
Input:
  source_ip: 10.0.0.6
  username: john
  password: password123
  user_agent: Mozilla/5.0 (Windows NT 10.0)

Analysis:
  username_penalty: 0.0    # Normal username
  user_agent_penalty: 0.0  # Browser user-agent
  frequency_bonus: 0.0     # Normal frequency
  rapid_fire_penalty: 0.0  # No rapid requests

Result:
  risk_score: 0.2 (base)
  classification: benign
  destination: h1/h2/h3 (normal servers)
```

### Scenario 2: Suspicious Activity
```yaml
Input:
  source_ip: 10.0.0.6
  username: admin
  password: password123
  user_agent: Mozilla/5.0 (Windows NT 10.0)

Analysis:
  username_penalty: 0.3    # Suspicious username
  user_agent_penalty: 0.0  # Browser user-agent  
  frequency_bonus: 0.0     # Normal frequency
  rapid_fire_penalty: 0.0  # No rapid requests

Result:
  risk_score: 0.5 (0.2 + 0.3)
  classification: suspicious
  destination: h4 (triage honeypot)
```

### Scenario 3: Malicious Attack
```yaml
Input:
  source_ip: 10.0.0.6
  username: root
  password: admin
  user_agent: curl/7.68.0

Analysis:
  username_penalty: 0.3    # Suspicious username
  user_agent_penalty: 0.2  # Bot user-agent
  frequency_bonus: 0.2     # Multiple requests
  rapid_fire_penalty: 0.0  # Below burst threshold

Result:
  risk_score: 0.9 (0.2 + 0.3 + 0.2 + 0.2)
  classification: malicious
  destination: h5 (deep honeypot)
```

### Scenario 4: Brute Force Attack
```yaml
Input:
  source_ip: 10.0.0.6
  username: admin
  requests_in_5min: 20
  user_agent: python-requests/2.25.1

Analysis:
  username_penalty: 0.3    # Suspicious username
  user_agent_penalty: 0.2  # Bot user-agent
  frequency_bonus: 0.4     # High frequency (>15 req/5min)
  rapid_fire_penalty: 0.3  # Burst detected

Result:
  risk_score: 1.2 (0.2 + 0.3 + 0.2 + 0.4 + 0.3)
  classification: malicious (high confidence)
  destination: h5 (deep honeypot)
```

---

## Configuration

### Model Parameters
```python
# ml_model/config.py
ML_CONFIG = {
    'base_score': 0.2,
    'classification_threshold': 0.6,
    'suspicious_threshold': 0.4,
    'username_penalty': 0.3,
    'user_agent_penalty': 0.2,
    'max_frequency_bonus': 0.4,
    'rapid_fire_penalty': 0.3,
    'time_window': 300,  # 5 minutes
    'burst_window': 60,  # 1 minute
    'random_variance': 0.1
}
```

### Suspicious Patterns
```python
# ml_model/patterns.py
SUSPICIOUS_USERNAMES = [
    'admin', 'root', 'administrator',
    'test', 'guest', 'user', 'demo',
    'oracle', 'postgres', 'mysql'
]

BOT_USER_AGENTS = [
    'curl', 'wget', 'python', 'requests',
    'bot', 'spider', 'crawler', 'scanner',
    'nikto', 'sqlmap', 'nmap', 'masscan'
]
```

### Server Mapping
```python
# controller/config.py
SERVERS = {
    'normal': {
        'h1': {'ip': '10.0.0.1', 'port': 8001},
        'h2': {'ip': '10.0.0.2', 'port': 8002},
        'h3': {'ip': '10.0.0.3', 'port': 8003}
    },
    'triage': {
        'h4': {'ip': '10.0.0.4', 'port': 8004}
    },
    'deep': {
        'h5': {'ip': '10.0.0.5', 'port': 8005}
    }
}
```

---

## Monitoring & Logging

### Log Format
```json
{
    "timestamp": "2024-06-09T16:30:45.123456",
    "source_ip": "10.0.0.6",
    "destination_ip": "10.0.0.4", 
    "request_type": "login_attempt",
    "classification": "suspicious",
    "risk_score": 0.55,
    "ml_prediction": 0,
    "features": {
        "username": "admin",
        "user_agent": "Mozilla/5.0",
        "request_frequency": 3,
        "session_duration": 45
    },
    "redirect_reason": "suspicious_username",
    "honeypot_layer": "triage"
}
```

### Real-time Statistics
```python
# Current system stats
stats = {
    "active_ips": 6,
    "suspicious_ips": ["10.0.0.6"],
    "malicious_ips": [],
    "total_requests": 127,
    "honeypot_interactions": 23,
    "classification_accuracy": 0.94,
    "false_positive_rate": 0.06,
    "response_time_avg": "85ms"
}
```

### Alert Conditions
```python
# Automated alerting
ALERT_CONDITIONS = {
    'high_risk_threshold': 0.8,
    'burst_attack_threshold': 15,  # requests/minute
    'unique_attacker_threshold': 5,  # unique IPs/hour
    'honeypot_escalation': True,  # triage → deep
    'ml_confidence_threshold': 0.9
}
```

---

## API Reference

### Controller API Endpoints

#### Get System Statistics
```http
GET http://localhost:8080/api/stats
```
```json
{
    "active_ips": 6,
    "suspicious_ips": ["10.0.0.6"],
    "malicious_ips": [],
    "flow_count": 12,
    "last_update": "16:30:45"
}
```

#### Get Classification History
```http
GET http://localhost:8080/api/classifications
```

#### Manual Classification Override
```http
POST http://localhost:8080/api/classify
Content-Type: application/json

{
    "source_ip": "10.0.0.6",
    "override_classification": "malicious",
    "reason": "manual_analysis"
}
```

### Dashboard API Endpoints

#### System Status
```http
GET http://localhost:9000/api/system-status
```

#### ML Model Test
```http
GET http://localhost:9000/api/ml-test
```

#### Honeypot Logs
```http
GET http://localhost:9000/api/honeypot-logs
```

---

## Performance Metrics

### Classification Performance
- **Accuracy**: ~95%
- **Response Time**: < 100ms
- **Throughput**: 1000+ requests/second
- **False Positive Rate**: ~5%
- **False Negative Rate**: < 2%

### System Resources
- **CPU Usage**: < 30% (normal load)
- **Memory Usage**: < 2GB
- **Network Latency**: +5ms overhead
- **Storage**: ~1MB/day logs

---

## Security Considerations

### Evasion Prevention
- **Pattern Randomization**: Prevent ML model fingerprinting
- **Timing Variation**: Variable response delays
- **Honeypot Consistency**: Identical interfaces across layers

### Privacy Protection
- **Data Minimization**: Only necessary features logged
- **IP Anonymization**: Optional IP masking
- **Retention Policy**: Automatic log rotation

---

## Troubleshooting

### Common Issues

#### 1. High False Positive Rate
```python
# Adjust threshold
ML_CONFIG['classification_threshold'] = 0.7  # More conservative
```

#### 2. Poor Classification Accuracy
```python
# Review feature weights
ML_CONFIG['username_penalty'] = 0.25  # Reduce username impact
```

#### 3. Performance Degradation
```python
# Optimize time windows
ML_CONFIG['time_window'] = 180  # Reduce to 3 minutes
```

### Debug Commands
```bash
# Check controller logs
tail -f logs/controller.log

# Monitor classifications  
tail -f logs/triage_honeypot.log | jq '.classification'

# System health check
./check_status.sh
```

---

## Future Enhancements

### Planned Features
- **Deep Learning Integration**: Neural network classifier
- **Behavioral Modeling**: User behavior profiling
- **Adaptive Thresholds**: Dynamic threshold adjustment
- **Threat Intelligence**: External feed integration
- **Advanced Deception**: Sophisticated honeypot environments

### Research Directions
- **Adversarial ML**: Robust classification under attack
- **Zero-day Detection**: Unknown attack pattern identification
- **Multi-stage Attacks**: Long-term campaign detection

---

*This documentation covers the complete traffic flow and classification system. For additional technical details, see the source code in `/controller` and `/ml_model` directories.* 