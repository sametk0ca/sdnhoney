# 🚀 SDN Honeypot - Quick Start Guide

## One-Command System Startup

### 🎯 Start Everything

```bash
./start_system.sh
```

This single command will:

1. ✅ Clean previous Mininet instances (`sudo mn -c`)
2. ✅ Start SDN Controller (Ryu on ports 6653 & 8080)
3. ✅ Create and start Monitoring Dashboard (port 8090)
4. ✅ Start Presentation Website (port 9000)
5. ✅ Start Network Topology with all services (ports 8001-8005)

### 🛑 Stop Everything

```bash
./stop_system.sh
```

This will cleanly stop all components and clean up processes.

---

## 🌐 Access URLs

Once started, you can access:

| Service             | URL                              | Description                    |
| ------------------- | -------------------------------- | ------------------------------ |
| **Presentation**    | http://localhost:9000            | Academic presentation website  |
| **Dashboard**       | http://localhost:8090            | Real-time monitoring dashboard |
| **Controller API**  | http://localhost:8080/api/status | SDN controller REST API        |
| **Triage Honeypot** | http://localhost:8004            | Honeypot service (via Mininet) |

---

## 🎮 Live Demo Commands

When the Mininet CLI opens, try these commands:

### Basic Connectivity Test

```bash
mininet> pingall
```

### Test Normal Server

```bash
mininet> h6 curl http://10.0.0.1:8001/
```

### Test Triage Honeypot

```bash
mininet> h6 curl http://10.0.0.4:8004/
```

### Trigger ML Analysis

```bash
mininet> h6 curl -X POST -d "username=admin&password=test" http://10.0.0.4:8004/
```

### Multiple Suspicious Requests (Triggers ML)

```bash
mininet> h6 curl -X POST -d "username=hacker1" http://10.0.0.4:8004/
mininet> h6 curl -X POST -d "username=hacker2" http://10.0.0.4:8004/
mininet> h6 curl -X POST -d "username=hacker3" http://10.0.0.4:8004/
```

### Exit Mininet

```bash
mininet> exit
```

---

## 📊 Monitoring

### Real-time Logs

Open a second terminal and run:

```bash
# Watch honeypot activity
tail -f logs/triage_honeypot.log

# Watch controller logs
tail -f logs/controller.log

# Watch all services
tail -f logs/*.log
```

### Check ML Model Status

```bash
curl http://localhost:8004/api/ml_status
```

### Check Controller Status

```bash
curl http://localhost:8080/api/status
```

---

## 🎓 For Academic Presentation

### Pre-Presentation Setup

1. **Start the system**: `./start_system.sh`
2. **Open presentation**: http://localhost:9000
3. **Open dashboard**: http://localhost:8090 (in another tab)
4. **Keep Mininet CLI open** for live demo

### During Presentation

1. **Show the landing page** (http://localhost:9000)
2. **Demonstrate live system** using dashboard
3. **Run demo commands** in Mininet CLI
4. **Show real-time logs** in another terminal

### After Presentation

1. **Exit Mininet CLI**: Type `exit`
2. **Stop system**: `./stop_system.sh`

---

## 🔧 Troubleshooting

### If Startup Fails

```bash
# Check what's running
netstat -tulpn | grep ":80"

# Force cleanup
./stop_system.sh
sudo mn -c

# Try again
./start_system.sh
```

### If Services Don't Start

```bash
# Check logs
ls -la logs/
cat logs/controller.log
cat logs/h4_service.log
```

### If Ports Are Busy

```bash
# Find what's using ports
sudo lsof -i :6653
sudo lsof -i :8080
sudo lsof -i :9000

# Kill specific processes
sudo kill -9 <PID>
```

---

## 📋 System Requirements

- **OS**: Linux (Ubuntu/Debian preferred)
- **Python**: 3.8+
- **Packages**: Flask, Requests, Ryu
- **Network**: Mininet, Open vSwitch
- **Privileges**: sudo access for Mininet

### Install Dependencies

```bash
# Install Ryu controller
pip3 install ryu

# Install Flask (already done)
pip3 install flask requests

# Install Mininet (if not installed)
sudo apt-get install mininet
```

---

## 🎯 Success Indicators

When everything is working correctly, you should see:

✅ **Controller**: Listening on ports 6653 & 8080  
✅ **Dashboard**: Accessible at http://localhost:8090  
✅ **Presentation**: Accessible at http://localhost:9000  
✅ **Mininet**: 100% connectivity (0% packet loss)  
✅ **Services**: All 5 services running (8001-8005)  
✅ **ML Model**: Operational with test predictions  
✅ **Logs**: Real-time activity in JSON format

---

## 🏆 Key Features to Highlight

- **One-command startup** - Complete system in seconds
- **Real-time ML classification** - Binary threat detection
- **Professional monitoring** - Dashboard + logs
- **Academic presentation** - Ready-to-present website
- **Live demonstration** - Interactive Mininet commands
- **Clean shutdown** - Proper process cleanup

Perfect for impressing your teachers! 🎓✨
