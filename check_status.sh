#!/bin/bash

# 📊 SDN Honeypot System - Status Checker
# Quick status check of all system components

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to check if a port is in use (localhost)
check_localhost_port() {
    local port=$1
    if lsof -ti:$port >/dev/null 2>&1; then
        return 0  # Port is in use
    else
        return 1  # Port is free
    fi
}

# Function to check Mininet services via process
check_mininet_service() {
    local port=$1
    if pgrep -f "python3.*app.py $port" >/dev/null 2>&1; then
        return 0  # Process running
    else
        return 1  # Process not running
    fi
}

# Function to check service status with proper namespace
check_service() {
    local port=$1
    local name=$2
    local description=$3
    local namespace=$4
    
    if [ "$namespace" = "localhost" ]; then
        if check_localhost_port $port; then
            echo -e "${GREEN}✅ $name${NC} (Port $port) - $description"
            return 0
        else
            echo -e "${RED}❌ $name${NC} (Port $port) - $description"
            return 1
        fi
    elif [ "$namespace" = "mininet" ]; then
        if check_mininet_service $port; then
            echo -e "${GREEN}✅ $name${NC} (Port $port) - $description"
            return 0
        else
            echo -e "${RED}❌ $name${NC} (Port $port) - $description"
            return 1
        fi
    fi
}

echo -e "${PURPLE}🛡️  SDN HONEYPOT SYSTEM STATUS${NC}"
echo "=================================="
echo ""

# Track running services
running_count=0
total_count=0

# Core Components
echo -e "${CYAN}🎮 Core Components:${NC}"
check_service 6653 "SDN Controller" "Ryu OpenFlow controller" "localhost" && running_count=$((running_count + 1))
total_count=$((total_count + 1))

check_service 8080 "Controller API" "REST API for controller" "localhost" && running_count=$((running_count + 1))
total_count=$((total_count + 1))

echo ""

# Web Interfaces
echo -e "${CYAN}🌐 Web Interfaces:${NC}"
check_service 9000 "Presentation" "Academic presentation website" "localhost" && running_count=$((running_count + 1))
total_count=$((total_count + 1))

check_service 8090 "Dashboard" "Real-time monitoring dashboard" "localhost" && running_count=$((running_count + 1))
total_count=$((total_count + 1))

echo ""

# Network Services (Mininet namespace)
echo -e "${CYAN}⚙️ Network Services:${NC}"
check_service 8001 "Normal Server 1" "h1 - Regular web server" "mininet" && running_count=$((running_count + 1))
total_count=$((total_count + 1))

check_service 8002 "Normal Server 2" "h2 - Regular web server" "mininet" && running_count=$((running_count + 1))
total_count=$((total_count + 1))

check_service 8003 "Normal Server 3" "h3 - Regular web server" "mininet" && running_count=$((running_count + 1))
total_count=$((total_count + 1))

check_service 8004 "Triage Honeypot" "h4 - ML-enabled honeypot" "mininet" && running_count=$((running_count + 1))
total_count=$((total_count + 1))

check_service 8005 "Deep Honeypot" "h5 - Advanced honeypot" "mininet" && running_count=$((running_count + 1))
total_count=$((total_count + 1))

echo ""

# Additional Checks
echo -e "${CYAN}🔍 Additional Status:${NC}"

# Check for Mininet
if pgrep -f mininet >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Mininet${NC} - Network topology active"
    running_count=$((running_count + 1))
else
    echo -e "${YELLOW}⚠️ Mininet${NC} - No active topology detected"
fi
total_count=$((total_count + 1))

# Check for Python processes
python_procs=$(pgrep -f "python3.*app.py" | wc -l)
if [ $python_procs -gt 0 ]; then
    echo -e "${GREEN}✅ Python Services${NC} - $python_procs service processes running"
else
    echo -e "${RED}❌ Python Services${NC} - No service processes detected"
fi

echo ""
echo "=================================="

# Summary
if [ $running_count -eq $total_count ]; then
    echo -e "${GREEN}🎉 System Status: FULLY OPERATIONAL${NC}"
    echo -e "${GREEN}All $total_count components are running perfectly!${NC}"
elif [ $running_count -gt $((total_count / 2)) ]; then
    echo -e "${YELLOW}⚠️ System Status: PARTIALLY RUNNING${NC}"
    echo -e "${YELLOW}$running_count/$total_count components are active${NC}"
else
    echo -e "${RED}❌ System Status: MOSTLY DOWN${NC}"
    echo -e "${RED}Only $running_count/$total_count components are running${NC}"
fi

echo ""

# Quick actions
if [ $running_count -eq 0 ]; then
    echo -e "${BLUE}💡 Quick Start:${NC} ./start_system.sh"
elif [ $running_count -lt $total_count ]; then
    echo -e "${BLUE}💡 Restart System:${NC} ./stop_system.sh && ./start_system.sh"
    echo -e "${BLUE}💡 Check Logs:${NC} ls -la logs/"
else
    echo -e "${BLUE}💡 Access URLs:${NC}"
    echo "   • Presentation: http://localhost:9000"
    echo "   • Dashboard: http://localhost:8090"
    echo "   • Controller API: http://localhost:8080/api/status"
fi

echo "" 