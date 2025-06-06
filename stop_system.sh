#!/bin/bash

# 🛑 SDN Honeypot System - Complete Shutdown Script
# This script stops all components of the SDN honeypot system

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_DIR="$PROJECT_ROOT/pids"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_header() {
    echo -e "${PURPLE}$1${NC}"
}

# Function to kill process by PID file
kill_by_pid_file() {
    local pid_file=$1
    local service_name=$2
    
    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if ps -p "$pid" > /dev/null 2>&1; then
            print_status "Stopping $service_name (PID: $pid)..."
            kill "$pid" 2>/dev/null
            sleep 2
            if ps -p "$pid" > /dev/null 2>&1; then
                print_warning "Force killing $service_name..."
                kill -9 "$pid" 2>/dev/null
            fi
            print_success "$service_name stopped"
        else
            print_warning "$service_name was not running"
        fi
        rm -f "$pid_file"
    else
        print_warning "No PID file found for $service_name"
    fi
}

# Function to kill processes by name
kill_by_name() {
    local process_name=$1
    local service_name=$2
    
    print_status "Stopping $service_name processes..."
    pkill -f "$process_name" 2>/dev/null && print_success "$service_name stopped" || print_warning "No $service_name processes found"
}

# Function to kill processes by port
kill_by_port() {
    local port=$1
    local service_name=$2
    
    print_status "Stopping $service_name on port $port..."
    local pid=$(lsof -ti:$port 2>/dev/null)
    if [ -n "$pid" ]; then
        kill "$pid" 2>/dev/null
        sleep 1
        if lsof -ti:$port >/dev/null 2>&1; then
            kill -9 "$pid" 2>/dev/null
        fi
        print_success "$service_name stopped"
    else
        print_warning "No process found on port $port"
    fi
}

# Main shutdown function
main() {
    print_header "🛑 SDN HONEYPOT SYSTEM - COMPLETE SHUTDOWN"
    print_header "=============================================="
    
    print_header "\n🧹 Step 1: Stopping Mininet"
    print_status "Cleaning Mininet topology..."
    sudo mn -c >/dev/null 2>&1 || print_warning "Mininet cleanup had issues"
    print_success "Mininet cleaned"
    
    print_header "\n🎮 Step 2: Stopping SDN Controller"
    kill_by_pid_file "$PID_DIR/controller.pid" "SDN Controller"
    # Fallback: kill by process name
    kill_by_name "ryu-manager.*honeypot_controller" "Ryu Controller"
    # Fallback: kill by port
    kill_by_port 6653 "Controller (port 6653)"
    kill_by_port 8080 "Controller API (port 8080)"
    
    print_header "\n📊 Step 3: Stopping Dashboard"
    kill_by_pid_file "$PID_DIR/dashboard.pid" "Dashboard"
    kill_by_port 8090 "Dashboard (port 8090)"
    
    print_header "\n🌐 Step 4: Stopping Presentation Website"
    kill_by_pid_file "$PID_DIR/presentation.pid" "Presentation"
    kill_by_port 9000 "Presentation (port 9000)"
    
    print_header "\n⚙️ Step 5: Stopping All Service Processes"
    # Stop all Flask app services
    kill_by_name "python3 app.py" "Service Apps"
    
    # Stop services by ports
    for port in 8001 8002 8003 8004 8005; do
        kill_by_port $port "Service (port $port)"
    done
    
    print_header "\n🧽 Step 6: Cleanup"
    print_status "Removing PID files..."
    rm -rf "$PID_DIR" 2>/dev/null && print_success "PID files removed" || print_warning "No PID files to remove"
    
    print_status "Cleaning up any remaining processes..."
    # Final cleanup of any remaining related processes
    pkill -f "honeypot" 2>/dev/null || true
    pkill -f "mininet" 2>/dev/null || true
    
    print_header "\n✅ SHUTDOWN COMPLETE"
    print_success "All SDN Honeypot components have been stopped"
    
    # Verify nothing is running
    print_header "\n📋 Final Status Check"
    for port in 6653 8080 8090 9000 8001 8002 8003 8004 8005; do
        if lsof -ti:$port >/dev/null 2>&1; then
            print_warning "Port $port is still in use"
        else
            print_success "Port $port is free"
        fi
    done
}

# Check if any components are running
check_status() {
    print_header "🔍 Checking Current System Status"
    
    local running_services=0
    
    # Check ports
    for port in 6653 8080 8090 9000 8001 8002 8003 8004 8005; do
        if lsof -ti:$port >/dev/null 2>&1; then
            echo -e "${YELLOW}⚠️ Port $port is in use${NC}"
            running_services=$((running_services + 1))
        fi
    done
    
    # Check for mininet
    if pgrep -f mininet >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠️ Mininet processes detected${NC}"
        running_services=$((running_services + 1))
    fi
    
    if [ $running_services -eq 0 ]; then
        print_success "No SDN Honeypot components are currently running"
        echo ""
        read -p "Nothing to stop. Exit? (Y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            exit 0
        fi
    else
        echo -e "${YELLOW}Found $running_services active components${NC}"
        echo ""
        read -p "Proceed with shutdown? (Y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Nn]$ ]]; then
            print_status "Shutdown cancelled"
            exit 0
        fi
    fi
}

# Main execution
print_header "🔧 Pre-shutdown Check"
check_status

# Execute shutdown
main

echo ""
print_header "🎉 System shutdown completed successfully!"
print_status "You can now restart the system with: ./start_system.sh" 