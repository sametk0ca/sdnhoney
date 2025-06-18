#!/bin/bash

# 🚀 SDN Honeypot System - Complete Startup Script
# This script starts all components of the SDN honeypot system in the correct order

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PATH="$PROJECT_ROOT/venv_sdnhoney"
CONTROLLER_PORT=6653
API_PORT=8080
PRESENTATION_PORT=9000

# Log files
LOG_DIR="$PROJECT_ROOT/logs"
CONTROLLER_LOG="$LOG_DIR/controller.log"
PRESENTATION_LOG="$LOG_DIR/presentation.log"

# PID files for process management
PID_DIR="$PROJECT_ROOT/pids"
CONTROLLER_PID="$PID_DIR/controller.pid"
PRESENTATION_PID="$PID_DIR/presentation.pid"

# Create necessary directories
mkdir -p "$LOG_DIR" "$PID_DIR"

# Function to run Python with virtual environment
run_python_venv() {
    "$VENV_PATH/bin/python" "$@"
}

# Function to run Python with virtual environment and sudo
run_python_venv_sudo() {
    sudo "$VENV_PATH/bin/python" "$@"
}

# Function to run Python with virtual environment and sudo for Mininet
run_mininet_cmd() {
    sudo /home/samet/Desktop/sdnhoney/venv_sdnhoney/bin/python "$@"
}

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

# Function to check if a port is in use
check_port() {
    local port=$1
    if netstat -ln | grep -q ":$port "; then
        return 0  # Port is in use
    else
        return 1  # Port is free
    fi
}

# Function to wait for a service to start
wait_for_service() {
    local port=$1
    local service_name=$2
    local timeout=30
    local counter=0
    
    print_status "Waiting for $service_name to start on port $port..."
    
    while [ $counter -lt $timeout ]; do
        if check_port $port; then
            print_success "$service_name is running on port $port"
            return 0
        fi
        sleep 1
        counter=$((counter + 1))
        echo -n "."
    done
    
    print_error "$service_name failed to start within $timeout seconds"
    return 1
}

# Function to cleanup on exit
cleanup() {
    print_header "\n🧹 Cleaning up processes..."
    
    # Kill background processes
    if [ -f "$CONTROLLER_PID" ]; then
        kill $(cat "$CONTROLLER_PID") 2>/dev/null || true
        rm -f "$CONTROLLER_PID"
    fi
    
    if [ -f "$PRESENTATION_PID" ]; then
        kill $(cat "$PRESENTATION_PID") 2>/dev/null || true
        rm -f "$PRESENTATION_PID"
    fi
    
    # Clean mininet with virtual environment
    sudo /home/samet/Desktop/sdnhoney/venv_sdnhoney/bin/python -c "from mininet.clean import cleanup; cleanup()" >/dev/null 2>&1 || true
    
    print_success "Cleanup completed"
}

# Set trap for cleanup on script exit
trap cleanup EXIT INT TERM

# Main startup function
main() {
    print_header "🛡️  SDN HONEYPOT SYSTEM - COMPLETE STARTUP"
    print_header "================================================"
    
    # Step 1: Clean previous Mininet instances
    print_header "\n🧹 Step 1: Cleaning Previous Mininet Instances"
    print_status "Running Mininet cleanup with virtual environment..."
    sudo /home/samet/Desktop/sdnhoney/venv_sdnhoney/bin/python -c "from mininet.clean import cleanup; cleanup()"
    sleep 2
    print_success "Mininet cleaned successfully"
    
    # Step 2: Start SDN Controller
    print_header "\n🎮 Step 2: Starting SDN Controller"
    cd "$PROJECT_ROOT"
    
    if check_port $CONTROLLER_PORT; then
        print_warning "Controller already running on port $CONTROLLER_PORT"
    else
        print_status "Starting Ryu SDN Controller..."
        nohup "$VENV_PATH/bin/ryu-manager" controller/controller.py --wsapi-port 8080\
            --observe-links \
            --verbose \
            > "$CONTROLLER_LOG" 2>&1 &
        echo $! > "$CONTROLLER_PID"
        
        # Wait for controller to start
        wait_for_service $CONTROLLER_PORT "SDN Controller"
        wait_for_service $API_PORT "Controller REST API"
    fi
    
    # Wait a moment for controller to fully initialize
    print_status "Allowing controller to initialize..."
    sleep 3
    
    # Step 3: Start Presentation Website
    print_header "\n🌐 Step 3: Starting Presentation Website"
    if check_port $PRESENTATION_PORT; then
        print_warning "Presentation already running on port $PRESENTATION_PORT"
    else
        start_presentation
    fi
    
    # Step 4: Start Network Topology and Services
    print_header "\n🕸️  Step 4: Starting Network Topology"
    print_status "This will start Mininet topology with all hosts and services..."
    print_warning "This step requires interactive input - the Mininet CLI will open"
    print_status "You can run 'pingall' to test connectivity and demo commands"
    print_status "Type 'exit' in Mininet CLI when done with the demo"
    
    # Show system status before starting topology
    show_system_status
    
    print_header "\n🚀 Starting Mininet Topology..."
    cd "$PROJECT_ROOT/topology"
    run_mininet_cmd topology.py
    
    print_header "\n✅ Topology session ended"
}

# Function to start presentation
start_presentation() {
    print_status "Starting presentation website..."
    cd "$PROJECT_ROOT/presentation"
    nohup "$VENV_PATH/bin/python" server.py > "$PRESENTATION_LOG" 2>&1 &
    echo $! > "$PRESENTATION_PID"
    
    wait_for_service $PRESENTATION_PORT "Presentation"
}

# Function to show system status
show_system_status() {
    print_header "\n📋 SYSTEM STATUS SUMMARY"
    echo "=================================="
    
    # Controller status
    if check_port $CONTROLLER_PORT; then
        echo -e "${GREEN}✅ SDN Controller${NC}      : Running (Port $CONTROLLER_PORT)"
        if check_port $API_PORT; then
            echo -e "${GREEN}✅ Controller API${NC}      : Running (Port $API_PORT)"
        fi
    else
        echo -e "${RED}❌ SDN Controller${NC}      : Not Running"
    fi
    
    # Presentation status
    if check_port $PRESENTATION_PORT; then
        echo -e "${GREEN}✅ Presentation${NC}        : Running (Port $PRESENTATION_PORT)"
    else
        echo -e "${RED}❌ Presentation${NC}        : Not Running"
    fi
    
    echo "=================================="
    echo -e "${CYAN}🌐 Access URLs:${NC}"
    echo "   Presentation   : http://localhost:$PRESENTATION_PORT"
    echo "   Controller API : http://localhost:$API_PORT/api/stats"
    echo "=================================="
    
    print_status "Ready to start network topology..."
}

# Check if running as root for mininet
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_error "Please run this script as a regular user, not root!"
        print_error "The script will use sudo when needed for Mininet."
        exit 1
    fi
}

# Check dependencies
check_dependencies() {
    print_status "Checking dependencies..."
    
    # Check if virtual environment exists
    if [ ! -d "$VENV_PATH" ]; then
        print_error "Virtual environment not found at $VENV_PATH"
        print_error "Please run: python3.9 -m venv venv_sdnhoney && source venv_sdnhoney/bin/activate && pip install -r requirements.txt"
        exit 1
    fi
    
    # Check if ryu-manager is available in venv
    if [ ! -f "$VENV_PATH/bin/ryu-manager" ]; then
        print_error "ryu-manager not found in virtual environment."
        print_error "Please run: source venv_sdnhoney/bin/activate && pip install ryu==4.34"
        exit 1
    fi
    
    # Check if python3 is available in venv
    if [ ! -f "$VENV_PATH/bin/python" ]; then
        print_error "Python not found in virtual environment."
        exit 1
    fi
    
    # Check if sudo is available
    if ! command -v sudo &> /dev/null; then
        print_error "sudo not found. This script requires sudo for Mininet."
        exit 1
    fi
    
    print_success "All dependencies found"
    print_status "Using virtual environment: $VENV_PATH"
}

# Main execution
print_header "🔧 Pre-flight Checks"
check_root
check_dependencies

# Ask for confirmation
print_header "\n🚀 Ready to Start SDN Honeypot System"
echo "This script will:"
echo "  1. Clean previous Mininet instances"
echo "  2. Start SDN Controller (Ryu)"
echo "  3. Start Presentation Website"
echo "  4. Start Network Topology with all services"
echo ""
read -p "Continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_status "Aborted by user"
    exit 0
fi

# Start the system
main

print_header "\n🎉 SDN Honeypot System Startup Complete!"
print_success "All components have been started successfully"
print_status "Check the presentation URL shown above" 