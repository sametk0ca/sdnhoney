#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_header() {
    echo -e "${CYAN}$1${NC}"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Check if Docker is running
check_docker() {
    if ! sudo docker info > /dev/null 2>&1; then
        print_error "Docker is not running! Please start Docker first."
        exit 1
    fi
    print_success "Docker is running"
}

# Check if docker-compose is available
check_docker_compose() {
    if ! command -v docker-compose > /dev/null 2>&1; then
        print_error "docker-compose not found! Please install docker-compose first."
        exit 1
    fi
    print_success "docker-compose is available"
}

# Main function
main() {
    print_header "🐳 SDN HONEYPOT DOCKER DEMO SYSTEM"
    print_header "===================================="
    
    print_status "Checking requirements..."
    check_docker
    check_docker_compose
    
    print_header "\n🏗️  Building Docker Images..."
    print_status "This may take a few minutes on first run..."
    
    # Build the demo image
    print_status "Building demo environment image..."
    sudo docker build -f docker/Dockerfile.demo -t sdnhoney-demo:latest .
    
    if [ $? -eq 0 ]; then
        print_success "Demo image built successfully"
    else
        print_error "Failed to build demo image"
        exit 1
    fi
    
    print_header "\n🚀 Starting Live Demo System..."
    
    # Start the live demo server in background
    print_status "Starting live demo server..."
    cd presentation
    python3 live_demo_docker.py &
    DEMO_PID=$!
    cd ..
    
    # Wait for demo server to start
    sleep 5
    
    if kill -0 $DEMO_PID 2>/dev/null; then
        print_success "Live demo server started (PID: $DEMO_PID)"
    else
        print_error "Failed to start live demo server"
        exit 1
    fi
    
    print_header "\n📋 DOCKER DEMO SYSTEM STATUS"
    echo "====================================="
    echo -e "${GREEN}✅ Docker Demo System${NC}  : Running"
    echo -e "${GREEN}✅ Live Demo Server${NC}    : Running (PID: $DEMO_PID)"
    echo "====================================="
    echo -e "${CYAN}🌐 Access URLs:${NC}"
    echo "   Live Demo Terminal : http://localhost:9001"
    echo "   Demo Container API : http://localhost:18080/api/stats"
    echo "====================================="
    
    print_header "\n🎯 DEMO USAGE INSTRUCTIONS"
    echo "1. Open http://localhost:9001 in your browser"
    echo "2. Wait for Docker container to initialize (1-2 minutes)"
    echo "3. Use the terminal to run commands like:"
    echo "   • h6 curl 10.0.0.4:8004"
    echo "   • h6 curl -X POST -d 'username=admin&password=admin' 10.0.0.4:8004"
    echo "   • pingall"
    echo "   • reset (to restart the demo environment)"
    echo ""
    echo "4. Monitor the system status and ML detections in real-time"
    echo "5. Present to your professors with confidence! 🎓"
    
    print_header "\n⚠️  IMPORTANT NOTES"
    echo "• Each demo session runs in an isolated Docker container"
    echo "• Use 'reset' command to get a fresh environment"
    echo "• Container automatically starts all services (Controller, honeypots, etc.)"
    echo "• Press Ctrl+C to stop the demo system"
    
    print_header "\n🔄 System Running - Press Ctrl+C to stop"
    
    # Wait for interrupt
    trap cleanup INT
    wait $DEMO_PID
}

# Cleanup function
cleanup() {
    print_header "\n🧹 Stopping Docker Demo System..."
    
    # Kill demo server
    if [ ! -z "$DEMO_PID" ]; then
        kill $DEMO_PID 2>/dev/null
        print_success "Live demo server stopped"
    fi
    
    # Stop and remove demo containers
    print_status "Stopping demo containers..."
    sudo docker stop sdnhoney-demo 2>/dev/null || true
    sudo docker rm sdnhoney-demo 2>/dev/null || true
    
    print_success "Cleanup completed"
    exit 0
}

# Run main function
main 