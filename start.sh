#!/bin/bash

echo "*** Starting SDN Honeypot System ***"

# Create logs directory if it doesn't exist
mkdir -p logs

# Install required dependencies if not already installed
echo "*** Checking and installing dependencies..."
pip_cmd=$(which pip3 || which pip)

# Function to check if a package is installed and install it if needed
check_and_install() {
    if ! $pip_cmd show $1 &>/dev/null; then
        echo "Installing $1..."
        $pip_cmd install $1
        sudo -H $pip_cmd install $1  # Also install for sudo user
    fi
}

# Check and install required packages
check_and_install numpy
check_and_install pandas
check_and_install scikit-learn
check_and_install grpcio
check_and_install grpcio-tools

# Check if any old processes are running and kill them
echo "*** Cleaning up any previous instances..."
sudo mn -c
pkill -f "ryu-manager" || true
pkill -f "model_service.py" || true
pkill -f "dashboard/app.py" || true

# Make sure ML model is trained
echo "*** Training ML model..."
cd ml_model
# Use the same Python that has the dependencies installed
PYTHON_PATH=$(which python3)
$PYTHON_PATH train_model.py
cd ..

# Start Ryu controller in background
echo "*** Starting Ryu controller..."
ryu-manager controller/my_controller.py --verbose > logs/controller.log 2>&1 &
CONTROLLER_PID=$!
echo "Controller started (PID: $CONTROLLER_PID)"
sleep 2  # Give controller time to start

# Start ML model service
echo "*** Starting ML model service..."
cd ml_model
$PYTHON_PATH model_service.py > ../logs/ml_model.log 2>&1 &
ML_PID=$!
cd ..
echo "ML model service started (PID: $ML_PID)"
sleep 2  # Give ML service time to start

# Start Dashboard
echo "*** Starting Dashboard..."
cd dashboard
$PYTHON_PATH app.py > ../logs/dashboard.log 2>&1 &
DASHBOARD_PID=$!
cd ..
echo "Dashboard started (PID: $DASHBOARD_PID) - Access at http://localhost:5001"
sleep 2  # Give dashboard time to start

# Start Mininet topology
echo "*** Starting Mininet topology..."
sudo python3 topology/large_topo.py

# Clean up when Mininet exits
echo "*** Network stopped. Cleaning up..."
sudo mn -c
pkill -f "ryu-manager" || true
pkill -f "model_service.py" || true
pkill -f "dashboard/app.py" || true

echo "*** SDN Honeypot System stopped ***" 