#!/bin/bash

echo "*** Starting SDN Honeypot System ***"

# Create logs directory if it doesn't exist
mkdir -p logs

# Check if any old processes are running and kill them
echo "*** Cleaning up any previous instances..."
sudo mn -c
pkill -f "ryu-manager" || true
pkill -f "model_service.py" || true
pkill -f "dashboard/app.py" || true

# Make sure ML model is trained
echo "*** Training ML model..."
cd ml_model
python3 train_model.py
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
python3 model_service.py > ../logs/ml_model.log 2>&1 &
ML_PID=$!
cd ..
echo "ML model service started (PID: $ML_PID)"
sleep 2  # Give ML service time to start

# Start Dashboard
echo "*** Starting Dashboard..."
cd dashboard
python3 app.py > ../logs/dashboard.log 2>&1 &
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