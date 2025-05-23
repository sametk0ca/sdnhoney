#!/bin/bash

# Ensure this script has execute permissions
chmod +x "$0"

# Get the directory of the script
SCRIPT_DIR="$( cd \"$( dirname \"${BASH_SOURCE[0]}\" )\" &> /dev/null && pwd )"

# Define log file for Ryu output
RYU_LOG_FILE="${SCRIPT_DIR}/ryu_controller.log"

echo "Starting SDN environment..."

# Command to start Ryu controller
# Output will be redirected to ryu_controller.log in the script's directory
RYU_CMD="ryu-manager ${SCRIPT_DIR}/controller/controller.py 2>&1 | tee ${RYU_LOG_FILE}"

# Command to start Mininet topology
# Needs to be run in the project root directory for correct pathing in topology.py
MININET_CMD="cd ${SCRIPT_DIR} && sudo python3 topology/topology.py"

# Check if gnome-terminal is available
if ! command -v gnome-terminal &> /dev/null
then
    echo "gnome-terminal could not be found. Please install it or adapt the script for your terminal."
    echo "Attempting to run sequentially in the current terminal as a fallback."
    echo "Starting Ryu controller (logging to ${RYU_LOG_FILE})..."
    eval "${RYU_CMD}" &
    RYU_PID=$!
    echo "Ryu controller started with PID $RYU_PID. Output is in ${RYU_LOG_FILE}"
    echo "Waiting 5 seconds for controller to initialize..."
    sleep 5
    echo "Starting Mininet topology..."
    eval "${MININET_CMD}"
    echo "Mininet exited. Remember to manually stop the Ryu controller (PID $RYU_PID)."
    exit 1
fi

echo "Opening Ryu controller in a new terminal tab (logging to ${RYU_LOG_FILE})..."
echo "Opening Mininet in another new terminal tab after a short delay..."

# Using gnome-terminal to open new tabs
# The first tab will be for the Ryu controller.
# The second tab will execute Mininet after a delay.
# The --working-directory flag ensures commands are run from the project root.
gnome-terminal --working-directory="${SCRIPT_DIR}" --tab --title="Ryu Controller" --command="bash -c '${RYU_CMD}; exec bash'" \
               --tab --title="Mininet" --command="bash -c 'echo Waiting 5 seconds for controller to initialize...; sleep 5; echo Starting Mininet...; ${MININET_CMD}; exec bash'"

echo "Ryu controller and Mininet should now be starting in new terminal tabs."
echo "Controller output is being logged to: ${RYU_LOG_FILE}"
echo "When you are finished, please manually close both terminal tabs." 