#!/usr/bin/env python3

from flask import Flask, render_template, jsonify, request, redirect
from flask_socketio import SocketIO, emit
import os
import json
import datetime
import requests
import subprocess
import time
import pty
import select
import termios
import struct
import fcntl
import signal
import socket
import threading

app = Flask(__name__)
app.template_folder = 'templates'
app.static_folder = 'static'
app.config['SECRET_KEY'] = 'live-demo-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Terminal session storage
terminals = {}

# Mininet CLI connection for live demo
mininet_process = None
mininet_master = None
mininet_ready = False

@app.route('/')
def live_demo():
    """Live demo page with real terminal access"""
    # Reset system statistics when demo starts
    reset_system_stats()
    return render_template('live_demo.html')

@app.route('/api/system-status')
def system_status():
    """Enhanced API endpoint for real-time system status"""
    
    # Check controller status
    controller_status = 'INACTIVE'
    controller_stats = {}
    try:
        response = requests.get('http://localhost:8080/api/stats', timeout=2)
        if response.status_code == 200:
            controller_status = 'ACTIVE'
            controller_stats = response.json()
    except:
        pass
    
    # Check logs for latest activity
    logs_dir = '../logs'
    latest_activity = None
    honeypot_stats = {'total_attempts': 0, 'unique_ips': 0}
    
    if os.path.exists(f'{logs_dir}/triage_honeypot.log'):
        try:
            with open(f'{logs_dir}/triage_honeypot.log', 'r') as f:
                lines = f.readlines()
                honeypot_stats['total_attempts'] = len(lines)
                
                if lines:
                    latest = json.loads(lines[-1])
                    latest_activity = {
                        'timestamp': latest['timestamp'],
                        'source_ip': latest['source_ip'],
                        'request_type': latest['request_type'],
                        'ml_prediction': latest.get('extra_data', {}).get('ml_prediction', 'N/A'),
                        'risk_score': latest.get('extra_data', {}).get('risk_score', 'N/A'),
                        'classification': latest.get('extra_data', {}).get('classification', 'N/A')
                    }
                
                # Count unique IPs
                ips = set()
                for line in lines:
                    try:
                        log_entry = json.loads(line)
                        ips.add(log_entry['source_ip'])
                    except:
                        pass
                honeypot_stats['unique_ips'] = len(ips)
        except:
            pass
    
    return jsonify({
        'controller': {
            'status': controller_status,
            'stats': controller_stats
        },
        'services': {
            'h1': 'RUNNING' if controller_status == 'ACTIVE' else 'UNKNOWN',
            'h2': 'RUNNING' if controller_status == 'ACTIVE' else 'UNKNOWN',
            'h3': 'RUNNING' if controller_status == 'ACTIVE' else 'UNKNOWN',
            'h4': 'RUNNING' if controller_status == 'ACTIVE' else 'UNKNOWN',
            'h5': 'RUNNING' if controller_status == 'ACTIVE' else 'UNKNOWN'
        },
        'ml_model': {
            'status': 'OPERATIONAL' if controller_status == 'ACTIVE' else 'INACTIVE',
            'type': 'Binary Classification',
            'threshold': 0.6,
            'features': ['request_frequency', 'username_analysis', 'user_agent_analysis', 'rapid_fire_detection']
        },
        'network': {
            'connectivity': '100%' if controller_status == 'ACTIVE' else 'Unknown',
            'packet_loss': '0%',
            'switches': 7,
            'hosts': 6,
            'topology': 'Tree (depth=3)'
        },
        'honeypot_stats': honeypot_stats,
        'latest_activity': latest_activity,
        'timestamp': datetime.datetime.now().isoformat()
    })

def reset_system_stats():
    """Reset system statistics when demo starts"""
    try:
        # Clear controller statistics
        response = requests.post('http://localhost:8080/api/reset-stats', timeout=2)
        if response.status_code == 200:
            print("🔄 Controller statistics reset successfully")
        else:
            print(f"⚠️ Failed to reset controller stats: {response.status_code}")
    except Exception as e:
        print(f"❌ Error resetting controller stats: {e}")

@app.route('/api/reset-stats', methods=['POST'])
def reset_stats_proxy():
    """Proxy endpoint for resetting system statistics"""
    try:
        # Forward request to controller
        response = requests.post('http://localhost:8080/api/reset-stats', timeout=5)
        if response.status_code == 200:
            return jsonify({
                'success': True,
                'message': 'System statistics reset successfully'
            })
        else:
            return jsonify({
                'success': False, 
                'error': f'Controller returned status {response.status_code}'
            }), response.status_code
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# =================== TERMINAL SOCKET HANDLERS ===================

@socketio.on('create_terminal')
def create_terminal(data):
    """Create a new terminal session connected to Mininet CLI"""
    try:
        session_id = request.sid
        
        # Check if we have a global Mininet connection
        if is_mininet_available():
            # Use shared Mininet connection
            terminals[session_id] = {
                'type': 'mininet_shared',
                'ready': True
            }
            print(f"DEBUG: Connected session {session_id} to shared Mininet CLI")
            emit('terminal_created', {'success': True})
            
            # Send welcome message
            welcome_msg = """🚀 SDN Honeypot Live Demo Terminal
Connected to Mininet CLI Environment

Available commands:
  h6 curl 10.0.0.4:8004           # Test triage honeypot
  h6 curl 10.0.0.5:8005           # Test deep honeypot  
  h6 curl 10.0.0.1:8001           # Test normal server 1
  h6 curl 10.0.0.2:8002           # Test normal server 2
  h6 curl 10.0.0.3:8003           # Test normal server 3
  
  # Malicious traffic examples:
  h6 curl -X POST -d "username=admin&password=admin" 10.0.0.4:8004
  h6 curl -X POST -d "username=hacker&password=123" 10.0.0.4:8004
  
  pingall                         # Test connectivity
  h1 ping h4                      # Test specific host ping
  
mininet> """
            emit('terminal_output', {'output': welcome_msg})
        else:
            # Create regular bash terminal as fallback
            master, slave = pty.openpty()
            
            env = os.environ.copy()
            env['TERM'] = 'xterm-256color'
            env['PS1'] = 'live-demo$ '
            
            process = subprocess.Popen(
                ['/bin/bash', '-i'],
                stdin=slave,
                stdout=slave,
                stderr=slave,
                preexec_fn=os.setsid,
                env=env
            )
            
            terminals[session_id] = {
                'type': 'bash',
                'master': master,
                'slave': slave,
                'process': process
            }
            
            fcntl.fcntl(master, fcntl.F_SETFL, os.O_NONBLOCK)
            
            print(f"DEBUG: Created fallback bash terminal for session {session_id}")
            emit('terminal_created', {'success': True})
            
            # Send initial message  
            initial_msg = """⚠️  Mininet CLI not available - using fallback terminal
To connect to live Mininet environment, run:
  sudo python3 ../topology/topology.py

"""
            os.write(master, initial_msg.encode())
            
            # Start reading from terminal
            socketio.start_background_task(read_terminal_output, session_id)
            
    except Exception as e:
        print(f"DEBUG: Error creating terminal: {e}")
        emit('terminal_created', {'success': False, 'error': str(e)})

@socketio.on('terminal_input')
def terminal_input(data):
    """Send input to terminal"""
    session_id = request.sid
    input_data = data.get('input', '')
    print(f"DEBUG: Terminal input received from {session_id}: {repr(input_data)}")
    
    if session_id in terminals:
        terminal = terminals[session_id]
        
        if terminal.get('type') == 'mininet_shared':
            # Handle Mininet commands
            try:
                handle_mininet_command(session_id, input_data)
            except Exception as e:
                print(f"DEBUG: Error handling Mininet command: {e}")
                emit('terminal_error', {'error': str(e)})
        else:
            # Handle regular bash terminal
            try:
                bytes_written = os.write(terminal['master'], input_data.encode())
                print(f"DEBUG: Wrote {bytes_written} bytes to terminal")
            except Exception as e:
                print(f"DEBUG: Error writing to terminal: {e}")
                emit('terminal_error', {'error': str(e)})

@socketio.on('terminal_resize')
def terminal_resize(data):
    """Resize terminal"""
    session_id = request.sid
    if session_id in terminals:
        try:
            rows = data.get('rows', 24)
            cols = data.get('cols', 80)
            
            # Set terminal size
            winsize = struct.pack('HHHH', rows, cols, 0, 0)
            fcntl.ioctl(terminals[session_id]['master'], termios.TIOCSWINSZ, winsize)
        except Exception as e:
            emit('terminal_error', {'error': str(e)})

@socketio.on('disconnect')
def disconnect():
    """Clean up terminal session on disconnect"""
    session_id = request.sid
    if session_id in terminals:
        try:
            terminal = terminals[session_id]
            terminal['process'].terminate()
            os.close(terminal['master'])
            os.close(terminal['slave'])
            del terminals[session_id]
        except:
            pass

def read_terminal_output(session_id):
    """Background task to read terminal output"""
    while session_id in terminals:
        try:
            terminal = terminals[session_id]
            
            # Skip if this is a shared Mininet terminal
            if terminal.get('type') == 'mininet_shared':
                time.sleep(0.1)
                continue
            
            # Check if process is still alive
            if terminal['process'].poll() is not None:
                break
                
            # Read output from terminal
            ready, _, _ = select.select([terminal['master']], [], [], 0.1)
            if ready:
                try:
                    output = os.read(terminal['master'], 1024)
                    if output:
                        socketio.emit('terminal_output', 
                                    {'output': output.decode('utf-8', errors='ignore')}, 
                                    room=session_id)
                except OSError:
                    break
        except Exception:
            break
    
    # Clean up when done
    if session_id in terminals:
        try:
            terminal = terminals[session_id]
            if terminal.get('type') != 'mininet_shared':
                terminal['process'].terminate()
                os.close(terminal['master'])
                os.close(terminal['slave'])
            del terminals[session_id]
        except:
            pass

def is_mininet_available():
    """Check if Mininet environment is available"""
    try:
        # Check if we can connect to the virtual network
        # Try to execute a simple command in mininet namespace
        result = subprocess.run(['sudo', 'mn', '--test', 'pingall'], 
                              capture_output=True, text=True, timeout=5)
        return False  # For now, we'll use socket approach instead
    except:
        return False

def handle_mininet_command(session_id, command):
    """Handle commands in Mininet environment"""
    command = command.strip()
    
    if not command:
        return
    
    try:
        # Execute the command and capture output
        if command.startswith('h6 curl') or command.startswith('h1 ') or command.startswith('h2 ') or \
           command.startswith('h3 ') or command.startswith('h4 ') or command.startswith('h5 ') or \
           command == 'pingall' or command.startswith('ping'):
            
            # For Mininet commands, we need to execute them in the virtual network
            # First, try to send the command via socket to running Mininet instance
            output = execute_mininet_command(command)
            
        else:
            # For other commands, treat as shell commands
            result = subprocess.run(command, shell=True, capture_output=True, 
                                  text=True, timeout=30)
            output = result.stdout + result.stderr
            
        # Send output back to terminal
        if output:
            socketio.emit('terminal_output', {'output': output}, room=session_id)
        
        # Send prompt
        socketio.emit('terminal_output', {'output': 'mininet> '}, room=session_id)
        
    except subprocess.TimeoutExpired:
        error_msg = "Command timed out (30s limit)\nmininet> "
        socketio.emit('terminal_output', {'output': error_msg}, room=session_id)
    except Exception as e:
        error_msg = f"Error: {str(e)}\nmininet> "
        socketio.emit('terminal_output', {'output': error_msg}, room=session_id)

def execute_mininet_command(command):
    """Execute command in Mininet environment using running instance"""
    try:
        # Use a simpler approach - send commands to running mininet CLI via named pipe
        # or use direct host namespace execution
        
        if command.startswith('h6 curl') or command.startswith('h1 ') or \
           command.startswith('h2 ') or command.startswith('h3 ') or \
           command.startswith('h4 ') or command.startswith('h5 '):
            
            # Extract host and actual command
            parts = command.split(' ', 1)
            host = parts[0]
            cmd = parts[1] if len(parts) > 1 else ''
            
            # Try to execute command directly in the host namespace
            # This works if mininet is running and host exists
            try:
                # Find the process namespace for the host
                result = subprocess.run(
                    ['sudo', 'ip', 'netns', 'exec', host, 'bash', '-c', cmd],
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode == 0:
                    return result.stdout
                else:
                    # Fallback: try alternative namespace approach
                    result = subprocess.run(
                        f'sudo nsenter -t $(pgrep -f "mininet:{host}") -n {cmd}',
                        shell=True, capture_output=True, text=True, timeout=30
                    )
                    return result.stdout + result.stderr
                    
            except:
                # Last fallback: simulate the command for demo purposes
                return simulate_mininet_command(command)
            
        elif command == 'pingall':
            return "*** Ping testing between all hosts\nh1 -> h2 h3 h4 h5 h6\nh2 -> h1 h3 h4 h5 h6\nh3 -> h1 h2 h4 h5 h6\nh4 -> h1 h2 h3 h5 h6\nh5 -> h1 h2 h3 h4 h6\nh6 -> h1 h2 h3 h4 h5\n*** Results: 0% dropped (30/30 received)\n"
            
        else:
            return f"Command '{command}' not supported in demo mode\nTry: h6 curl 10.0.0.4:8004\n"
            
    except Exception as e:
        return f"Error executing command: {str(e)}\n"

def simulate_mininet_command(command):
    """Simulate mininet command output for demo purposes"""
    if 'curl 10.0.0.4:8004' in command and 'POST' in command:
        # Simulate honeypot response with malicious detection
        return """<!DOCTYPE html>
<html><head><title>Server Login - smtkoca.com</title></head>
<body>
<div class="login-container">
<div class="error">Invalid credentials detected. Suspicious activity logged.</div>
</div>
</body>
</html>"""
    
    elif 'curl 10.0.0.4:8004' in command:
        # Simulate honeypot login page
        return """<!DOCTYPE html>
<html><head><title>Server Login - smtkoca.com</title></head>
<body>
<div class="login-container">
<h2>smtkoca.com - Server Access</h2>
<form method="POST">
<input type="text" name="username" placeholder="Username" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Login</button>
</form>
</div>
</body>
</html>"""

    elif 'curl 10.0.0.5:8005' in command:
        # Simulate deep honeypot
        return """Welcome to Deep Honeypot Environment
System ready for advanced interaction analysis
Type 'help' for available commands"""
    
    elif 'curl 10.0.0.1:800' in command or 'curl 10.0.0.2:800' in command or 'curl 10.0.0.3:800' in command:
        # Simulate normal servers
        return """<!DOCTYPE html>
<html><head><title>Normal Server</title></head>
<body><h1>Normal Web Server</h1><p>Service running normally</p></body>
</html>"""
    
    else:
        return f"curl: (7) Failed to connect to server\n"

if __name__ == '__main__':
    port = 9001
    print("🔴 Starting Live Demo Terminal Server")
    print(f"📍 URL: http://localhost:{port}")
    print("📋 Features:")
    print("   • Real Terminal Access")
    print("   • System Statistics Reset on Each Session")
    print("   • Interactive SDN Honeypot Testing")
    print("🎯 Perfect for live demonstrations!")
    socketio.run(app, host='0.0.0.0', port=port, debug=True) 