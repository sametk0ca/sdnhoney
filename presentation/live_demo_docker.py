#!/usr/bin/env python3

from flask import Flask, render_template, jsonify, request, redirect
from flask_socketio import SocketIO, emit
import os
import json
import datetime
import requests
import subprocess
import time
import docker
import threading

app = Flask(__name__)
app.template_folder = 'templates'
app.static_folder = 'static'
app.config['SECRET_KEY'] = 'live-demo-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Docker client and container management
docker_client = None
demo_container = None
container_ready = False

# Terminal session storage
terminals = {}

@app.route('/')
def live_demo():
    """Live demo page with Docker-based Mininet access"""
    global demo_container
    
    # Ensure demo container is running
    if not container_ready:
        setup_demo_container()
    
    return render_template('live_demo.html')

@app.route('/api/system-status')
def system_status():
    """Get system status including Docker container status"""
    global demo_container, container_ready
    
    # Check Docker container status
    container_status = 'INACTIVE'
    if demo_container:
        try:
            demo_container.reload()
            if demo_container.status == 'running':
                container_status = 'ACTIVE'
        except:
            container_status = 'ERROR'
    
    # Get controller stats from container if available
    controller_stats = {}
    if container_status == 'ACTIVE':
        try:
            # Execute curl inside the container to get controller stats
            result = demo_container.exec_run('curl -s http://localhost:8080/api/stats')
            if result.exit_code == 0:
                controller_stats = json.loads(result.output.decode())
        except:
            pass
    
    return jsonify({
        'controller': {
            'status': container_status,
            'stats': controller_stats
        },
        'container': {
            'status': container_status,
            'id': demo_container.short_id if demo_container else 'none',
            'ready': container_ready
        },
        'services': {
            'h1': 'RUNNING' if container_status == 'ACTIVE' else 'UNKNOWN',
            'h2': 'RUNNING' if container_status == 'ACTIVE' else 'UNKNOWN',
            'h3': 'RUNNING' if container_status == 'ACTIVE' else 'UNKNOWN',
            'h4': 'RUNNING' if container_status == 'ACTIVE' else 'UNKNOWN',
            'h5': 'RUNNING' if container_status == 'ACTIVE' else 'UNKNOWN'
        },
        'ml_model': {
            'status': 'OPERATIONAL' if container_status == 'ACTIVE' else 'INACTIVE',
            'type': 'Binary Classification',
            'threshold': 0.6,
            'features': ['request_frequency', 'username_analysis', 'user_agent_analysis', 'rapid_fire_detection']
        },
        'timestamp': datetime.datetime.now().isoformat()
    })

@app.route('/api/reset-container', methods=['POST'])
def reset_container():
    """Reset the demo container for a fresh environment"""
    try:
        reset_demo_container()
        return jsonify({
            'success': True,
            'message': 'Demo container reset successfully'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# =================== TERMINAL SOCKET HANDLERS ===================

@socketio.on('create_terminal')
def create_terminal(data):
    """Create a new terminal session connected to Docker container"""
    try:
        session_id = request.sid
        
        if container_ready and demo_container:
            terminals[session_id] = {
                'type': 'docker',
                'ready': True
            }
            
            print(f"DEBUG: Connected session {session_id} to Docker container")
            emit('terminal_created', {'success': True})
            
            # Send welcome message
            welcome_msg = """🐳 SDN Honeypot Live Demo Terminal (Docker Mode)
Connected to containerized Mininet environment

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
  
  # System commands:
  reset                           # Reset container environment
  status                          # Check system status
  
mininet> """
            emit('terminal_output', {'output': welcome_msg})
        else:
            emit('terminal_created', {'success': False, 'error': 'Demo container not ready'})
            
    except Exception as e:
        print(f"DEBUG: Error creating terminal: {e}")
        emit('terminal_created', {'success': False, 'error': str(e)})

@socketio.on('terminal_input')
def terminal_input(data):
    """Send input to Docker container"""
    session_id = request.sid
    input_data = data.get('input', '').strip()
    
    print(f"DEBUG: Terminal input received from {session_id}: {repr(input_data)}")
    
    if session_id in terminals and terminals[session_id].get('type') == 'docker':
        try:
            handle_docker_command(session_id, input_data)
        except Exception as e:
            print(f"DEBUG: Error handling Docker command: {e}")
            emit('terminal_error', {'error': str(e)})

@socketio.on('disconnect')
def disconnect():
    """Clean up terminal session on disconnect"""
    session_id = request.sid
    if session_id in terminals:
        del terminals[session_id]

# =================== DOCKER MANAGEMENT ===================

def setup_demo_container():
    """Setup Docker demo container"""
    global docker_client, demo_container, container_ready
    
    try:
        # Use sudo for Docker commands since user may not be in docker group yet
        docker_client = docker.DockerClient(base_url='unix://var/run/docker.sock')
        
        # Build the demo image if it doesn't exist
        build_demo_image()
        
        # Stop and remove existing container if it exists
        try:
            existing = docker_client.containers.get('sdnhoney-demo')
            existing.stop()
            existing.remove()
        except:
            pass
        
        # Start new container
        demo_container = docker_client.containers.run(
            'sdnhoney-demo:latest',
            name='sdnhoney-demo',
            ports={
                '8001/tcp': 18001,
                '8002/tcp': 18002, 
                '8003/tcp': 18003,
                '8004/tcp': 18004,
                '8005/tcp': 18005,
                '8080/tcp': 18080,
                '6653/tcp': 16653
            },
            detach=True,
            privileged=True,  # Required for Mininet
            remove=True
        )
        
        print(f"Started demo container: {demo_container.short_id}")
        
        # Wait for container to be ready
        time.sleep(10)  # Give time for services to start
        container_ready = True
        
    except Exception as e:
        print(f"Error setting up demo container: {e}")
        container_ready = False

def build_demo_image():
    """Build the demo Docker image"""
    global docker_client
    
    try:
        # Build from the docker directory
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        print("Building demo Docker image...")
        docker_client.images.build(
            path=project_root,
            dockerfile='docker/Dockerfile.demo',
            tag='sdnhoney-demo:latest'
        )
        print("Demo Docker image built successfully")
        
    except Exception as e:
        print(f"Error building Docker image: {e}")
        raise

def reset_demo_container():
    """Reset the demo container"""
    global demo_container, container_ready
    
    container_ready = False
    
    if demo_container:
        try:
            demo_container.stop()
            demo_container.remove()
        except:
            pass
    
    # Setup new container
    setup_demo_container()

# =================== COMMAND HANDLING ===================

def handle_docker_command(session_id, command):
    """Handle commands in Docker container"""
    global demo_container
    
    if not command:
        return
    
    try:
        if command == 'reset':
            emit('terminal_output', {'output': '🔄 Resetting demo environment...\n'}, room=session_id)
            threading.Thread(target=reset_demo_container).start()
            emit('terminal_output', {'output': '✅ Environment reset initiated\nmininet> '}, room=session_id)
            return
            
        elif command == 'status':
            output = get_container_status()
            emit('terminal_output', {'output': output + '\nmininet> '}, room=session_id)
            return
        
        # Execute command in container
        if demo_container and container_ready:
            # Convert mininet-style commands
            docker_command = convert_mininet_command(command)
            
            result = demo_container.exec_run(
                docker_command,
                workdir='/app',
                user='root'
            )
            
            output = result.output.decode('utf-8', errors='ignore')
            if not output.strip():
                output = f"Command executed (no output)\n"
                
        else:
            output = "❌ Demo container not ready\n"
        
        # Send output back to terminal
        emit('terminal_output', {'output': output}, room=session_id)
        emit('terminal_output', {'output': 'mininet> '}, room=session_id)
        
    except Exception as e:
        error_msg = f"Error: {str(e)}\nmininet> "
        emit('terminal_output', {'output': error_msg}, room=session_id)

def convert_mininet_command(command):
    """Convert mininet commands to Docker-compatible format"""
    if command.startswith('h6 ') or command.startswith('h1 ') or \
       command.startswith('h2 ') or command.startswith('h3 ') or \
       command.startswith('h4 ') or command.startswith('h5 '):
        
        # Extract host and command
        parts = command.split(' ', 1)
        host = parts[0]
        cmd = parts[1] if len(parts) > 1 else ''
        
        # Use mnexec to execute in host namespace
        return f'mnexec -a $(pgrep -f "mininet:{host}") {cmd}'
        
    elif command == 'pingall':
        return 'python3 -c "from mininet.net import Mininet; net = Mininet(); net.pingAll()"'
        
    else:
        return command

def get_container_status():
    """Get container status information"""
    global demo_container, container_ready
    
    if not demo_container:
        return "❌ No demo container running"
    
    try:
        demo_container.reload()
        status = f"""🐳 Demo Container Status:
ID: {demo_container.short_id}
Status: {demo_container.status}
Ready: {'✅' if container_ready else '❌'}

🌐 Services Status:
- SDN Controller: Port 6653
- REST API: Port 8080  
- h1 service: Port 8001
- h2 service: Port 8002
- h3 service: Port 8003
- h4 honeypot: Port 8004
- h5 honeypot: Port 8005"""
        
        return status
        
    except Exception as e:
        return f"❌ Error getting container status: {e}"

if __name__ == '__main__':
    port = 9001
    print("🐳 Starting Live Demo Terminal Server (Docker Mode)")
    print(f"📍 URL: http://localhost:{port}")
    print("📋 Features:")
    print("   • Docker-based Mininet Environment")
    print("   • Real Terminal Access")
    print("   • Container Reset for Fresh Demos")
    print("   • Isolated Network Environment")
    print("🎯 Perfect for live demonstrations!")
    
    # Setup demo container on startup
    setup_demo_container()
    
    socketio.run(app, host='0.0.0.0', port=port, debug=True) 