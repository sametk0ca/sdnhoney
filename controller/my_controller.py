from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, udp, icmp, ether_types
from flow_rules import add_default_flow, add_learning_flow
import configparser
import grpc
import random  # Move random import to module level

# Add project root to path to find 'proto' module
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

import proto.ml_model_pb2 as ml_model_pb2
import proto.ml_model_pb2_grpc as ml_model_pb2_grpc

import logging
import time

# Imports for REST API
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
import json
import subprocess # For reading log tail

# Define log path consistently (relative to project root)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
CONFIG_DIR = os.path.join(PROJECT_ROOT, 'config')
LOGS_DIR = os.path.join(PROJECT_ROOT, 'logs')
CONTROLLER_LOG_PATH = os.path.join(LOGS_DIR, 'controller.log')
ML_MODEL_LOG_PATH = os.path.join(LOGS_DIR, 'ml_model.log')
HOST15_HONEYPOT_LOG_PATH = os.path.join(LOGS_DIR, 'host15_honeypot.log')
HONEYPOT_CONFIG_PATH = os.path.join(CONFIG_DIR, 'honeypot_config.json')

# Ensure config directory exists
os.makedirs(CONFIG_DIR, exist_ok=True)

# Network configuration - matching topology settings
NETWORK_CONFIG = {
    'honeypot': {
        'ip': '10.0.0.15',
        'default_port': 1
    },
    'ml_service': {
        'host': 'localhost',
        'port': 50051,
        'timeout': 1.0
    },
    'external_hosts': {
        'ip_range': ['10.0.0.9', '10.0.0.10', '10.0.0.11', '10.0.0.12']
    }
}

# Attack detection parameters
RATE_LIMIT_THRESHOLD = 50  # Requests per minute
RATE_LIMIT_WINDOW = 60     # Reset window in seconds

# ML confidence thresholds
ML_HIGH_CONFIDENCE = 0.8   # Threshold for high confidence predictions

class MyController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    # Tell Ryu to instantiate our RestController
    _CONTEXTS = {
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(MyController, self).__init__(*args, **kwargs)
        
        # Initialize dictionaries for MAC address and port tracking
        self.mac_to_port = {}
        
        # Initialize suspected IPs list
        self.suspected_ips = set()
        self.known_ips = set()
        
        # Add honeypot configuration - will be set from config file
        self.honeypot_ip = NETWORK_CONFIG['honeypot']['ip']
        self.honeypot_mac = None
        self.honeypot_port = NETWORK_CONFIG['honeypot']['default_port']
        self.has_verified_honeypot = False
        
        # Statistics tracking
        self.total_packets_processed = 0
        self.suspicious_packets_detected = 0
        self.redirected_connections = 0
        self.ml_requests_count = 0
        self.ml_success_count = 0
        self.ml_error_count = 0
        
        # Initialize dictionary to store recent TCP payloads for attack detection
        self.last_tcp_payload = {}
        
        # Create a list of expected hosts for dashboard
        self.expected_hosts = ['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'h7', 
                              'external1', 'external2', 'external3', 'external4',
                              'h8', 'h9', 'h10', 'h11', 'h12', 'h13', 'h14', 'h15']
        
        # Map host names to IP addresses
        self.host_ips = {
            'h1': '10.0.0.1', 'h2': '10.0.0.2', 'h3': '10.0.0.3', 'h4': '10.0.0.4',
            'h5': '10.0.0.5', 'h6': '10.0.0.6', 'h7': '10.0.0.7', 'h8': '10.0.0.8',
            'h9': '10.0.0.9', 'h10': '10.0.0.10', 'h11': '10.0.0.11', 'h12': '10.0.0.12',
            'h13': '10.0.0.13', 'h14': '10.0.0.14', 'h15': '10.0.0.15',
            'external1': '10.0.0.9', 'external2': '10.0.0.10', 'external3': '10.0.0.11', 'external4': '10.0.0.12'
        }
        
        # Updated rule table to focus on HTTP traffic
        self.rule_table = {
            # Known good patterns (legitimate HTTP traffic)
            'good': [
                # Basic protocols everyone needs
                {'protocol': 'icmp'},                     # Allow ping for network diagnostics
                {'protocol': 'udp', 'dst_port': 53},      # DNS (needed for hostname resolution)
                
                # Regular hosts (h1-h14) are allowed normal web traffic
                {'src_ip': '10.0.0.1', 'protocol': 'tcp', 'dst_port': 8080},  # h1
                {'src_ip': '10.0.0.2', 'protocol': 'tcp', 'dst_port': 8080},  # h2
                {'src_ip': '10.0.0.3', 'protocol': 'tcp', 'dst_port': 8080},  # h3
                {'src_ip': '10.0.0.4', 'protocol': 'tcp', 'dst_port': 8080},  # h4
                {'src_ip': '10.0.0.5', 'protocol': 'tcp', 'dst_port': 8080},  # h5
                {'src_ip': '10.0.0.6', 'protocol': 'tcp', 'dst_port': 8080},  # h6
                {'src_ip': '10.0.0.7', 'protocol': 'tcp', 'dst_port': 8080},  # h7
                {'src_ip': '10.0.0.8', 'protocol': 'tcp', 'dst_port': 8080},  # h8
                {'src_ip': '10.0.0.9', 'protocol': 'tcp', 'dst_port': 8080},  # h9 (IP shared with external1)
                {'src_ip': '10.0.0.10', 'protocol': 'tcp', 'dst_port': 8080}, # h10 (IP shared with external2)
                {'src_ip': '10.0.0.11', 'protocol': 'tcp', 'dst_port': 8080}, # h11 (IP shared with external3)
                {'src_ip': '10.0.0.12', 'protocol': 'tcp', 'dst_port': 8080}, # h12 (IP shared with external4)
                {'src_ip': '10.0.0.13', 'protocol': 'tcp', 'dst_port': 8080}, # h13
                {'src_ip': '10.0.0.14', 'protocol': 'tcp', 'dst_port': 8080}, # h14
                
                # HTTPS for secure communications
                {'protocol': 'tcp', 'dst_port': 443},     # HTTPS
                
                # Allow honeypot to communicate (for responses)
                {'src_ip': '10.0.0.15', 'protocol': 'tcp'}, # h15 (honeypot) outbound
            ],
            
            # Known bad patterns (immediately redirect to honeypot)
            'bad': [
                # External hosts with specific attack patterns
                # External1 (MAC 00:00:00:00:00:01)
                {'src_ip': '10.0.0.9', 'src_mac': '00:00:00:00:00:01', 'protocol': 'tcp', 'dst_port': 8080},
                
                # External2 (MAC 00:00:00:00:00:02)
                {'src_ip': '10.0.0.10', 'src_mac': '00:00:00:00:00:02', 'protocol': 'tcp', 'dst_port': 8080},
                
                # External3 (MAC 00:00:00:00:00:03)
                {'src_ip': '10.0.0.11', 'src_mac': '00:00:00:00:00:03', 'protocol': 'tcp', 'dst_port': 8080},
                
                # External4 (MAC 00:00:00:00:00:04)
                {'src_ip': '10.0.0.12', 'src_mac': '00:00:00:00:00:04', 'protocol': 'tcp', 'dst_port': 8080},
                
                # Non-HTTP services - redirect to honeypot as these shouldn't be accessed
                {'protocol': 'tcp', 'dst_port': 22},    # SSH
                {'protocol': 'tcp', 'dst_port': 23},    # Telnet
                {'protocol': 'tcp', 'dst_port': 445},   # SMB
                {'protocol': 'tcp', 'dst_port': 3389},  # RDP
                {'protocol': 'tcp', 'dst_port': 3306},  # MySQL
                {'protocol': 'tcp', 'dst_port': 5432},  # PostgreSQL
                {'protocol': 'tcp', 'dst_port': 1433},  # MSSQL
                {'protocol': 'tcp', 'dst_port': 25},    # SMTP
                {'protocol': 'tcp', 'dst_port': 21},    # FTP
                {'protocol': 'tcp', 'dst_port': 20},    # FTP Data
                
                # Common attack patterns detected in HTTP requests
                {'url_pattern': ['../etc/passwd']},    # Path traversal
                {'url_pattern': ['../windows/win.ini']}, # Path traversal (Windows)
                {'url_pattern': ['union select']},     # SQL injection
                {'url_pattern': ['exec(']},            # Code injection
                {'url_pattern': ['eval(']},            # Code injection
                {'url_pattern': ['<script>']},         # XSS
                {'url_pattern': ['alert(']},           # XSS
                {'url_pattern': ['onload=']},          # XSS
                {'url_pattern': ['cmd.exe']},          # Command injection (Windows)
                {'url_pattern': ['/bin/sh']},          # Command injection (Linux)
                {'url_pattern': ['wget ']},            # Download attempt
                {'url_pattern': ['curl ']},            # Download attempt
            ]
        }
        
        # Reload configuration (always reload to get latest values)
        self.reload_config()
        
        # Log the honeypot configuration
        self.logger.info(f"Honeypot configured at IP: {self.honeypot_ip}, MAC: {self.honeypot_mac}, Port: {self.honeypot_port}")
        
        # Store the WSGI app instance
        self.wsgi = kwargs['wsgi']
        # Register our RestController with the WSGI application
        self.wsgi.register(RestController, {'my_controller_app': self})
        
        # Initialize gRPC client
        try:
            ml_host = NETWORK_CONFIG['ml_service']['host']
            ml_port = NETWORK_CONFIG['ml_service']['port']
            self.channel = grpc.insecure_channel(f'{ml_host}:{ml_port}')
            self.stub = ml_model_pb2_grpc.MLModelServiceStub(self.channel)
            logging.info(f"gRPC connection established to {ml_host}:{ml_port}")
        except Exception as e:
            logging.error(f"gRPC connection error: {e}")
        
        # Add HTTP request tracking for rate limiting
        self.http_request_count = {}  # {ip: {"count": n, "last_reset": timestamp}}
        
        logging.info("SDN Controller started - HTTP Honeypot Mode")
        logging.info(f"Honeypot settings - IP: {self.honeypot_ip}, MAC: {self.honeypot_mac}, Port: {self.honeypot_port}")

    def reload_config(self):
        """Reload honeypot configuration from file."""
        # Default settings if config is not available
        default_honeypot_ip = "10.0.0.15"  # host15 in large topology
        
        try:
            # Check for config directory, create if it doesn't exist
            config_dir = os.path.join(os.path.dirname(__file__), '../config')
            if not os.path.exists(config_dir):
                os.makedirs(config_dir)
                
            # Define the config file path
            config_file = os.path.join(config_dir, 'honeypot_config.json')
            
            # Check if the file exists
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    
                # Get honeypot settings from config
                self.honeypot_ip = config.get('honeypot_ip', default_honeypot_ip)
                self.honeypot_mac = config.get('honeypot_mac')
                self.honeypot_port = config.get('honeypot_port')
                
                self.logger.info(f"Loaded honeypot config: IP={self.honeypot_ip}, MAC={self.honeypot_mac}, Port={self.honeypot_port}")
                if self.honeypot_mac and self.honeypot_port:
                    self.has_verified_honeypot = True
            else:
                # Use default settings if config file doesn't exist
                self.honeypot_ip = default_honeypot_ip
                
                # Try to locate honeypot MAC and port by checking our MAC table
                for dpid, mac_table in self.mac_to_port.items():
                    for mac, port in mac_table.items():
                        # Check if this MAC might be from switch 14 (s14 is connected to h15)
                        # We'll dynamically discover it rather than relying on hardcoded patterns
                        if dpid == 14:
                            self.honeypot_mac = mac
                            self.honeypot_port = port
                            self.has_verified_honeypot = True
                            self.logger.info(f"Found honeypot dynamically: MAC={mac}, port={port}")
                                
                            # Write this information to config file for future use
                            config_data = {
                                'honeypot_ip': self.honeypot_ip,
                                'honeypot_mac': self.honeypot_mac,
                                'honeypot_port': self.honeypot_port
                            }
                            with open(config_file, 'w') as f:
                                json.dump(config_data, f, indent=4)
                                
                            return
                
                self.logger.warning(f"Config file not found at {config_file}. Using defaults. No port found for honeypot.")
        except Exception as e:
            # Handle any errors in loading config
            self.logger.error(f"Error loading config: {e}")
            self.honeypot_ip = default_honeypot_ip

    def is_multicast_or_broadcast(self, mac):
        # Multicast adresleri (33:33, 01:00:5e, 01:80:c2) ve broadcast (ff:ff:ff:ff:ff:ff) kontrol et
        return mac.startswith(('33:33', '01:00:5e', '01:80:c2')) or mac == 'ff:ff:ff:ff:ff:ff'

    def check_rule_table(self, packet_info):
        """Check if packet matches any known rules
        
        This function is enhanced to detect HTTP traffic patterns
        for the HTTP honeypot system.
        """
        # Always allow ICMP (ping) for basic connectivity
        if packet_info.get('protocol') == 'icmp':
            return 'good'
            
        # Direct check for external hosts with suspicious patterns
        src_ip = packet_info.get('src_ip')
        src_mac = packet_info.get('src_mac')
        dst_port = packet_info.get('dst_port', 0)
        
        # Better identification of external hosts - using both IP and MAC
        is_external = False
        
        # External hosts are identified by MAC addresses 00:00:00:00:00:01 through 00:00:00:00:00:04
        if src_mac and src_mac in ['00:00:00:00:00:01', '00:00:00:00:00:02', '00:00:00:00:00:03', '00:00:00:00:00:04']:
            is_external = True
            self.logger.info(f"External host identified by MAC: {src_mac}, IP: {src_ip}")
            
            # If this external host is targeting HTTP service, mark as suspicious 
            if dst_port == 8080:
                self.logger.warning(f"External host {src_ip} (MAC: {src_mac}) detected accessing HTTP service - marking as suspicious")
                return 'bad'
        
        # Check if source IP is in suspected IPs list
        if src_ip in self.suspected_ips:
            self.logger.warning(f"Suspected IP detected: {src_ip} (MAC: {src_mac})")
            return 'bad'
        
        # First check if it matches any good patterns
        for rule in self.rule_table['good']:
            # Check if all rule criteria match this packet
            match = True
            for key, value in rule.items():
                if key not in packet_info or packet_info[key] != value:
                    match = False
                    break
                    
            if match:
                return 'good'
        
        # Then check if it matches any bad patterns
        for rule in self.rule_table['bad']:
            match = True
            for key, value in rule.items():
                # Special handling for URL patterns
                if key == 'url_pattern':
                    if 'payload' not in packet_info:
                        match = False
                        break
                    
                    payload = packet_info['payload'].lower() if packet_info['payload'] else ''
                    pattern_match = False
                    
                    for pattern in value:
                        if pattern.lower() in payload:
                            pattern_match = True
                            self.logger.warning(f"Suspicious pattern '{pattern}' found in payload from {src_ip}")
                            break
                            
                    if not pattern_match:
                        match = False
                        break
                # Regular field matching
                elif key not in packet_info or packet_info[key] != value:
                    match = False
                    break
                    
            if match:
                self.logger.warning(f"Bad traffic pattern matched for {src_ip} (MAC: {src_mac})")
                return 'bad'
        
        # Special handling for regular hosts vs. external hosts for unknown traffic
        if is_external:
            # For external hosts, be more suspicious of unknown traffic
            self.logger.info(f"Unknown traffic pattern from external host {src_ip} (MAC: {src_mac}) - treating as suspicious")
            return 'bad'
            
        return 'unknown'
        
    def check_rate_limit(self, ip):
        """Check if an IP has exceeded the rate limit for HTTP requests"""
        # Get current time
        now = time.time()
        
        # Initialize if this IP is not being tracked
        if ip not in self.http_request_count:
            self.http_request_count[ip] = {"count": 1, "last_reset": now}
            return False
            
        # Check if we need to reset the counter (1 minute window)
        if now - self.http_request_count[ip]["last_reset"] > RATE_LIMIT_WINDOW:
            self.http_request_count[ip] = {"count": 1, "last_reset": now}
            return False
            
        # Increment the counter
        self.http_request_count[ip]["count"] += 1
        
        # Check if over the limit
        if self.http_request_count[ip]["count"] > RATE_LIMIT_THRESHOLD:
            return True
            
        return False

    def query_ml_model(self, src_ip, dst_ip, src_port, dst_port, protocol):
        """Query ML model for traffic classification
        
        This function attempts to identify malicious traffic that doesn't have
        obvious attack signatures by analyzing traffic patterns.
        """
        self.ml_requests_count += 1
        
        # Always allow ICMP traffic for basic connectivity
        if protocol == 'icmp':
            return False  # Not suspicious
        
        # Track HTTP request frequency for rate limiting detection
        if protocol == 'tcp' and (dst_port == 80 or dst_port == 8080 or dst_port == 443):
            # Check if source IP is making too many requests in a short time
            if self.check_rate_limit(src_ip):
                self.logger.warning(f"Rate limit exceeded for {src_ip}")
                return True
            
            # Enhanced HTTP attack detection for simple_attack.py patterns
            if src_ip in self.last_tcp_payload:
                payload = self.last_tcp_payload[src_ip]
                
                # Check for common attack patterns in the URL
                if '?id=' in payload and ("'OR" in payload or "OR'1'" in payload or "OR 1=1" in payload):
                    self.logger.warning(f"SQL injection pattern detected in URL from {src_ip}")
                    return True
                
                if '../' in payload or 'etc/passwd' in payload:
                    self.logger.warning(f"Path traversal pattern detected in URL from {src_ip}")
                    return True
                    
                if '?cmd=' in payload or ';' in payload or '&&' in payload:
                    self.logger.warning(f"Command injection pattern detected in URL from {src_ip}")
                    return True
                    
                if '<script>' in payload or 'alert(' in payload:
                    self.logger.warning(f"XSS pattern detected in URL from {src_ip}")
                    return True
        
        # Prepare packet info for ML model
        packet_info = ml_model_pb2.PacketInfo(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol
        )
        
        # If this is from an external host, add context to the packet info
        if self.is_external_host(src_ip):
            packet_info.is_external = True
        
        try:
            timeout = NETWORK_CONFIG['ml_service']['timeout']
            response = self.stub.PredictPacket(packet_info, timeout=timeout)
            is_suspicious = response.is_suspicious
            confidence = response.confidence
            
            # Update statistics
            self.ml_success_count += 1
            
            # Log prediction details with confidence level indicator
            confidence_level = "HIGH" if confidence > ML_HIGH_CONFIDENCE else "MEDIUM" if confidence > 0.5 else "LOW"
            
            if is_suspicious:
                self.logger.warning(f"ML model prediction: SUSPICIOUS traffic from {src_ip}:{src_port} to {dst_ip}:{dst_port} ({protocol}) - Confidence: {confidence:.2f} [{confidence_level}]")
                # Add to suspicious IPs if not already there
                if src_ip not in self.suspected_ips:
                    self.suspected_ips.add(src_ip)
            else:
                self.logger.info(f"ML model prediction: BENIGN traffic from {src_ip}:{src_port} to {dst_ip}:{dst_port} ({protocol}) - Confidence: {confidence:.2f} [{confidence_level}]")
                # Add to known IPs for faster processing next time
                if confidence > ML_HIGH_CONFIDENCE and src_ip not in self.known_ips:
                    self.known_ips.add(src_ip)
            
            return is_suspicious
        except grpc.RpcError as e:
            self.logger.error(f"gRPC error when querying ML model: {e}")
            self.ml_error_count += 1
            
            # Enhanced fallback detection when ML service is unavailable
            return self.fallback_detection(src_ip, dst_ip, src_port, dst_port, protocol)

    def fallback_detection(self, src_ip, dst_ip, src_port, dst_port, protocol):
        """Fallback detection logic when ML model is unavailable"""
        self.logger.warning(f"Using fallback detection for traffic: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        
        # 1. Check if source is an external host (higher suspicion)
        if self.is_external_host(src_ip):
            self.logger.warning(f"Fallback detection: External host {src_ip} attempting connection")
            
            # Check for access to sensitive ports from external hosts
            sensitive_ports = [22, 23, 3389, 445, 3306, 5432, 8080]
            if dst_port in sensitive_ports:
                self.logger.warning(f"Fallback detection: External host accessing sensitive port {dst_port}")
                return True
        
        # 2. Check port scan pattern (lots of connections to different ports)
        for src_check_ip, count in self.http_request_count.items():
            if src_check_ip == src_ip and count["count"] > 10:
                self.logger.warning(f"Fallback detection: Possible port scan from {src_ip}")
                return True
        
        # 3. Check for common attack patterns in URLs
        try:
            if hasattr(self, 'last_tcp_payload') and self.last_tcp_payload.get(src_ip):
                payload = self.last_tcp_payload[src_ip]
                
                # Check for SQL injection patterns
                sql_patterns = ["OR 1=1", "' OR '", "OR '1'='1", "--", "/*", "UNION SELECT", "1' OR '1'='1"]
                
                # Check for path traversal
                path_patterns = ["../", "..\\", "/etc/passwd", "\\windows\\system32"]
                
                # Check for command injection
                cmd_patterns = ["exec(", "system(", "cmd=", ";", "&&", "||", "`", "$"]
                
                # Check for XSS
                xss_patterns = ["<script>", "onerror=", "onload=", "javascript:", "alert("]
                
                # Combined patterns
                attack_patterns = sql_patterns + path_patterns + cmd_patterns + xss_patterns
                
                for pattern in attack_patterns:
                    if pattern.lower() in payload.lower():
                        self.logger.warning(f"Fallback detection: Attack pattern '{pattern}' detected in traffic from {src_ip}")
                        return True
        except Exception as e:
            self.logger.error(f"Error in fallback detection: {e}")
        
        # 4. Check suspicious port combinations
        if protocol == 'tcp':
            # Unusual source ports might indicate scanning or unusual behavior
            if src_port < 1024 and dst_port > 1024:
                self.logger.warning(f"Fallback detection: Unusual port combination {src_port} -> {dst_port}")
                return True
        
        # Conservative approach: when ML model fails, only consider suspicious
        # for non-standard ports or protocols from external hosts
        if self.is_external_host(src_ip) and dst_port not in [80, 443, 8080, 53]:
            return True
            
        return False  # Default to allowing common services

    def is_external_host(self, ip):
        """Check if the given IP belongs to an external host"""
        return ip in NETWORK_CONFIG['external_hosts']['ip_range']

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        logging.info(f"[SWITCH FEATURES] Datapath {datapath.id} connected")
        
        # Install ARP flood rule (priority 1)
        match_arp = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        actions_arp = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        inst_arp = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions_arp)]
        mod_arp = parser.OFPFlowMod(
            datapath=datapath,
            priority=1,
            match=match_arp,
            instructions=inst_arp,
            idle_timeout=0,
            hard_timeout=0
        )
        datapath.send_msg(mod_arp)
        logging.info(f"[SWITCH FEATURES] ARP flood flow installed on switch {datapath.id}")

        # Install direct default flow: send all other packets to controller (priority 0)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            match=match,
            instructions=inst,
            idle_timeout=0,
            hard_timeout=0
        )
        datapath.send_msg(mod)
        logging.info(f"[SWITCH FEATURES] Default flow installed on switch {datapath.id}")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath, buffer_id=buffer_id, priority=priority,
                match=match, instructions=inst,
                idle_timeout=idle_timeout, hard_timeout=hard_timeout
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=priority,
                match=match, instructions=inst,
                idle_timeout=idle_timeout, hard_timeout=hard_timeout
            )
        datapath.send_msg(mod)

    def redirect_to_honeypot(self, datapath, parser, ip_pkt, tcp_pkt, in_port):
        """Trafiği honeypot'a yönlendirmek için flow kuralı ekler"""
        match = parser.OFPMatch(
            eth_type=0x0800,           # IPv4
            ip_proto=6,                # TCP
            ipv4_src=ip_pkt.src,
            ipv4_dst=ip_pkt.dst,
            tcp_src=tcp_pkt.src_port,
            tcp_dst=tcp_pkt.dst_port
        )
        
        # Honeypot'a yönlendirme actions
        actions = [
            parser.OFPActionSetField(ipv4_dst=self.honeypot_ip),
            parser.OFPActionSetField(eth_dst=self.honeypot_mac),
            parser.OFPActionOutput(self.honeypot_port)
        ]
        
        # Yüksek öncelikli flow ekle (5 dakika idle_timeout)
        self.add_flow(datapath, 100, match, actions, idle_timeout=300)
        logging.warning(f"Honeypot yönlendirme kuralı eklendi: {ip_pkt.src} -> {self.honeypot_ip}")
        
        # Add flow to direct all traffic from this source to honeypot
        self.add_flow(datapath, 100, match, actions, idle_timeout=300)
        
        # Install a more general flow rule for all traffic from this IP
        general_match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=ip_pkt.src
        )
        
        # Add general flow rule with lower priority
        self.add_flow(datapath, 90, general_match, actions, idle_timeout=300)
        
        # Create a copy of the current packet and modify it
        eth = ip_pkt.get_protocols(ethernet.ethernet)[0]
        ip_header = ip_pkt.get_protocol(ipv4.ipv4)
        eth.dst = self.honeypot_mac
        ip_header.dst = self.honeypot_ip
        
        # Send the modified packet to the honeypot
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=ip_pkt.serialize()
        )
        datapath.send_msg(out)
        
        self.logger.warning(f"Redirected packet from {ip_pkt.src} to honeypot IP {self.honeypot_ip}, MAC {self.honeypot_mac} on port {self.honeypot_port}")
        return actions

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.debug("packet in %s %s %s %s", dpid, src, dst, in_port)

        # Learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        
        # Check if this is the honeypot MAC address (if on switch 14)
        if dpid == 14 and src_ip == self.honeypot_ip:
            self.honeypot_mac = src
            self.honeypot_port = in_port
            self.has_verified_honeypot = True
            self.logger.info(f"VERIFIED HONEYPOT CONNECTION: MAC={src}, port={in_port}, switch={dpid}")
            
            # Update config
            try:
                config_file = os.path.join(os.path.dirname(__file__), '../config/honeypot_config.json')
                config_data = {
                    'honeypot_ip': self.honeypot_ip,
                    'honeypot_mac': self.honeypot_mac,
                    'honeypot_port': self.honeypot_port
                }
                with open(config_file, 'w') as f:
                    json.dump(config_data, f, indent=4)
            except Exception as e:
                self.logger.error(f"Error updating honeypot config: {e}")

        # Check if the packet is IPv4 for further processing
        ip_header = pkt.get_protocol(ipv4.ipv4)
        if ip_header:
            src_ip = ip_header.src
            dst_ip = ip_header.dst
            protocol_num = ip_header.proto
            
            # Get transport layer info
            tcp_header = pkt.get_protocol(tcp.tcp)
            udp_header = pkt.get_protocol(udp.udp)
            icmp_header = pkt.get_protocol(icmp.icmp)
            
            src_port = 0
            dst_port = 0
            protocol_str = str(protocol_num)
            
            if tcp_header:
                src_port = tcp_header.src_port
                dst_port = tcp_header.dst_port
                protocol_str = 'tcp'
                protocol_num = 6  # Ensure consistent protocol number for TCP
                
                # Extract HTTP payload data from TCP packets for traffic going to HTTP ports
                if dst_port == 8080 or dst_port == 80 or dst_port == 443:
                    try:
                        # Check for payload data
                        payload_data = None
                        for p in pkt:
                            if hasattr(p, 'data') and p.data:
                                payload_data = p.data
                                break
                                
                        if payload_data:
                            # Try to decode as string (for HTTP requests)
                            try:
                                # Convert binary data to string, replace invalid bytes
                                payload_str = payload_data.decode('utf-8', errors='replace')
                                
                                # Check if it's an HTTP request
                                if payload_str.startswith('GET ') or payload_str.startswith('POST ') or \
                                   payload_str.startswith('PUT ') or payload_str.startswith('DELETE '):
                                    # Store payload for this IP
                                    self.last_tcp_payload[src_ip] = payload_str
                                    
                                    # Enhanced pattern detection specifically for simple_attack.py
                                    # Log suspicious URL patterns
                                    suspicious_patterns = {
                                        'sql_injection': ['%20OR%20', "'OR'", '1=1', 'OR%201'],
                                        'path_traversal': ['../..', '%2e%2e', 'etc/passwd'],
                                        'cmd_injection': ['cmd=', ';', '&&', '||'],
                                        'xss': ['<script>', 'alert', '%3cscript%3e']
                                    }
                                    
                                    # Extract the request URL
                                    try:
                                        url_part = payload_str.split(' ')[1]
                                        for attack_type, patterns in suspicious_patterns.items():
                                            for pattern in patterns:
                                                if pattern in url_part:
                                                    self.logger.warning(f"Suspicious {attack_type} pattern detected in URL from {src_ip}: {url_part}")
                                                    
                                                    # Add to suspected IPs for faster processing
                                                    if src_ip not in self.suspected_ips:
                                                        self.suspected_ips.add(src_ip)
                                                        self.logger.warning(f"Added {src_ip} to suspected IPs list due to detected attack pattern")

                                                    # Immediately mark as suspicious for redirection
                                                    is_suspicious = True
                                                    
                                                    # Redirect to honeypot
                                                    self.redirect_to_honeypot_direct(datapath, parser, pkt, ip_header, src_ip, dst_ip, in_port)
                                                    return
                                    except Exception as e:
                                        self.logger.debug(f"Error parsing URL part: {e}")
                            except Exception as e:
                                # If we can't decode it, it's probably not an HTTP request
                                self.logger.debug(f"Error decoding payload: {e}")
                    except Exception as e:
                        # Don't let payload extraction errors affect packet handling
                        self.logger.debug(f"Error extracting payload: {e}")

            # For all IP packets, not just TCP
            if dst_ip == self.honeypot_ip:
                # This packet is already going to the honeypot, let it through
                self.logger.info(f"Direct traffic to honeypot: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                if dst in self.mac_to_port[dpid]:
                    out_port = self.mac_to_port[dpid][dst]
                else:
                    out_port = ofproto.OFPP_FLOOD
                
                actions = [parser.OFPActionOutput(out_port)]
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data
                    
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                        in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
                return
            
            # Proceed with normal traffic handling
            self.handle_ip_traffic(msg, datapath, ofproto, parser, pkt, eth, in_port, dpid, 
                               ip_header, src_ip, dst_ip, 
                               tcp_header, udp_header, icmp_header, 
                               src_port, dst_port, protocol_str, protocol_num)
            return
        
        # For non-IP packets (e.g., ARP)
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def handle_ip_traffic(self, msg, datapath, ofproto, parser, pkt, eth, in_port, dpid,
                        ip_header, src_ip, dst_ip, 
                        tcp_header, udp_header, icmp_header,
                        src_port, dst_port, protocol_str, protocol_num):
        """Handle IP traffic separately for better organization"""
        # Log the packet details at INFO level for all HTTP traffic
        if dst_port == 8080 or dst_port == 80 or dst_port == 443:
            self.logger.info(f"HTTP(S) Traffic: {src_ip}:{src_port} -> {dst_ip}:{dst_port} via {protocol_str}, MAC: {eth.src}")
        
        # Skip ARP, DNS, and network infrastructure traffic
        if protocol_str == 'icmp' or dst_port == 53:
            # Allow ICMP and DNS traffic without additional checks
            pass
        else:
            # Modified to no longer check for specific IPs like external1
            # All traffic including external1 should now be evaluated by ML model
            is_suspicious = False
            
            # Check basic rule table for suspicious patterns
            packet_info = {
                'src_ip': src_ip, 
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol_str,
                'src_mac': eth.src
            }
            
            # Add payload data if available for URL pattern matching
            if src_ip in self.last_tcp_payload:
                packet_info['payload'] = self.last_tcp_payload[src_ip]
            
            rule_result = self.check_rule_table(packet_info)
            if rule_result == 'bad':
                is_suspicious = True
                self.logger.warning(f"Rule-based detection marked traffic as suspicious: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            elif rule_result == 'unknown':
                # Only query ML model if rule-based detection is inconclusive
                if protocol_str in ['tcp', 'udp']:
                    # Use ML model to determine if traffic is suspicious
                    is_suspicious = self.query_ml_model(src_ip, dst_ip, src_port, dst_port, protocol_str)
                    if is_suspicious:
                        self.logger.warning(f"ML-based detection marked traffic as suspicious: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            
            # Add specific attack pattern detection for external traffic to internal hosts
            if not is_suspicious and src_ip.startswith("10.0.0.") and int(src_ip.split(".")[-1]) >= 9:
                # This is traffic from potential external hosts (external1, external2, etc.)
                if dst_port == 8080:
                    # HTTP traffic to internal web servers - check for attack signatures
                    if src_ip in self.last_tcp_payload:
                        payload = self.last_tcp_payload[src_ip]
                        # Look for suspicious patterns in HTTP requests
                        if ('?id=' in payload and ('OR 1=1' in payload or "'" in payload)) or \
                           ('cmd=' in payload) or \
                           ('../' in payload) or \
                           ('<script>' in payload):
                            is_suspicious = True
                            self.logger.warning(f"Attack signature detected in HTTP traffic from {src_ip}")
            
            # Redirect suspicious traffic to honeypot
            if is_suspicious:
                self.redirect_to_honeypot_direct(datapath, parser, pkt, ip_header, src_ip, dst_ip, in_port)
                return

        # Handle regular traffic
        if eth.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth.dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def redirect_to_honeypot_direct(self, datapath, parser, pkt, ip_header, src_ip, dst_ip, in_port):
        """Direct method to redirect traffic to honeypot"""
        # Verify that we have the necessary honeypot information
        if not self.has_verified_honeypot:
            self.logger.warning("Attempting to redirect but honeypot not verified yet")
            # Try to use config values
            try:
                config_file = os.path.join(os.path.dirname(__file__), '../config/honeypot_config.json')
                if os.path.exists(config_file):
                    with open(config_file, 'r') as f:
                        config = json.load(f)
                    self.honeypot_mac = config.get('honeypot_mac', self.honeypot_mac)
                    self.honeypot_port = config.get('honeypot_port', self.honeypot_port)
                    self.has_verified_honeypot = True
                    self.logger.info(f"Loaded honeypot config: MAC={self.honeypot_mac}, port={self.honeypot_port}")
            except Exception as e:
                self.logger.error(f"Error loading honeypot config: {e}")
                
        # Check if we have valid honeypot MAC and port now
        if not self.honeypot_mac or not self.honeypot_port:
            self.logger.error("Cannot redirect - honeypot MAC or port not set")
            return
            
        # Debug info - print the honeypot details
        self.logger.warning(f"DEBUG - Honeypot details: IP={self.honeypot_ip}, MAC={self.honeypot_mac}, PORT={self.honeypot_port}")
            
        # Log the redirection clearly
        self.logger.warning(f"REDIRECTING SUSPICIOUS TRAFFIC: {src_ip} -> {dst_ip} TO HONEYPOT IP {self.honeypot_ip}")
        
        # Extract ethernet header
        eth_header = pkt.get_protocols(ethernet.ethernet)[0]
        
        # Debug - show original destination
        self.logger.warning(f"DEBUG - Original destination: MAC={eth_header.dst}, IP={ip_header.dst}")
        
        # Modify packet destination to honeypot
        eth_header.dst = self.honeypot_mac
        ip_header.dst = self.honeypot_ip
        
        # Define actions to modify the packet
        actions = [
            parser.OFPActionSetField(eth_dst=self.honeypot_mac),
            parser.OFPActionSetField(ipv4_dst=self.honeypot_ip),
            parser.OFPActionOutput(self.honeypot_port)
        ]
        
        # Install flow rules for this specific connection
        ofproto = datapath.ofproto
        
        # Generic match for all traffic from this source IP
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=src_ip
        )
        
        # Add flow with high priority and timeout
        self.add_flow(datapath, 100, match, actions, idle_timeout=300)
        
        # Send this specific packet to the honeypot
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=pkt.serialize()
        )
        datapath.send_msg(out)
        
        self.logger.warning(f"Redirected packet from {src_ip} to honeypot IP {self.honeypot_ip}, MAC {self.honeypot_mac}, PORT {self.honeypot_port}")
        self.redirected_connections += 1

# --- REST API Controller --- #

class RestController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(RestController, self).__init__(req, link, data, **config)
        self.my_controller_app = data['my_controller_app']

    @route('api', '/api/status', methods=['GET'])
    def get_status(self, req, **kwargs):
        # Use Response(json=...) for automatic serialization and content-type/charset
        return Response(json={'status': 'Controller Running'})

    @route('api', '/api/switches', methods=['GET'])
    def list_switches(self, req, **kwargs):
        # The main app needs to store datapath objects when switches connect
        # For now, we'll just return the keys from mac_to_port as DPIDs
        dpids = list(self.my_controller_app.mac_to_port.keys())
        # Use Response(json=...)
        return Response(json={'switches': dpids})

    @route('api', '/api/mac_table', methods=['GET'])
    def get_mac_table(self, req, **kwargs):
        # Return the learned MAC table
        mac_table = self.my_controller_app.mac_to_port
        # Use Response(json=...)
        return Response(json={'mac_table': mac_table})

    @route('api', '/api/hosts', methods=['GET'])
    def list_hosts(self, req, **kwargs):
        hosts_data = {}
        for host in self.my_controller_app.expected_hosts:
            # Add IP address to the host status dictionary
            hosts_data[host] = {
                'status': 'connected', # Assuming connected if controller is up
                'ip': self.my_controller_app.host_ips.get(host, 'N/A')
            }
        return Response(json={'hosts': hosts_data})

    @route('api', '/api/logs', methods=['GET'])
    def get_logs(self, req, **kwargs):
        log_lines = []
        num_lines = 20 # Number of lines to retrieve
        try:
            with open(CONTROLLER_LOG_PATH, 'r') as f:
                # Read all lines and take the last N
                # This is less efficient than tail for huge files, but more robust here
                all_lines = f.readlines()
                log_lines = [line.strip() for line in all_lines[-num_lines:]]
        except FileNotFoundError:
            log_lines = [f"Log file not found at {CONTROLLER_LOG_PATH}"]
        except Exception as e:
            log_lines = [f"Error reading log: {e}"]
        return Response(json={'logs': log_lines})

    @route('api', '/api/ml_logs', methods=['GET'])
    def get_ml_logs(self, req, **kwargs):
        log_lines = []
        num_lines = 20 # Number of lines to retrieve
        try:
            # Ensure file exists before trying to open
            if os.path.exists(ML_MODEL_LOG_PATH):
                 with open(ML_MODEL_LOG_PATH, 'r') as f:
                    all_lines = f.readlines()
                    log_lines = [line.strip() for line in all_lines[-num_lines:]]
            else:
                log_lines = [f"ML Log file not found at {ML_MODEL_LOG_PATH}"]
        except Exception as e:
            log_lines = [f"Error reading ML log: {e}"]
        return Response(json={'ml_logs': log_lines})

    @route('api', '/api/host15_honeypot_logs', methods=['GET'])
    def get_host15_honeypot_logs(self, req, **kwargs):
        log_lines = []
        num_lines = 50 # Show more lines for honeypot
        try:
            if os.path.exists(HOST15_HONEYPOT_LOG_PATH):
                with open(HOST15_HONEYPOT_LOG_PATH, 'r') as f:
                    all_lines = f.readlines()
                    log_lines = [line.strip() for line in all_lines[-num_lines:]]
            else:
                log_lines = [f"Host15 Honeypot Log file not found at {HOST15_HONEYPOT_LOG_PATH}"]
        except Exception as e:
            log_lines = [f"Error reading Host15 Honeypot log: {e}"]
        return Response(json={'host15_honeypot_logs': log_lines})

    # Removed get_honeypot_logs endpoint
    # @route('api', '/api/honeypot_logs', methods=['GET'])
    # def get_honeypot_logs(self, req, **kwargs):
    #     log_lines = []
    #     num_lines = 20 # Number of lines to retrieve
    #     try:
    #         with open(HONEYPOT_LOG_PATH, 'r') as f:
    #             all_lines = f.readlines()
    #             log_lines = [line.strip() for line in all_lines[-num_lines:]]
    #     except FileNotFoundError:
    #         log_lines = [f"Honeypot Log file not found at {HONEYPOT_LOG_PATH}"]
    #     except Exception as e:
    #         log_lines = [f"Error reading honeypot log: {e}"]
    #     return Response(json={'honeypot_logs': log_lines})

# Make sure Response is imported if not already available globally in this context
# Depending on WSGI implementation, might need:
from webob import Response

# Note: Need to ensure the main MyController class updates self.mac_to_port
# correctly when switches connect/disconnect and hosts are learned.