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
CONTROLLER_LOG_PATH = os.path.join(PROJECT_ROOT, 'logs', 'controller.log')
ML_MODEL_LOG_PATH = os.path.join(PROJECT_ROOT, 'logs', 'ml_model.log')
HOST8_HONEYPOT_LOG_PATH = os.path.join(PROJECT_ROOT, 'logs', 'host8_honeypot.log')
# Define path for Honeypot log - REMOVED
# HONEYPOT_LOG_PATH = os.path.join(PROJECT_ROOT, 'honeypot', 'log', 'glastopf.log')

class MyController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    # Tell Ryu to instantiate our RestController
    _CONTEXTS = {
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(MyController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.suspected_ips = set()
        self.known_ips = set()
        # Define expected hosts based on topology
        self.expected_hosts = [f'h{i}' for i in range(1, 9)] + ['external1', 'external2']
        # Map hostnames to IPs (needed for tooltips)
        self.host_ips = {
            'h1': '10.0.0.1', 'h2': '10.0.0.2', 'h3': '10.0.0.3', 'h4': '10.0.0.4',
            'h5': '10.0.0.5', 'h6': '10.0.0.6', 'h7': '10.0.0.7', 'h8': '10.0.0.8',
            'external1': '10.0.0.9', 'external2': '10.0.0.10'
        }
        
        # Updated rule table to focus on HTTP traffic
        self.rule_table = {
            # Known good patterns (legitimate HTTP traffic)
            'good': [
                {'protocol': 'tcp', 'dst_port': 8080},    # HTTP
                {'protocol': 'tcp', 'dst_port': 443},     # HTTPS
                {'protocol': 'udp', 'dst_port': 53},      # DNS (needed for hostname resolution)
                {'protocol': 'icmp'},                     # Allow ping for network diagnostics
                # Trusted internal hosts
                {'src_ip': '10.0.0.1', 'protocol': 'tcp', 'dst_port': 8080},  # h1 to HTTP
                {'src_ip': '10.0.0.2', 'protocol': 'tcp', 'dst_port': 8080},  # h2 to HTTP
                {'src_ip': '10.0.0.3', 'protocol': 'tcp', 'dst_port': 8080},  # h3 to HTTP
                {'src_ip': '10.0.0.4', 'protocol': 'tcp', 'dst_port': 8080},  # h4 to HTTP
                {'src_ip': '10.0.0.5', 'protocol': 'tcp', 'dst_port': 8080},  # h5 to HTTP
                {'src_ip': '10.0.0.6', 'protocol': 'tcp', 'dst_port': 8080},  # h6 to HTTP
                {'src_ip': '10.0.0.7', 'protocol': 'tcp', 'dst_port': 8080},  # h7 to HTTP
            ],
            # Known bad patterns (immediately redirect to honeypot)
            'bad': [
                # Force mark external1 as suspicious for testing
                {'src_ip': '10.0.0.9'},  # external1 - we know it's malicious for testing
                {'src_ip': '10.0.0.11'},  # attack simulator - mark all traffic as malicious
                
                # Non-HTTP services - redirect to honeypot as these shouldn't be accessed
                {'protocol': 'tcp', 'dst_port': 22},    # SSH
                {'protocol': 'tcp', 'dst_port': 23},    # Telnet
                {'protocol': 'tcp', 'dst_port': 445},   # SMB
                {'protocol': 'tcp', 'dst_port': 3389},  # RDP
                {'protocol': 'tcp', 'dst_port': 3306},  # MySQL
                {'protocol': 'tcp', 'dst_port': 5432},  # PostgreSQL
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
            self.channel = grpc.insecure_channel('localhost:50051')
            self.stub = ml_model_pb2_grpc.MLModelServiceStub(self.channel)
            logging.info("gRPC connection successful")
        except Exception as e:
            logging.error(f"gRPC connection error: {e}")
        
        # Add HTTP request tracking for rate limiting
        self.http_request_count = {}  # {ip: {"count": n, "last_reset": timestamp}}
        
        logging.info("SDN Controller started - HTTP Honeypot Mode")
        logging.info(f"Honeypot settings - IP: {self.honeypot_ip}, Port: {self.honeypot_port}")
        
        # Force external1 into suspected IPs list for testing
        self.suspected_ips.add('10.0.0.9')
        self.suspected_ips.add('10.0.0.11')  # Also add attack simulator IP

    def reload_config(self):
        """Reload configuration from the controller_config.ini file"""
        config = configparser.ConfigParser()
        config_path = os.path.join(os.path.dirname(__file__), 'controller_config.ini')
        
        if not os.path.exists(config_path):
            self.logger.error(f"Config file not found at {config_path}")
            # Set default values
            self.honeypot_ip = '10.0.0.8'
            self.honeypot_mac = '00:00:00:00:00:08'
            self.honeypot_port = 8
            return
        
        try:
            config.read(config_path)
            self.honeypot_ip = config.get('Network', 'honeypot_ip', fallback='10.0.0.8')
            self.honeypot_mac = config.get('Network', 'honeypot_mac', fallback='00:00:00:00:00:08')
            self.honeypot_port = int(config.get('Network', 'honeypot_port', fallback='8'))
            self.logger.info(f"Loaded config: honeypot_ip={self.honeypot_ip}, honeypot_mac={self.honeypot_mac}, honeypot_port={self.honeypot_port}")
        except Exception as e:
            self.logger.error(f"Error loading config: {e}")
            # Set default values
            self.honeypot_ip = '10.0.0.8'
            self.honeypot_mac = '00:00:00:00:00:08'
            self.honeypot_port = 8

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
            
        # Check if source IP is in suspected IPs list
        src_ip = packet_info.get('src_ip')
        if src_ip in self.suspected_ips:
            self.logger.warning(f"Suspected IP detected: {src_ip}")
            return 'bad'
            
        # Log external1 traffic for debugging
        if src_ip == '10.0.0.9':
            self.logger.info(f"External1 traffic: {packet_info}")
        
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
                if key not in packet_info or packet_info[key] != value:
                    match = False
                    break
                    
            if match:
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
        if now - self.http_request_count[ip]["last_reset"] > 60:
            self.http_request_count[ip] = {"count": 1, "last_reset": now}
            return False
            
        # Increment the counter
        self.http_request_count[ip]["count"] += 1
        
        # Check if over the limit (50 requests per minute)
        if self.http_request_count[ip]["count"] > 50:
            return True
            
        return False

    def query_ml_model(self, src_ip, dst_ip, src_port, dst_port, protocol):
        """Query ML model for traffic classification
        
        This function attempts to identify malicious traffic that doesn't have
        obvious attack signatures by analyzing traffic patterns.
        """
        # Always allow ICMP traffic for basic connectivity
        if protocol == 'icmp':
            return False  # Not suspicious
        
        # Track HTTP request frequency for rate limiting detection
        if protocol == 'tcp' and (dst_port == 80 or dst_port == 8080 or dst_port == 443):
            # Check if source IP is making too many requests in a short time
            if self.check_rate_limit(src_ip):
                self.logger.warning(f"Rate limit exceeded for {src_ip}")
                return True
            
        # Prepare packet info for ML model
        packet_info = ml_model_pb2.PacketInfo(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol
        )
        
        try:
            response = self.stub.PredictPacket(packet_info, timeout=1.0)
            is_suspicious = response.is_suspicious
            confidence = response.confidence
            
            # Log prediction details
            if is_suspicious:
                self.logger.warning(f"ML model prediction: SUSPICIOUS traffic from {src_ip}:{src_port} to {dst_ip}:{dst_port} ({protocol}) - Confidence: {confidence:.2f}")
                # Add to suspicious IPs if not already there
                if src_ip not in self.suspected_ips:
                    self.suspected_ips.add(src_ip)
            else:
                self.logger.info(f"ML model prediction: BENIGN traffic from {src_ip}:{src_port} to {dst_ip}:{dst_port} ({protocol}) - Confidence: {confidence:.2f}")
                # Add to known IPs for faster processing next time
                if confidence > 0.8 and src_ip not in self.known_ips:
                    self.known_ips.add(src_ip)
            
            return is_suspicious
        except grpc.RpcError as e:
            self.logger.error(f"gRPC error when querying ML model: {e}")
            # Conservative approach: when ML model fails, consider suspicious
            # for non-standard ports or protocols
            if dst_port not in [80, 443, 8080, 53, 22, 23]:
                return True
            return False  # Default to allowing common services

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

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # Check if the packet is IPv4
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
            elif udp_header:
                src_port = udp_header.src_port
                dst_port = udp_header.dst_port
                protocol_str = 'udp'
                protocol_num = 17  # Ensure consistent protocol number for UDP
            elif icmp_header:
                src_port = icmp_header.type
                dst_port = icmp_header.code
                protocol_str = 'icmp'
                protocol_num = 1  # Ensure consistent protocol number for ICMP
            
            # Log the packet details at INFO level for all HTTP traffic
            if dst_port == 8080 or dst_port == 80 or dst_port == 443:
                self.logger.info(f"HTTP(S) Traffic: {src_ip}:{src_port} -> {dst_ip}:{dst_port} via {protocol_str}")
            
            # Skip ARP, DNS, and network infrastructure traffic
            if protocol_str == 'icmp' or dst_port == 53:
                # Allow ICMP and DNS traffic without additional checks
                pass
            else:
                # Check if source IP is already known to be suspicious (external1 or attack simulator)
                # This is a fast path for known bad actors
                is_suspicious = False
                if src_ip in self.suspected_ips or src_ip == '10.0.0.9' or src_ip == '10.0.0.11':
                    is_suspicious = True
                    self.logger.warning(f"Known suspicious IP detected: {src_ip}")
                    if src_ip not in self.suspected_ips:
                        self.suspected_ips.add(src_ip)
                else:
                    # Check basic rule table for suspicious patterns
                    packet_info = {
                        'src_ip': src_ip, 
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'protocol': protocol_str
                    }
                    
                    rule_result = self.check_rule_table(packet_info)
                    if rule_result == 'bad':
                        is_suspicious = True
                        self.logger.warning(f"Rule-based detection marked traffic as suspicious: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                
                # Redirect suspicious traffic to honeypot
                if is_suspicious:
                    self.logger.warning(f"REDIRECTING SUSPICIOUS TRAFFIC: {src_ip}:{src_port} -> {dst_ip}:{dst_port} TO HONEYPOT IP {self.honeypot_ip}")
                    
                    # Get MAC address of the honeypot from config
                    honeypot_mac = self.honeypot_mac
                    honeypot_ip = self.honeypot_ip
                    honeypot_port = self.honeypot_port
                    
                    # Install specific flow rule for this connection
                    if tcp_header:
                        match = parser.OFPMatch(
                            eth_type=ether_types.ETH_TYPE_IP,
                            ipv4_src=src_ip,
                            ip_proto=protocol_num,
                            tcp_src=src_port,
                            tcp_dst=dst_port
                        )
                    elif udp_header:
                        match = parser.OFPMatch(
                            eth_type=ether_types.ETH_TYPE_IP,
                            ipv4_src=src_ip,
                            ip_proto=protocol_num,
                            udp_src=src_port,
                            udp_dst=dst_port
                        )
                    else:
                        # Generic IP match if not TCP/UDP
                        match = parser.OFPMatch(
                            eth_type=ether_types.ETH_TYPE_IP,
                            ipv4_src=src_ip
                        )
                    
                    # Define actions to modify the packet
                    actions = [
                        parser.OFPActionSetField(eth_dst=honeypot_mac),
                        parser.OFPActionSetField(ipv4_dst=honeypot_ip),
                        parser.OFPActionOutput(honeypot_port)
                    ]
                    
                    # Add flow to direct all traffic from this source to honeypot
                    self.add_flow(datapath, 100, match, actions, idle_timeout=300)
                    
                    # Install a more general flow rule for all traffic from this IP
                    general_match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=src_ip
                    )
                    
                    # Add general flow rule with lower priority
                    self.add_flow(datapath, 90, general_match, actions, idle_timeout=300)
                    
                    # Create a copy of the current packet and modify it
                    eth.dst = honeypot_mac
                    ip_header.dst = honeypot_ip
                    
                    # Send the modified packet to the honeypot
                    out = parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=in_port,
                        actions=actions,
                        data=pkt.serialize()
                    )
                    datapath.send_msg(out)
                    
                    self.logger.warning(f"Redirected packet from {src_ip} to honeypot IP {self.honeypot_ip}, MAC {self.honeypot_mac} on port {honeypot_port}")
                    return

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

    @route('api', '/api/host8_honeypot_logs', methods=['GET'])
    def get_host8_honeypot_logs(self, req, **kwargs):
        log_lines = []
        num_lines = 50 # Show more lines for honeypot
        try:
            if os.path.exists(HOST8_HONEYPOT_LOG_PATH):
                with open(HOST8_HONEYPOT_LOG_PATH, 'r') as f:
                    all_lines = f.readlines()
                    log_lines = [line.strip() for line in all_lines[-num_lines:]]
            else:
                log_lines = [f"Host8 Honeypot Log file not found at {HOST8_HONEYPOT_LOG_PATH}"]
        except Exception as e:
            log_lines = [f"Error reading Host8 Honeypot log: {e}"]
        return Response(json={'host8_honeypot_logs': log_lines})

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