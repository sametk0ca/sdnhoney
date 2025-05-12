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

# --- SDN Controller for Two-Stage Honeypot Architecture ---
# - Stage 1: Rule-based logic (controller) decides if traffic is suspicious
# - Stage 2: Suspicious traffic is redirected to triage honeypot (h15)
# - Stage 3: ML model is called for traffic in h15; if malicious, redirect to hard honeypot (h16)
# - All MAC/port learning is dynamic; no hardcoding

class MyController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(MyController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.arp_table = {}
        self.host_state = {}  # {src_ip: 'normal'|'triage'|'hard'}
        self.honeypots = {
            'triage': {'ip': '10.0.0.15', 'mac': None, 'port': None},
            'hard':   {'ip': '10.0.0.16', 'mac': None, 'port': None},
        }
        self.has_verified_honeypots = {'triage': False, 'hard': False}
        self.wsgi = kwargs['wsgi']
        self.wsgi.register(RestController, {'my_controller_app': self})
        # ML model gRPC client setup (for triage stage)
        self.ml_channel = grpc.insecure_channel('localhost:50051')
        self.ml_stub = ml_model_pb2_grpc.MLModelServiceStub(self.ml_channel)
        self.logger.info("Controller initialized for two-stage honeypot.")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # Only install default rule: send all to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst)
        datapath.send_msg(mod)
        self.logger.info(f"Default flow installed on switch {datapath.id}")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        # --- ARP Handling ---
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkt = pkt.get_protocol(arp.arp)
            src_ip = arp_pkt.src_ip
            src_mac = arp_pkt.src_mac
            dst_ip = arp_pkt.dst_ip
            dst_mac = arp_pkt.dst_mac
            opcode = arp_pkt.opcode
            self.arp_table[src_ip] = src_mac
            self.mac_to_port.setdefault(dpid, {})
            self.mac_to_port[dpid][src_mac] = in_port
            if opcode == arp.ARP_REQUEST:
                if dst_ip in self.arp_table and self.arp_table[dst_ip] in self.mac_to_port[dpid]:
                    out_port = self.mac_to_port[dpid][self.arp_table[dst_ip]]
                else:
                    out_port = ofproto.OFPP_FLOOD
                actions = [parser.OFPActionOutput(out_port)]
            elif opcode == arp.ARP_REPLY:
                if dst_mac in self.mac_to_port[dpid]:
                    out_port = self.mac_to_port[dpid][dst_mac]
                else:
                    out_port = ofproto.OFPP_FLOOD
                actions = [parser.OFPActionOutput(out_port)]
            else:
                return
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=in_port, actions=actions, data=msg.data)
            datapath.send_msg(out)
            return
        # --- MAC learning ---
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        # --- IP Handling ---
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            self._fwd_l2(datapath, eth, in_port, ofproto, parser, msg)
            return
        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        # --- Honeypot MAC/port learning ---
        for hp_name, hp in self.honeypots.items():
            if src_ip == hp['ip'] and not self.has_verified_honeypots[hp_name]:
                self.honeypots[hp_name]['mac'] = eth.src
                self.honeypots[hp_name]['port'] = in_port
                self.has_verified_honeypots[hp_name] = True
                self.logger.info(f"Learned {hp_name} honeypot: MAC={eth.src}, port={in_port}, switch={dpid}")
        # --- Stage 1: Rule-based classification ---
        state = self.host_state.get(src_ip, 'normal')
        if state == 'hard':
            self._redirect_to_honeypot('hard', datapath, parser, pkt, ip_pkt, eth, in_port)
            return
        elif state == 'triage':
            ml_result = self._query_ml_model(ip_pkt, pkt)
            if ml_result == 'malicious':
                self.host_state[src_ip] = 'hard'
                self._redirect_to_honeypot('hard', datapath, parser, pkt, ip_pkt, eth, in_port)
                return
            elif ml_result == 'benign':
                self.host_state[src_ip] = 'normal'
        else:
            if self._is_suspicious(ip_pkt, pkt):
                self.host_state[src_ip] = 'triage'
                self._redirect_to_honeypot('triage', datapath, parser, pkt, ip_pkt, eth, in_port)
                return
        self._fwd_l3(datapath, eth, ip_pkt, in_port, ofproto, parser, msg)

    def _is_suspicious(self, ip_pkt, pkt):
        # Simple rule-based logic (customize as needed)
        if ip_pkt.proto == 1:  # ICMP
            return False
        if ip_pkt.dst == self.honeypots['triage']['ip'] or ip_pkt.dst == self.honeypots['hard']['ip']:
            return False
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if tcp_pkt and tcp_pkt.dst_port not in [80, 8080, 443]:
            return True
        return False

    def _query_ml_model(self, ip_pkt, pkt):
        try:
            req = ml_model_pb2.PacketInfo(
                src_ip=ip_pkt.src,
                dst_ip=ip_pkt.dst,
                src_port=getattr(pkt.get_protocol(tcp.tcp), 'src_port', 0),
                dst_port=getattr(pkt.get_protocol(tcp.tcp), 'dst_port', 0),
                protocol='tcp' if pkt.get_protocol(tcp.tcp) else 'udp' if pkt.get_protocol(udp.udp) else 'icmp',
            )
            resp = self.ml_stub.PredictPacket(req)
            return 'malicious' if resp.is_suspicious else 'benign'
        except Exception as e:
            self.logger.error(f"ML model error: {e}")
            return 'benign'

    def _redirect_to_honeypot(self, hp_name, datapath, parser, pkt, ip_pkt, eth, in_port):
        hp = self.honeypots[hp_name]
        if not (hp['mac'] and hp['port']):
            self.logger.warning(f"Honeypot {hp_name} not yet learned. Flooding.")
            out_port = datapath.ofproto.OFPP_FLOOD
        else:
            out_port = hp['port']
        actions = [parser.OFPActionSetField(eth_dst=hp['mac']),
                   parser.OFPActionSetField(ipv4_dst=hp['ip']),
                   parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                                 in_port=in_port, actions=actions, data=pkt.data)
        datapath.send_msg(out)
        self.logger.info(f"Redirected {ip_pkt.src} to {hp_name} honeypot at {hp['ip']}")

    def _fwd_l2(self, datapath, eth, in_port, ofproto, parser, msg):
        dpid = datapath.id
        dst = eth.dst
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                 in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)

    def _fwd_l3(self, datapath, eth, ip_pkt, in_port, ofproto, parser, msg):
        dpid = datapath.id
        dst_mac = eth.dst
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]
        match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                               eth_src=eth.src, eth_dst=eth.dst, ipv4_dst=ip_pkt.dst)
        self.add_flow(datapath, 1, match, actions, idle_timeout=60, hard_timeout=300)
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                 in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst,
                               idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        datapath.send_msg(mod)

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

    @route('api', '/api/host_states', methods=['GET'])
    def get_host_states(self, req, **kwargs):
        # Return the current state of all source IPs
        return Response(json=self.my_controller_app.host_state)

    @route('api', '/api/honeypots', methods=['GET'])
    def get_honeypots(self, req, **kwargs):
        # Return info about both honeypots
        return Response(json=self.my_controller_app.honeypots)

    @route('api', '/api/host15_honeypot_logs', methods=['GET'])
    def get_host15_honeypot_logs(self, req, **kwargs):
        # Return last 50 lines of h15 honeypot log
        log_path = 'logs/host15_honeypot.log'
        num_lines = 50
        try:
            with open(log_path, 'r') as f:
                lines = f.readlines()[-num_lines:]
        except Exception as e:
            lines = [f"Error reading log: {e}"]
        return Response(json={'host15_honeypot_logs': lines})

    @route('api', '/api/host16_honeypot_logs', methods=['GET'])
    def get_host16_honeypot_logs(self, req, **kwargs):
        # Return last 50 lines of h16 honeypot log
        log_path = 'logs/host16_honeypot.log'
        num_lines = 50
        try:
            with open(log_path, 'r') as f:
                lines = f.readlines()[-num_lines:]
        except Exception as e:
            lines = [f"Error reading log: {e}"]
        return Response(json={'host16_honeypot_logs': lines})

# Make sure Response is imported if not already available globally in this context
# Depending on WSGI implementation, might need:
from webob import Response

# Note: Need to ensure the main MyController class updates self.mac_to_port
# correctly when switches connect/disconnect and hosts are learned.