#!/usr/bin/env python3

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import arp
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response
import json
import time
import threading
from collections import defaultdict
import requests

# Host mapping for our topology
HOSTS = {
    '10.0.0.1': {'name': 'h1', 'type': 'normal_server', 'port': 8001, 'mac': '00:00:00:00:00:01'},
    '10.0.0.2': {'name': 'h2', 'type': 'normal_server', 'port': 8002, 'mac': '00:00:00:00:00:02'},
    '10.0.0.3': {'name': 'h3', 'type': 'normal_server', 'port': 8003, 'mac': '00:00:00:00:00:03'},
    '10.0.0.4': {'name': 'h4', 'type': 'triage_honeypot', 'port': 8004, 'mac': '00:00:00:00:00:04'},
    '10.0.0.5': {'name': 'h5', 'type': 'deep_honeypot', 'port': 8005, 'mac': '00:00:00:00:00:05'},
    '10.0.0.6': {'name': 'h6', 'type': 'external_source', 'port': None, 'mac': '00:00:00:00:00:06'},
}

# Load balancing for normal servers
NORMAL_SERVERS = ['10.0.0.1', '10.0.0.2', '10.0.0.3']
TRIAGE_HONEYPOT = '10.0.0.4'
DEEP_HONEYPOT = '10.0.0.5'

class HoneypotSDNController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(HoneypotSDNController, self).__init__(*args, **kwargs)
        
        # MAC learning table
        self.mac_to_port = {}
        
        # Traffic analysis
        self.suspicious_ips = set()
        self.malicious_ips = set()
        self.traffic_stats = defaultdict(lambda: {'packets': 0, 'last_seen': 0})
        self.load_balancer_index = 0
        
        # Flow tracking for analysis
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'request_rate': 0,
            'last_packet_time': 0,
            'classification': 'normal'
        })
        
        # Initialize baseline active IPs from topology
        self._initialize_baseline_ips()
        
        # Start monitoring thread
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        
        # Setup REST API
        wsgi = kwargs['wsgi']
        wsgi.register(HoneypotController, {'controller': self})
        
        self.logger.info("Honeypot SDN Controller initialized")

    def _initialize_baseline_ips(self):
        """Initialize all host IPs as active for baseline monitoring"""
        current_time = time.time()
        
        # Mark all host IPs as active (except h6 which is external source)
        baseline_ips = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4', '10.0.0.5', '10.0.0.6']
        
        for ip in baseline_ips:
            self.traffic_stats[ip] = {
                'packets': 1,  # Initialize with 1 packet to show as active
                'last_seen': current_time
            }
        
        self.logger.info(f"Initialized {len(baseline_ips)} baseline active IPs")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch connection with improved flow installation"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info(f"Switch s{datapath.id} connected - installing flows")

        # Install default flow to controller (lowest priority)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        # Install tree topology forwarding flows
        self._install_tree_forwarding_flows(datapath)
        
        # Install ARP flooding rule (medium priority)
        arp_match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        arp_actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, 10, arp_match, arp_actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, hard_timeout=0):
        """Add a flow entry to the flow table"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handle incoming packets"""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})

        # Learn MAC address
        self.mac_to_port[dpid][src] = in_port

        # Handle ARP
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self._handle_arp(datapath, pkt, in_port)
            return

        # Handle IPv4
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            self._handle_ipv4(datapath, pkt, in_port, msg)
            return

        # Default flooding for unknown protocols
        out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _handle_arp(self, datapath, pkt, in_port):
        """Handle ARP packets"""
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocols(arp.arp)[0]
        
        if arp_pkt.opcode != arp.ARP_REQUEST:
            return

        # Simple ARP flooding for now
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        
        data = None
        if hasattr(datapath, 'buffer_id'):
            data = pkt.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _handle_ipv4(self, datapath, pkt, in_port, msg):
        """Handle IPv4 packets with traffic analysis"""
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ipv4_pkt = pkt.get_protocols(ipv4.ipv4)[0]
        
        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst
        
        # Update traffic stats
        current_time = time.time()
        self.traffic_stats[src_ip]['packets'] += 1
        self.traffic_stats[src_ip]['last_seen'] = current_time
        
        # Analyze traffic for HTTP requests (TCP port 80, 8001-8005)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if tcp_pkt and tcp_pkt.dst_port in [80, 8001, 8002, 8003, 8004, 8005]:
            classification = self._classify_traffic(src_ip, dst_ip, tcp_pkt)
            self._handle_web_traffic(datapath, pkt, in_port, src_ip, dst_ip, classification, msg)
        else:
            # Regular L2 switching for non-web traffic
            self._l2_switching(datapath, pkt, in_port, msg)

    def _classify_traffic(self, src_ip, dst_ip, tcp_pkt):
        """Classify traffic as normal, suspicious, or malicious"""
        current_time = time.time()
        
        # Update flow stats
        flow_key = f"{src_ip}->{dst_ip}:{tcp_pkt.dst_port}"
        flow_stat = self.flow_stats[flow_key]
        flow_stat['packet_count'] += 1
        
        # Calculate request rate (packets per minute)
        if flow_stat['last_packet_time'] > 0:
            time_diff = current_time - flow_stat['last_packet_time']
            if time_diff > 0:
                flow_stat['request_rate'] = flow_stat['packet_count'] / (time_diff / 60)
        
        flow_stat['last_packet_time'] = current_time
        
        # Classification logic
        if src_ip in self.malicious_ips:
            classification = 'malicious'
        elif src_ip in self.suspicious_ips:
            classification = 'suspicious'
        elif flow_stat['request_rate'] > 30:  # More than 30 requests per minute
            classification = 'suspicious'
            self.suspicious_ips.add(src_ip)
        elif flow_stat['packet_count'] > 100:  # More than 100 total packets
            classification = 'suspicious'
            self.suspicious_ips.add(src_ip)
        else:
            classification = 'normal'
        
        flow_stat['classification'] = classification
        
        self.logger.info(f"Traffic from {src_ip} classified as: {classification}")
        return classification

    def _handle_web_traffic(self, datapath, pkt, in_port, src_ip, dst_ip, classification, msg):
        """Handle web traffic with honeypot redirection"""
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ipv4_pkt = pkt.get_protocols(ipv4.ipv4)[0]
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        
        # Determine destination based on classification
        if classification == 'malicious':
            # Redirect to deep honeypot
            target_ip = DEEP_HONEYPOT
            self.logger.info(f"Redirecting malicious traffic from {src_ip} to deep honeypot")
        elif classification == 'suspicious':
            # Redirect to triage honeypot
            target_ip = TRIAGE_HONEYPOT
            self.logger.info(f"Redirecting suspicious traffic from {src_ip} to triage honeypot")
        else:
            # Load balance to normal servers
            target_ip = self._get_next_normal_server()
            self.logger.info(f"Load balancing normal traffic from {src_ip} to {target_ip}")
        
        # Install flow rule for this connection
        self._install_redirection_flow(datapath, src_ip, dst_ip, target_ip, tcp_pkt.dst_port)
        
        # Forward current packet
        self._forward_to_target(datapath, pkt, target_ip, msg)

    def _get_next_normal_server(self):
        """Round-robin load balancing for normal servers"""
        server = NORMAL_SERVERS[self.load_balancer_index]
        self.load_balancer_index = (self.load_balancer_index + 1) % len(NORMAL_SERVERS)
        return server

    def _install_redirection_flow(self, datapath, src_ip, original_dst, target_ip, dst_port):
        """
        Install comprehensive flow rules for traffic redirection
        Creates bidirectional flows with proper timeout and priority
        """
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        # Get target information
        target_mac = HOSTS[target_ip]['mac']
        target_port = self._get_port_for_ip(target_ip)
        
        self.logger.info(f"Installing redirection flow: {src_ip} -> {original_dst} redirected to {target_ip}")
        
        # Forward direction: src -> original_dst becomes src -> target
        forward_match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=src_ip,
            ipv4_dst=original_dst,
            ip_proto=6,  # TCP
            tcp_dst=dst_port
        )
        
        forward_actions = [
            parser.OFPActionSetField(ipv4_dst=target_ip),
            parser.OFPActionSetField(eth_dst=target_mac),
            parser.OFPActionOutput(target_port)
        ]
        
        # Install forward flow with high priority and timeout
        self.add_flow(datapath, 200, forward_match, forward_actions, hard_timeout=600)
        
        # Return direction: target -> src (modify source to appear as original destination)
        return_match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=target_ip,
            ipv4_dst=src_ip,
            ip_proto=6
        )
        
        # Get source information for return path
        src_port = self._get_port_for_ip(src_ip)
        src_mac = HOSTS[src_ip]['mac'] if src_ip in HOSTS else "00:00:00:00:00:00"
        
        return_actions = [
            parser.OFPActionSetField(ipv4_src=original_dst),  # Appear as original destination
            parser.OFPActionSetField(eth_dst=src_mac) if src_mac != "00:00:00:00:00:00" else parser.OFPActionOutput(src_port),
            parser.OFPActionOutput(src_port)
        ]
        
        # Install return flow
        self.add_flow(datapath, 200, return_match, return_actions, hard_timeout=600)
        
        self.logger.info(f"Installed bidirectional flows for {src_ip} <-> {target_ip}")

    def _get_port_for_ip(self, ip):
        """
        Get switch port for given IP in tree topology
        Improved with proper topology mapping
        """
        # Tree topology port mapping:
        # s1 (root): connects to s2 (port 1), s3 (port 2)
        # s2: connects to s1 (port 1), s4 (port 2), s5 (port 3)  
        # s3: connects to s1 (port 1), s6 (port 2), s7 (port 3)
        # s4: connects to s2 (port 1), h1 (port 2), h6 (port 3)
        # s5: connects to s2 (port 1), h2 (port 2)
        # s6: connects to s3 (port 1), h3 (port 2)
        # s7: connects to s3 (port 1), h4 (port 2), h5 (port 3)
        
        port_map = {
            '10.0.0.1': 2,  # h1 on s4 port 2
            '10.0.0.2': 2,  # h2 on s5 port 2
            '10.0.0.3': 2,  # h3 on s6 port 2
            '10.0.0.4': 2,  # h4 on s7 port 2
            '10.0.0.5': 3,  # h5 on s7 port 3
            '10.0.0.6': 3,  # h6 on s4 port 3
        }
        return port_map.get(ip, 1)  # Default to port 1

    def _get_switch_for_ip(self, ip):
        """Get switch ID for given IP"""
        switch_map = {
            '10.0.0.1': 4,  # h1 on s4
            '10.0.0.2': 5,  # h2 on s5  
            '10.0.0.3': 6,  # h3 on s6
            '10.0.0.4': 7,  # h4 on s7
            '10.0.0.5': 7,  # h5 on s7
            '10.0.0.6': 4,  # h6 on s4
        }
        return switch_map.get(ip, 1)  # Default to s1

    def _install_tree_forwarding_flows(self, datapath):
        """
        Install forwarding flows for tree topology
        This creates the basic routing infrastructure
        """
        parser = datapath.ofproto_parser
        dpid = datapath.id
        
        self.logger.info(f"Installing tree forwarding flows for switch s{dpid}")
        
        # Switch-specific forwarding rules based on tree topology
        if dpid == 1:  # Root switch s1
            # Forward to s2 (hosts h1, h2, h6)
            for ip in ['10.0.0.1', '10.0.0.2', '10.0.0.6']:
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ip)
                actions = [parser.OFPActionOutput(1)]  # To s2
                self.add_flow(datapath, 50, match, actions)
            
            # Forward to s3 (hosts h3, h4, h5)
            for ip in ['10.0.0.3', '10.0.0.4', '10.0.0.5']:
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ip)
                actions = [parser.OFPActionOutput(2)]  # To s3
                self.add_flow(datapath, 50, match, actions)
                
        elif dpid == 2:  # Switch s2
            # Forward to s4 (hosts h1, h6)
            for ip in ['10.0.0.1', '10.0.0.6']:
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ip)
                actions = [parser.OFPActionOutput(2)]  # To s4
                self.add_flow(datapath, 50, match, actions)
            
            # Forward to s5 (host h2)
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst='10.0.0.2')
            actions = [parser.OFPActionOutput(3)]  # To s5
            self.add_flow(datapath, 50, match, actions)
            
        elif dpid == 3:  # Switch s3
            # Forward to s6 (host h3)
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst='10.0.0.3')
            actions = [parser.OFPActionOutput(2)]  # To s6
            self.add_flow(datapath, 50, match, actions)
            
            # Forward to s7 (hosts h4, h5)
            for ip in ['10.0.0.4', '10.0.0.5']:
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ip)
                actions = [parser.OFPActionOutput(3)]  # To s7
                self.add_flow(datapath, 50, match, actions)
        
        elif dpid in [4, 5, 6, 7]:  # Leaf switches
            # Direct host connections handled by MAC learning
            pass

    def _forward_to_target(self, datapath, pkt, target_ip, msg):
        """Forward packet to target host"""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        target_mac = HOSTS[target_ip]['mac']
        out_port = self._get_port_for_ip(target_ip)
        
        # Modify packet destination
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ipv4_pkt = pkt.get_protocols(ipv4.ipv4)[0]
        
        actions = [
            parser.OFPActionSetField(eth_dst=target_mac),
            parser.OFPActionSetField(ipv4_dst=target_ip),
            parser.OFPActionOutput(out_port)
        ]
        
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=msg.match['in_port'], actions=actions, data=data)
        datapath.send_msg(out)

    def _l2_switching(self, datapath, pkt, in_port, msg):
        """Standard L2 switching for non-web traffic"""
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _monitoring_loop(self):
        """Background monitoring and logging"""
        baseline_ips = {'10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4', '10.0.0.5', '10.0.0.6'}
        
        while True:
            try:
                current_time = time.time()
                
                # Log traffic statistics - but keep baseline IPs alive
                for ip, stats in list(self.traffic_stats.items()):
                    if ip in baseline_ips:
                        # Keep baseline IPs active by updating their last_seen periodically
                        if current_time - stats['last_seen'] > 240:  # Update every 4 minutes
                            stats['last_seen'] = current_time
                    elif current_time - stats['last_seen'] > 300:  # 5 minutes timeout for real traffic
                        del self.traffic_stats[ip]
                
                # Log flow statistics
                active_flows = len([f for f in self.flow_stats.values() 
                                   if current_time - f['last_packet_time'] < 60])
                
                self.logger.info(f"Active IPs: {len(self.traffic_stats)}, "
                               f"Active Flows: {active_flows}, "
                               f"Suspicious IPs: {len(self.suspicious_ips)}, "
                               f"Malicious IPs: {len(self.malicious_ips)}")
                
                time.sleep(30)  # Monitor every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Monitoring error: {e}")

    def update_classification(self, source_ip, classification, risk_score, ml_prediction=None):
        """
        Enhanced classification update with ML model integration
        """
        self.logger.info(f"[DEBUG] Updating classification: IP={source_ip}, Class={classification}, Risk={risk_score}, ML={ml_prediction}")
        
        # Handle ML prediction if provided
        if ml_prediction is not None:
            if ml_prediction == 1:
                # ML says malicious - prioritize this
                self.malicious_ips.add(source_ip)
                self.suspicious_ips.discard(source_ip)
                self.logger.info(f"IP {source_ip} marked as MALICIOUS by ML model (prediction=1, risk={risk_score})")
            elif ml_prediction == 0:
                # ML says benign - use risk_score for classification
                if risk_score > 70:
                    self.malicious_ips.add(source_ip)
                    self.suspicious_ips.discard(source_ip)
                    self.logger.info(f"IP {source_ip} marked as MALICIOUS by risk score despite ML=0 (risk={risk_score})")
                elif risk_score > 40:
                    self.suspicious_ips.add(source_ip)
                    self.logger.info(f"IP {source_ip} marked as SUSPICIOUS by risk score with ML=0 (risk={risk_score})")
                else:
                    # Clean slate for low risk + ML=0
                    self.suspicious_ips.discard(source_ip)
                    self.malicious_ips.discard(source_ip)
                    self.logger.info(f"IP {source_ip} cleared by ML model (prediction=0, risk={risk_score})")
        else:
            # Fallback to traditional risk-based classification
            if classification == 'malicious' and risk_score > 70:
                self.malicious_ips.add(source_ip)
                self.suspicious_ips.discard(source_ip)
                self.logger.info(f"IP {source_ip} marked as MALICIOUS (risk: {risk_score})")
            elif classification == 'suspicious' and risk_score > 40:
                self.suspicious_ips.add(source_ip)
                self.logger.info(f"IP {source_ip} marked as SUSPICIOUS (risk: {risk_score})")
            else:
                # Clean classification - remove from suspicious/malicious
                self.suspicious_ips.discard(source_ip)
                self.malicious_ips.discard(source_ip)
                self.logger.info(f"IP {source_ip} CLEARED (risk: {risk_score})")


class HoneypotController(ControllerBase):
    """REST API for honeypot controller"""
    
    def __init__(self, req, link, data, **config):
        super(HoneypotController, self).__init__(req, link, data, **config)
        self.controller = data['controller']

    @route('honeypot', '/honeypot/classification', methods=['POST'])
    def honeypot_classification(self, req, **kwargs):
        """Receive classification updates from honeypots with ML integration"""
        try:
            data = json.loads(req.body.decode('utf-8'))
            source_ip = data['source_ip']
            classification = data['classification']
            risk_score = data['risk_score']
            ml_prediction = data.get('ml_prediction', None)  # Binary ML prediction (1 or 0)
            honeypot_type = data.get('honeypot_type', 'unknown')
            
            self.controller.update_classification(source_ip, classification, risk_score, ml_prediction)
            
            response_data = {'status': 'success', 'source_ip': source_ip}
            if ml_prediction is not None:
                response_data['ml_prediction_processed'] = ml_prediction
                
            return Response(content_type='application/json',
                          body=json.dumps(response_data).encode('utf-8'))
        except Exception as e:
            return Response(content_type='application/json',
                          body=json.dumps({'status': 'error', 'message': str(e)}).encode('utf-8'),
                          status=400)

    @route('honeypot', '/honeypot/stats', methods=['GET'])
    def get_stats(self, req, **kwargs):
        """Get controller statistics (legacy endpoint)"""
        stats = {
            'active_ips': len(self.controller.traffic_stats),
            'suspicious_ips': list(self.controller.suspicious_ips),
            'malicious_ips': list(self.controller.malicious_ips),
            'flow_count': len(self.controller.flow_stats)
        }
        
        return Response(content_type='application/json',
                      body=json.dumps(stats).encode('utf-8'))

    @route('api', '/api/stats', methods=['GET'])
    def get_api_stats(self, req, **kwargs):
        """Get controller statistics (standard API endpoint)"""
        stats = {
            'active_ips': len(self.controller.traffic_stats),
            'suspicious_ips': list(self.controller.suspicious_ips),
            'malicious_ips': list(self.controller.malicious_ips),
            'flow_count': len(self.controller.flow_stats),
            'last_update': time.strftime('%H:%M:%S')
        }
        
        return Response(content_type='application/json',
                      body=json.dumps(stats).encode('utf-8'))


if __name__ == '__main__':
    from ryu.cmd import manager
    manager.main() 