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
    '10.0.0.6': {'name': 'h6', 'type': 'client', 'port': None, 'mac': '00:00:00:00:00:06'},
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
        
        # Start monitoring thread
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        
        # Setup REST API
        wsgi = kwargs['wsgi']
        wsgi.register(HoneypotController, {'controller': self})
        
        self.logger.info("Honeypot SDN Controller initialized")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch connection"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info(f"Switch connected: {datapath.id}")

        # Install default flow to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

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
        """Install flow rules to redirect traffic"""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        # Get target MAC
        target_mac = HOSTS[target_ip]['mac']
        
        # Match incoming packets from src to original destination
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=src_ip,
            ipv4_dst=original_dst,
            ip_proto=6,  # TCP
            tcp_dst=dst_port
        )
        
        # Actions: modify destination IP and MAC, then output
        actions = [
            parser.OFPActionSetField(ipv4_dst=target_ip),
            parser.OFPActionSetField(eth_dst=target_mac),
            parser.OFPActionOutput(self._get_port_for_ip(target_ip))
        ]
        
        # Install flow with timeout
        self.add_flow(datapath, 100, match, actions, hard_timeout=300)

    def _get_port_for_ip(self, ip):
        """Get switch port for given IP (simplified - assumes single switch)"""
        # In a real topology, this would query the topology to find the correct port
        # For our tree topology, we'll use a simple mapping
        port_map = {
            '10.0.0.1': 4,  # h1 connected to s4
            '10.0.0.2': 5,  # h2 connected to s5  
            '10.0.0.3': 6,  # h3 connected to s6
            '10.0.0.4': 7,  # h4 connected to s7
            '10.0.0.5': 8,  # h5 connected to s7
            '10.0.0.6': 4,  # h6 connected to s4
        }
        return port_map.get(ip, 1)  # Default to port 1

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
        while True:
            try:
                current_time = time.time()
                
                # Log traffic statistics
                for ip, stats in list(self.traffic_stats.items()):
                    if current_time - stats['last_seen'] > 300:  # 5 minutes timeout
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

    def update_classification(self, source_ip, classification, risk_score):
        """Update IP classification from honeypot feedback"""
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


class HoneypotController(ControllerBase):
    """REST API for honeypot controller"""
    
    def __init__(self, req, link, data, **config):
        super(HoneypotController, self).__init__(req, link, data, **config)
        self.controller = data['controller']

    @route('honeypot', '/honeypot/classification', methods=['POST'])
    def honeypot_classification(self, req, **kwargs):
        """Receive classification updates from honeypots"""
        try:
            data = json.loads(req.body.decode('utf-8'))
            source_ip = data['source_ip']
            classification = data['classification']
            risk_score = data['risk_score']
            
            self.controller.update_classification(source_ip, classification, risk_score)
            
            return Response(content_type='application/json',
                          body=json.dumps({'status': 'success'}).encode('utf-8'))
        except Exception as e:
            return Response(content_type='application/json',
                          body=json.dumps({'status': 'error', 'message': str(e)}).encode('utf-8'),
                          status=400)

    @route('honeypot', '/honeypot/stats', methods=['GET'])
    def get_stats(self, req, **kwargs):
        """Get controller statistics"""
        stats = {
            'active_ips': len(self.controller.traffic_stats),
            'suspicious_ips': list(self.controller.suspicious_ips),
            'malicious_ips': list(self.controller.malicious_ips),
            'flow_count': len(self.controller.flow_stats)
        }
        
        return Response(content_type='application/json',
                      body=json.dumps(stats).encode('utf-8'))


if __name__ == '__main__':
    from ryu.cmd import manager
    manager.main() 