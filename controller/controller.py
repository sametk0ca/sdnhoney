from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
# Import additional packet types for detailed logging
from ryu.lib.packet import arp, ipv4, icmp, tcp, udp
import random # Added for random classification
import time # Added for timestamping

# --- Rule-Based Classification Constants ---
HIGH_RATE_THRESHOLD = 20  # Packets from a single source
RATE_TIME_WINDOW = 5  # Seconds
PORT_SCAN_THRESHOLD = 5  # Unique destination ports targeted by a source on a single destination IP
SCAN_TIME_WINDOW = 10  # Seconds
# --- End Constants ---

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        # --- State for Rule-Based Classification ---
        self.known_bad_ips = {'10.0.0.100', '10.0.0.101'} # Example bad IPs
        self.suspicious_ports_protocols = {
            ('UDP', 80): "UDP to common HTTP port",
            ('TCP', 5353): "TCP to MDNS port (often UDP)"
        } # Example: { (protocol_name_str, port_num): reason_str }
        self.source_ip_activity = {}
        # Structure: { 
        #   src_ip: {
        #       'timestamps': [ts1, ts2, ...], # For general rate limiting
        #       'port_scan_tracker': { 
        #           dst_ip: {'ports': {port1, port2}, 'timestamps': [ts1, ts2]}
        #       }
        #   }
        # }
        # --- End State ---

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def _clean_old_activity(self, current_time):
        # Clean general rate limiting timestamps
        for src_ip, data in list(self.source_ip_activity.items()): # Use list for safe modification
            data['timestamps'] = [ts for ts in data['timestamps'] if current_time - ts < RATE_TIME_WINDOW]
            if not data['timestamps'] and not data.get('port_scan_tracker'): # Remove src_ip if no relevant activity
                del self.source_ip_activity[src_ip]
                continue

            # Clean port scan tracker timestamps and ports
            if 'port_scan_tracker' in data:
                for dst_ip, scan_data in list(data['port_scan_tracker'].items()): # Use list for safe modification
                    valid_scan_timestamps = [ts for ts in scan_data['timestamps'] if current_time - ts < SCAN_TIME_WINDOW]
                    # Filter ports based on valid timestamps (more complex if ports are added at different times within the window)
                    # For simplicity, we are just cleaning timestamps here. A more robust way would be to associate timestamps with each port. 
                    # Current approach: if all timestamps for a (src,dst) pair are old, clear ports too.
                    if not valid_scan_timestamps:
                        del data['port_scan_tracker'][dst_ip]
                    else:
                        scan_data['timestamps'] = valid_scan_timestamps
                        # To accurately prune ports, one would need to know which timestamp corresponds to which port discovery.
                        # This simplified version prunes the dst_ip entry if no recent scan activity is recorded via timestamps.

                if not data['port_scan_tracker']:
                    del data['port_scan_tracker'] 
            
            # Final check to remove src_ip if all activity is cleaned
            if not data['timestamps'] and not data.get('port_scan_tracker'):
                 if src_ip in self.source_ip_activity: # check if not already deleted
                    del self.source_ip_activity[src_ip]

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        
        current_time = time.time()
        self._clean_old_activity(current_time)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        
        classification = "normal"
        reason = ""

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
            src_ip = ipv4_pkt.src
            dst_ip = ipv4_pkt.dst
            protocol_num = ipv4_pkt.proto
            log_protocol_detail = "" # Initialize log_protocol_detail

            # Initialize activity for new source IP
            if src_ip not in self.source_ip_activity:
                self.source_ip_activity[src_ip] = {'timestamps': [], 'port_scan_tracker': {}}
            
            self.source_ip_activity[src_ip]['timestamps'].append(current_time)

            # Rule 1: Known Bad IP
            if src_ip in self.known_bad_ips:
                classification = "suspicious"
                reason = "Known Bad IP"

            # Further checks only if not already suspicious and not ICMP
            if classification == "normal" and protocol_num != 1: # Exclude ICMP from these specific rules
                dst_port = 0
                protocol_name = ""
                log_protocol_detail = f"IPv4 {src_ip} > {dst_ip} Proto:{protocol_num}"

                if protocol_num == 6: # TCP
                    tcp_pkt = pkt.get_protocol(tcp.tcp)
                    dst_port = tcp_pkt.dst_port
                    protocol_name = "TCP"
                    log_protocol_detail = f"TCP {src_ip}:{tcp_pkt.src_port} > {dst_ip}:{dst_port}"
                elif protocol_num == 17: # UDP
                    udp_pkt = pkt.get_protocol(udp.udp)
                    dst_port = udp_pkt.dst_port
                    protocol_name = "UDP"
                    log_protocol_detail = f"UDP {src_ip}:{udp_pkt.src_port} > {dst_ip}:{dst_port}"
                
                if protocol_name and dst_port > 0:
                    # Rule 2: Suspicious Port/Protocol Combination
                    if (protocol_name, dst_port) in self.suspicious_ports_protocols:
                        classification = "suspicious"
                        reason = self.suspicious_ports_protocols[(protocol_name, dst_port)]
                    
                    # Rule 3: Port Scan Detection (if still normal)
                    if classification == "normal":
                        if dst_ip not in self.source_ip_activity[src_ip]['port_scan_tracker']:
                            self.source_ip_activity[src_ip]['port_scan_tracker'][dst_ip] = {'ports': set(), 'timestamps': []}
                        
                        tracker = self.source_ip_activity[src_ip]['port_scan_tracker'][dst_ip]
                        tracker['ports'].add(dst_port)
                        tracker['timestamps'].append(current_time)
                        # Keep only recent timestamps for this specific (src,dst) scan tracking
                        tracker['timestamps'] = [ts for ts in tracker['timestamps'] if current_time - ts < SCAN_TIME_WINDOW]
                        
                        # If timestamps are empty, it means all previous activity for this scan pair is old, reset ports.
                        # This is a simplified reset; a more robust way ties ports to their specific timestamps.
                        if not tracker['timestamps']:
                            tracker['ports'].clear()
                        
                        # Check for scan only if there are recent timestamps
                        if tracker['timestamps'] and len(tracker['ports']) > PORT_SCAN_THRESHOLD:
                            classification = "suspicious"
                            reason = f"Port Scan ({len(tracker['ports'])} ports to {dst_ip})"

            # Rule 4: High Request Rate (check regardless of previous classification for logging purposes, can be refined)
            # This check is done after other rules, a high rate might be a symptom of other suspicious activity.
            # We count all packets from src_ip in the window for this rule.
            if len(self.source_ip_activity[src_ip]['timestamps']) > HIGH_RATE_THRESHOLD:
                if classification == "normal": # Only mark as suspicious if not already by a more specific rule
                    classification = "suspicious"
                    reason = "High Request Rate"
                elif not reason: # If already suspicious but no specific reason set by other rules (e.g. bad IP doesn't set port scan reason)
                     reason += ", High Request Rate" # Append if already suspicious for another reason
                else:
                    reason += ", also High Request Rate" # Append if already suspicious for another reason


            # Logging for TCP, UDP, and other non-ICMP IPv4
            if src_ip == '10.0.0.11': # Check if the source IP is the one to be ignored
                pass # Skip logging for this IP
            else:
                log_prefix = f"DPID:{dpid} P:{in_port} {eth.src} > {eth.dst} |"
                log_suffix = f" | {classification}"
                if reason:
                    log_suffix += f" ({reason})"
                
                # Construct log_protocol_detail if not already set (e.g. for non-TCP/UDP IP packets)
                if not log_protocol_detail and protocol_num not in [6, 17]:
                     log_protocol_detail = f"IPv4 {src_ip} > {dst_ip} Proto:{protocol_num}"
                elif not log_protocol_detail and protocol_num == 1: # specifically for ICMP
                     icmp_pkt = pkt.get_protocol(icmp.icmp)
                     log_protocol_detail = f"ICMP {src_ip} > {dst_ip} Type:{icmp_pkt.type} Code:{icmp_pkt.code}"
                elif not log_protocol_detail: # Should be set if TCP/UDP
                    # Fallback, though ideally it's always set for TCP/UDP by now
                    log_protocol_detail = f"IP {src_ip} > {dst_ip} Proto:{protocol_num} DstPort:{dst_port if 'dst_port' in locals() else 'N/A'}"

                self.logger.info(f"{log_prefix} {log_protocol_detail}{log_suffix}")

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][eth.src] = in_port

        if eth.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth.dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Add flow entry to avoid Macting controller next time.
        if out_port != ofproto.OFPP_FLOOD:
            match_kwargs = {'in_port': in_port, 'eth_src': eth.src, 'eth_dst': eth.dst}

            if eth.ethertype == ether_types.ETH_TYPE_IP:
                match_kwargs['eth_type'] = ether_types.ETH_TYPE_IP
                # Attempt to get the IPv4 packet details again to ensure they are correctly scoped here
                # The variables ipv4_pkt, tcp_pkt, udp_pkt might have been defined earlier in the function
                # but re-getting them here or ensuring their availability is safer for constructing the match.
                # We assume 'pkt' (the full packet object) is available here.
                ipv4_protocol = pkt.get_protocol(ipv4.ipv4)
                if ipv4_protocol:
                    match_kwargs['ipv4_src'] = ipv4_protocol.src
                    match_kwargs['ipv4_dst'] = ipv4_protocol.dst
                    match_kwargs['ip_proto'] = ipv4_protocol.proto

                    if ipv4_protocol.proto == 6:  # TCP
                        tcp_protocol = pkt.get_protocol(tcp.tcp)
                        if tcp_protocol:
                            match_kwargs['tcp_src'] = tcp_protocol.src_port
                            match_kwargs['tcp_dst'] = tcp_protocol.dst_port
                    elif ipv4_protocol.proto == 17:  # UDP
                        udp_protocol = pkt.get_protocol(udp.udp)
                        if udp_protocol:
                            match_kwargs['udp_src'] = udp_protocol.src_port
                            match_kwargs['udp_dst'] = udp_protocol.dst_port
            
            match = parser.OFPMatch(**match_kwargs)

            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out) 