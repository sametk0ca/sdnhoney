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
        # --- Honeypot Configuration ---
        self.triage_honeypot_ip = '10.0.0.9'  # IP of h9 (Triage Honeypot)
        self.triage_honeypot_mac = None  # Will be learned dynamically
        self.controller_mac = "00:00:00:00:00:CC" # MAC for controller to use in ARP replies for honeypot_ip
        self.load_balancer_vip = '10.0.0.254' # Virtual IP for the load balanced service
        # --- End State ---

        # --- Load Balancing Configuration ---
        self.backend_server_ips = [f'10.0.0.{i}' for i in range(1, 9)] # h1-h8 IPs
        self.next_server_idx = 0
        # Stores MAC addresses of backend servers: {'ip_addr': 'mac_addr'}
        self.server_macs = {} 
        # --- End Load Balancing ---

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout)
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

    def _handle_arp(self, datapath, port, pkt_ethernet, pkt_arp):
        # Learn MAC of backend servers from their ARP replies or requests
        if pkt_arp.src_ip in self.backend_server_ips and pkt_arp.src_ip not in self.server_macs:
            self.server_macs[pkt_arp.src_ip] = pkt_arp.src_mac
            # self.logger.info(f"LB: Learned MAC {pkt_arp.src_mac} for backend server {pkt_arp.src_ip} via ARP.")

        if pkt_arp.opcode != arp.ARP_REQUEST:
            return False # Not an ARP request we might need to handle beyond learning

        # Handle ARP for Triage Honeypot IP
        if self.triage_honeypot_mac is None and pkt_arp.src_ip == self.triage_honeypot_ip:
            self.triage_honeypot_mac = pkt_arp.src_mac
            # self.logger.info(f"Learned triage honeypot MAC via ARP: {self.triage_honeypot_mac} from IP {pkt_arp.src_ip}")

        if pkt_arp.dst_ip == self.triage_honeypot_ip:
            if self.triage_honeypot_mac is None:
                self.logger.warning(f"ARP request for honeypot IP {self.triage_honeypot_ip} but its MAC is unknown. Dropping ARP.")
                return True # Consumed, but no reply
            
            # self.logger.info(f"ARP request for honeypot IP {self.triage_honeypot_ip}, replying with MAC {self.triage_honeypot_mac}")
            arp_reply_pkt = packet.Packet()
            arp_reply_pkt.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP,
                                dst=pkt_ethernet.src, 
                                src=self.triage_honeypot_mac)) 
            arp_reply_pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                src_mac=self.triage_honeypot_mac,
                                src_ip=self.triage_honeypot_ip,
                                dst_mac=pkt_arp.src_mac,
                                dst_ip=pkt_arp.src_ip))
            arp_reply_pkt.serialize()
            actions = [datapath.ofproto_parser.OFPActionOutput(port)]
            out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                                 buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                                                 in_port=datapath.ofproto.OFPP_CONTROLLER,
                                                 actions=actions, data=arp_reply_pkt.data)
            datapath.send_msg(out)
            return True
        
        # Handle ARP for Load Balancer VIP
        if pkt_arp.dst_ip == self.load_balancer_vip: # ARP Request for VIP
            # self.logger.info(f"ARP request for Load Balancer VIP {self.load_balancer_vip}, replying with controller MAC {self.controller_mac}")
            arp_reply_pkt = packet.Packet()
            arp_reply_pkt.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP,
                                dst=pkt_ethernet.src,
                                src=self.controller_mac)) # Controller's MAC for the VIP
            arp_reply_pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                src_mac=self.controller_mac, # Controller's MAC
                                src_ip=self.load_balancer_vip,  # VIP IP
                                dst_mac=pkt_arp.src_mac,
                                dst_ip=pkt_arp.src_ip))
            arp_reply_pkt.serialize()
            actions = [datapath.ofproto_parser.OFPActionOutput(port)]
            out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                                 buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                                                 in_port=datapath.ofproto.OFPP_CONTROLLER,
                                                 actions=actions, data=arp_reply_pkt.data)
            datapath.send_msg(out)
            return True

        return False

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth_frame = pkt.get_protocol(ethernet.ethernet)
        if not eth_frame:
            return

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        
        current_time = time.time()
        self._clean_old_activity(current_time)

        if eth_frame.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        
        classification = "normal"
        reason = ""

        # Learn source MAC to output port mapping
        # This is important for general L2 switching and for knowing where to send ARP replies
        self.mac_to_port[dpid][eth_frame.src] = in_port

        # Handle ARP packets for honeypot IP
        if eth_frame.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkt = pkt.get_protocol(arp.arp)
            if arp_pkt:
                if self._handle_arp(datapath, in_port, eth_frame, arp_pkt):
                    return # ARP handled, no further processing needed for this packet

        if eth_frame.ethertype == ether_types.ETH_TYPE_IP:
            ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
            src_ip = ipv4_pkt.src
            dst_ip = ipv4_pkt.dst
            protocol_num = ipv4_pkt.proto
            log_protocol_detail = "" # Initialize log_protocol_detail

            # --- EARLY EXCLUSION FOR IGNORED IPs ---
            if src_ip == '10.0.0.11': # Example: An IP to always treat as normal, e.g. a test client machine
                classification = "normal"
                reason = "Ignored Test Client IP"
            elif src_ip in self.backend_server_ips: # Traffic FROM a backend server
                classification = "normal" 
                reason = "From Backend Server"
                # We won't apply rate/scan rules to backend server's own traffic
            else: # Potential client traffic, apply full classification rules
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
                            if tracker['timestamps'] and len(tracker['ports']) >= PORT_SCAN_THRESHOLD:
                                classification = "suspicious"
                                reason = f"Port Scan ({len(tracker['ports'])} ports to {dst_ip})"

                # Rule 4: High Request Rate (check regardless of previous classification for logging purposes, can be refined)
                # This check is done after other rules, a high rate might be a symptom of other suspicious activity.
                # We count all packets from src_ip in the window for this rule.
                # Exclude ICMP from high rate detection as it's used for legitimate network operations
                if protocol_num != 1 and len(self.source_ip_activity[src_ip]['timestamps']) >= HIGH_RATE_THRESHOLD:
                    if classification == "normal": # Only mark as suspicious if not already by a more specific rule
                        classification = "suspicious"
                        reason = "High Request Rate"
                    elif not reason: # If already suspicious but no specific reason set by other rules (e.g. bad IP doesn't set port scan reason)
                         reason += ", High Request Rate" # Append if already suspicious for another reason
                    else:
                        reason += ", also High Request Rate" # Append if already suspicious for another reason

            # Logging for TCP, UDP, and other non-ICMP IPv4
            # Note: Now we only log if src_ip != '10.0.0.11' due to early exclusion above
            if protocol_num != 1 and src_ip != '10.0.0.11': # Exclude ICMP and 10.0.0.11 from logging
                log_prefix = f"DPID:{dpid} P:{in_port} {eth_frame.src} > {eth_frame.dst} |"
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

                # Commenting out general packet logging, only keeping redirection logs
                # self.logger.info(f"{log_prefix} {log_protocol_detail}{log_suffix}")
                pass

        # --- HONEYPOT REDIRECTION LOGIC ---
        original_dst_mac = eth_frame.dst
        redirect_to_honeypot = False
        
        if classification == "suspicious":
            # Learn the triage honeypot MAC if we haven't already
            if self.triage_honeypot_mac is None:
                # Try to find the honeypot MAC from our learned addresses
                for dpid_table in self.mac_to_port.values():
                    for mac, port in dpid_table.items():
                        # We'll learn the honeypot MAC when it sends its first packet
                        # For now, we'll use a placeholder and update it dynamically
                        pass
            
            # Redirect suspicious traffic to triage honeypot
            redirect_to_honeypot = True
            self.logger.info(f"REDIRECTING suspicious traffic from ({src_ip}) to triage honeypot") # Keep this log
            
            # If we know the honeypot MAC, use it; otherwise, flood to learn
            if self.triage_honeypot_mac:
                eth_frame.dst = self.triage_honeypot_mac
            else:
                # We don't know the honeypot MAC yet, so we'll flood
                # The honeypot will respond and we'll learn its MAC
                pass
        # --- END HONEYPOT REDIRECTION ---

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][eth_frame.src] = in_port

        # Special handling for triage honeypot MAC learning
        # We want to learn it if we haven't yet and this packet is from the honeypot IP
        if self.triage_honeypot_mac is None and hasattr(self, 'triage_honeypot_ip'): # Check if MAC is not learned yet
            if eth_frame.ethertype == ether_types.ETH_TYPE_IP:
                ip_pkt_check = pkt.get_protocol(ipv4.ipv4) # Use a different var name to avoid scope issues
                if ip_pkt_check and ip_pkt_check.src == self.triage_honeypot_ip: # And packet is from honeypot IP
                    self.triage_honeypot_mac = eth_frame.src
                    # self.logger.info(f"Learned triage honeypot MAC: {self.triage_honeypot_mac} from port {in_port}")

        # --- ACTION DETERMINATION & PACKET FORWARDING LOGIC ---
        actions = []
        out_port = ofproto.OFPP_FLOOD # Default to flood if no specific path found
        perform_load_balancing = False # Flag to indicate if LB action is taken

        original_dst_ip = None
        if eth_frame.ethertype == ether_types.ETH_TYPE_IP:
            # Re-fetch ipv4_pkt here if needed, or ensure it's from the main processing block
            # For safety, let's assume ipv4_pkt might be None if the main IP block wasn't fully processed
            # or if we are dealing with a non-IP packet that somehow reached here.
            temp_ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
            if temp_ipv4_pkt:
                 original_dst_ip = temp_ipv4_pkt.dst # Get original_dst_ip for LB check
                 protocol_num = temp_ipv4_pkt.proto # Get protocol number for LB check
                 src_ip = temp_ipv4_pkt.src # Get src_ip

        if redirect_to_honeypot and self.triage_honeypot_mac:
            self.logger.info(f"ACTION: Preparing redirection to honeypot {self.triage_honeypot_ip} (MAC: {self.triage_honeypot_mac})") # Keep this
            actions.append(parser.OFPActionSetField(ipv4_dst=self.triage_honeypot_ip))
            actions.append(parser.OFPActionSetField(eth_dst=self.triage_honeypot_mac))
            if self.triage_honeypot_mac in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][self.triage_honeypot_mac]
                # self.logger.info(f"ACTION: Honeypot out_port found: {out_port}")
            else:
                out_port = ofproto.OFPP_FLOOD # Should be rare if honeypot is active
                self.logger.warning(f"ACTION: Honeypot MAC {self.triage_honeypot_mac} known, but port unknown. Flooding.")
        
        elif classification == "normal" and original_dst_ip == self.load_balancer_vip and protocol_num != 1: # Exclude ICMP from LB
            # self.logger.info(f"LB CHECK: Traffic to VIP {self.load_balancer_vip}. Original Dst IP: {original_dst_ip}, Protocol: {protocol_num}")
            if self.backend_server_ips: # Ensure pool is not empty
                selected_idx = self.next_server_idx
                chosen_server_ip = self.backend_server_ips[selected_idx]
                chosen_server_mac = self.server_macs.get(chosen_server_ip)
                
                # self.logger.info(f"LB CHECK: Trying server_idx={selected_idx}, IP={chosen_server_ip}, Known MAC={chosen_server_mac}. All Server MACs: {self.server_macs}")

                if chosen_server_mac:
                    if chosen_server_mac in self.mac_to_port[dpid]:
                        out_port = self.mac_to_port[dpid][chosen_server_mac]
                        perform_load_balancing = True
                        
                        actions.append(parser.OFPActionSetField(eth_dst=chosen_server_mac))
                        actions.append(parser.OFPActionSetField(ipv4_dst=chosen_server_ip))
                        
                        self.logger.info(f"LOAD BALANCING: Original Dst: {original_dst_ip}, Chosen Server: {chosen_server_ip} (MAC: {chosen_server_mac}) via port {out_port}") # Keep this log
                        self.next_server_idx = (self.next_server_idx + 1) % len(self.backend_server_ips) # Cycle index
                    else:
                        out_port = ofproto.OFPP_FLOOD # Flood to learn port for chosen server
                        self.logger.warning(f"LB FAILED (Port Unknown): MAC for chosen server {chosen_server_ip} ({chosen_server_mac}) known, but its port is unknown. Flooding to find it.")
                else: # MAC for chosen server IP unknown
                    out_port = ofproto.OFPP_FLOOD # Flood to learn MAC (and then port) for chosen server
                    self.logger.warning(f"LB FAILED (MAC Unknown): MAC for chosen server IP {chosen_server_ip} is unknown. Flooding to trigger ARP.")
            else: # Should not happen if backend_server_ips is initialized
                self.logger.error("LB SKIPPED: Backend server IP list is empty!")
                if original_dst_mac in self.mac_to_port[dpid]: # Fallback to normal L2
                    out_port = self.mac_to_port[dpid][original_dst_mac]
                else:
                    out_port = ofproto.OFPP_FLOOD
        
        else: # Normal L2 forwarding (not suspicious, not to backend LB pool, or LB failed and fell through)
            if original_dst_mac in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][original_dst_mac]
            else: # Destination MAC unknown, flood
                out_port = ofproto.OFPP_FLOOD
            
            # Only log normal L2 forwarding if it's not being flooded
            if out_port != ofproto.OFPP_FLOOD:
                pass # Logging removed as per user request

        actions.append(parser.OFPActionOutput(out_port))

        # Add flow entry to avoid Macting controller next time.
        if out_port != ofproto.OFPP_FLOOD:
            match_kwargs = {'in_port': in_port, 'eth_src': eth_frame.src, 'eth_dst': original_dst_mac if redirect_to_honeypot else eth_frame.dst}

            if eth_frame.ethertype == ether_types.ETH_TYPE_IP:
                match_kwargs['eth_type'] = ether_types.ETH_TYPE_IP
                ipv4_protocol = pkt.get_protocol(ipv4.ipv4)
                if ipv4_protocol:
                    match_kwargs['ipv4_src'] = ipv4_protocol.src
                    match_kwargs['ipv4_dst'] = ipv4_protocol.dst # Use original_dst_ip for match if LB/redirect happened
                    match_kwargs['ip_proto'] = ipv4_protocol.proto

                    # Reverted: L4 ports should be part of the match for LB forward flow.
                    # is_lb_flow = perform_load_balancing 
                    
                    if ipv4_protocol.proto == 6:  # TCP
                        tcp_protocol = pkt.get_protocol(tcp.tcp)
                        if tcp_protocol:
                            # if not is_lb_flow: # Reverted
                            match_kwargs['tcp_src'] = tcp_protocol.src_port
                            match_kwargs['tcp_dst'] = tcp_protocol.dst_port
                    elif ipv4_protocol.proto == 17:  # UDP
                        udp_protocol = pkt.get_protocol(udp.udp)
                        if udp_protocol:
                            # if not is_lb_flow: # Reverted
                            match_kwargs['udp_src'] = udp_protocol.src_port
                            match_kwargs['udp_dst'] = udp_protocol.dst_port
            
            # self.logger.info(f"CONTROLLER: Preparing to install flow with match_kwargs: {match_kwargs}") # Remove diagnostic log
            match = parser.OFPMatch(**match_kwargs)
            
            # Determine flow priority and timeouts based on action taken
            flow_priority = 1  # Default for normal L2 forwarding
            idle_timeout_val = 15 # Default idle timeout for normal flows
            hard_timeout_val = 0 # Default hard timeout

            if redirect_to_honeypot:
                flow_priority = 3 # Highest for redirection
                idle_timeout_val = 30 
                hard_timeout_val = 60
            elif perform_load_balancing: # Check the specific flag for load balancing
                flow_priority = 10 # Increased priority for LB flows
                idle_timeout_val = 60  # Increased timeout for LB flows
                
                # Install the forward flow (Client -> VIP rewritten to Backend)
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, flow_priority, match, actions, msg.buffer_id, idle_timeout=idle_timeout_val, hard_timeout=hard_timeout_val)
                else:
                    self.add_flow(datapath, flow_priority, match, actions, idle_timeout=idle_timeout_val, hard_timeout=hard_timeout_val)

                # Install the reverse flow (Backend -> Client rewritten to VIP -> Client)
                # The 'actions' list for the forward flow already contains OFPActionOutput(out_port_to_backend_server)
                # For the reverse flow, the output port is the original client's in_port.
                actions_reverse = []
                actions_reverse.append(parser.OFPActionSetField(eth_src=self.controller_mac))
                actions_reverse.append(parser.OFPActionSetField(ipv4_src=self.load_balancer_vip))
                # The output port for reverse traffic is the port where the client's original request came from
                actions_reverse.append(parser.OFPActionOutput(in_port)) 

                match_kwargs_reverse = {
                    'eth_type': ether_types.ETH_TYPE_IP,
                    'ip_proto': ipv4_protocol.proto, # protocol_num from original client packet
                    'ipv4_src': chosen_server_ip,    # Backend server IP
                    'ipv4_dst': ipv4_protocol.src,       # Client's IP
                }
                
                # Get original destination port (service port) and client's source port
                client_src_port = None
                service_dst_port = None

                if ipv4_protocol.proto == 6: # TCP
                    tcp_header = pkt.get_protocol(tcp.tcp)
                    if tcp_header:
                        client_src_port = tcp_header.src_port
                        service_dst_port = tcp_header.dst_port # This was dest port for VIP
                        match_kwargs_reverse['tcp_src'] = service_dst_port # Backend server is source, using the service port
                        match_kwargs_reverse['tcp_dst'] = client_src_port
                elif ipv4_protocol.proto == 17: # UDP
                    udp_header = pkt.get_protocol(udp.udp)
                    if udp_header:
                        client_src_port = udp_header.src_port
                        service_dst_port = udp_header.dst_port # This was dest port for VIP
                        match_kwargs_reverse['udp_src'] = service_dst_port # Backend server is source, using the service port
                        match_kwargs_reverse['udp_dst'] = client_src_port
                
                if client_src_port and service_dst_port: # Ensure ports were found
                    match_reverse = parser.OFPMatch(**match_kwargs_reverse)
                    # Priority for reverse flow should be high enough, same as forward LB flow
                    # self.logger.info(f"LOAD BALANCING: Installing REVERSE flow. Match: {match_kwargs_reverse}, Actions: {[str(a) for a in actions_reverse]}")
                    self.add_flow(datapath, flow_priority, match_reverse, actions_reverse, idle_timeout=idle_timeout_val, hard_timeout=hard_timeout_val)
                else:
                    self.logger.warning(f"LOAD BALANCING: Could not install REVERSE flow due to missing port info for proto {ipv4_protocol.proto}.")
                
                # After installing flows, if buffer_id was used for forward flow, we just return as packet is handled.
                # If no buffer_id, packet_out is done later.
                # Since we've potentially installed two flows, and the first add_flow with buffer_id returns,
                # we need to ensure packet_out for the original packet still happens if no buffer_id.
                # The existing logic for packet_out after this 'if out_port != OFPP_FLOOD:' block should handle the original client->VIP packet.
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    return # Forward flow handled packet processing

            # This existing add_flow is for non-LB, non-redirect, or if LB/redirect failed to find a port (flood case)
            # Or if it's a simple L2 flow after LB flows have been installed by the section above
            elif msg.buffer_id != ofproto.OFP_NO_BUFFER: # Note: 'elif' here
                self.add_flow(datapath, flow_priority, match, actions, msg.buffer_id, idle_timeout=idle_timeout_val, hard_timeout=hard_timeout_val)
                return
            else: # Note: 'else' here
                self.add_flow(datapath, flow_priority, match, actions, idle_timeout=idle_timeout_val, hard_timeout=hard_timeout_val)
        
        # For packet out, we need to handle redirection as well
        # This packet_out sends the original packet that came to the controller (if not buffered)
        if redirect_to_honeypot and self.triage_honeypot_mac:
            # Modify the packet's destination MAC before sending
            eth_frame.dst = self.triage_honeypot_mac
            # Re-create the packet with modified destination
            pkt.serialize()
            data = pkt.data
        else:
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out) 