from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp
from flow_rules import add_default_flow, add_learning_flow
import configparser
import grpc
import ml_model_pb2
import ml_model_pb2_grpc

class MyController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MyController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        config = configparser.ConfigParser()
        config.read('controller_config.ini')
        self.honeypot_ip = config.get('Network', 'honeypot_ip', fallback='10.0.0.8')
        self.honeypot_port = int(config.get('Network', 'honeypot_port', fallback='8'))
        # gRPC istemcisini başlat
        self.channel = grpc.insecure_channel('localhost:50051')
        self.stub = ml_model_pb2_grpc.MLModelServiceStub(self.channel)

    def query_ml_model(self, src_ip, dst_ip, src_port, dst_port, protocol):
        # gRPC sunucusuna paket bilgilerini gönder
        packet_info = ml_model_pb2.PacketInfo(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol
        )
        response = self.stub.PredictPacket(packet_info)
        return response.is_suspicious

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        priority, match, actions = add_default_flow(datapath, parser)
        self.add_flow(datapath, priority, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        if eth:
            dst = eth.dst
            src = eth.src
            dpid = datapath.id
            self.mac_to_port.setdefault(dpid, {})

            self.mac_to_port[dpid][src] = in_port

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

            is_suspicious = 0
            if ip and tcp_pkt:
                # Paket bilgilerini al
                src_ip = ip.src
                dst_ip = ip.dst
                src_port = tcp_pkt.src_port
                dst_port = tcp_pkt.dst_port
                protocol = "TCP"
                # ML modeline sorgu gönder
                is_suspicious = self.query_ml_model(src_ip, dst_ip, src_port, dst_port, protocol)

            if is_suspicious:
                # Şüpheliyse honeypot’a yönlendir
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip.src, ipv4_dst=ip.dst, ip_proto=6, tcp_dst=tcp_pkt.dst_port)
                actions = [parser.OFPActionSetField(ipv4_dst=self.honeypot_ip),
                           parser.OFPActionSetField(tcp_dst=2222),
                           parser.OFPActionOutput(self.honeypot_port)]
                self.add_flow(datapath, 100, match, actions)
                out_port = self.honeypot_port

            if out_port != ofproto.OFPP_FLOOD and not is_suspicious:
                priority, match, actions = add_learning_flow(datapath, parser, in_port, dst, out_port)
                self.add_flow(datapath, priority, match, actions)

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)