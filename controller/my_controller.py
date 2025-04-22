from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, udp, icmp
from flow_rules import add_default_flow, add_learning_flow
import configparser
import grpc
import ml_model_pb2
import ml_model_pb2_grpc
import logging
import time

# Loglama ayarları
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/home/samet/capstone/logs/controller.log'),
        logging.StreamHandler()
    ]
)

class MyController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MyController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.suspected_ips = set()  # Şüpheli IP'leri takip etmek için küme
        
        # Konfigürasyonu yükle
        config = configparser.ConfigParser()
        config.read('controller/controller_config.ini')
        self.honeypot_ip = config.get('Network', 'honeypot_ip', fallback='10.0.0.8')
        self.honeypot_mac = config.get('Network', 'honeypot_mac', fallback='00:00:00:00:00:08')
        self.honeypot_port = int(config.get('Network', 'honeypot_port', fallback='8'))
        
        # gRPC istemcisini başlat
        try:
            self.channel = grpc.insecure_channel('localhost:50051')
            self.stub = ml_model_pb2_grpc.MLModelServiceStub(self.channel)
            logging.info("gRPC bağlantısı başarılı")
        except Exception as e:
            logging.error(f"gRPC bağlantısı hatası: {e}")
        
        logging.info("SDN Controller başlatıldı")
        logging.info(f"Honeypot ayarları - IP: {self.honeypot_ip}, Port: {self.honeypot_port}")

    def is_multicast_or_broadcast(self, mac):
        # Multicast adresleri (33:33, 01:00:5e, 01:80:c2) ve broadcast (ff:ff:ff:ff:ff:ff) kontrol et
        return mac.startswith(('33:33', '01:00:5e', '01:80:c2')) or mac == 'ff:ff:ff:ff:ff:ff'

    def query_ml_model(self, src_ip, dst_ip, src_port, dst_port, protocol):
        # Şüpheli olarak bilinen IP'leri kontrol et
        if src_ip in self.suspected_ips:
            logging.info(f"Önceden şüpheli olarak işaretlenmiş IP: {src_ip}")
            return 1
        
        # gRPC sunucusuna paket bilgilerini gönder
        packet_info = ml_model_pb2.PacketInfo(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol
        )
        
        # Belirli zaman aşımı ile gRPC sunucusunu çağır
        try:
            response = self.stub.PredictPacket(packet_info, timeout=1.0)
            is_suspicious = response.is_suspicious
            
            # Şüpheli ise, IP'yi şüpheli listesine ekle
            if is_suspicious:
                self.suspected_ips.add(src_ip)
                logging.warning(f"Şüpheli paket tespit edildi: {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({protocol})")
            
            return is_suspicious
        except grpc.RpcError as e:
            logging.error(f"gRPC hatası: {e}")
            return 0  # Hata durumunda varsayılan olarak normal kabul et

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Default tüm paketleri controller'a gönder
        match = parser.OFPMatch()  # Her pakete uyacak
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        
        # Yeni flow kuralını ekle (düşük öncelik)
        self.add_flow(datapath, 0, match, actions)
        logging.info(f"Switch {datapath.id} bağlandı, default flow rules ayarlandı")

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
        
        return actions

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        # Protokol tipleri için değişkenler
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        arp_pkt = pkt.get_protocol(arp.arp)

        if eth:
            dst = eth.dst
            src = eth.src
            dpid = datapath.id
            self.mac_to_port.setdefault(dpid, {})

            # Multicast veya broadcast adresleri işleme alma
            if self.is_multicast_or_broadcast(dst):
                logging.debug(f"Multicast/Broadcast adres algılandı: {dst}, paketi iletme")
                # Broadcast paketleri için normal bir FLOOD yap
                actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
                return

            # MAC adresini öğren
            self.mac_to_port[dpid][src] = in_port

            # IP paketlerini analiz et
            protocol_str = "Unknown"
            is_suspicious = 0
            
            # Aksiyon değişkeni
            actions = []
            
            # Paketi analiz et ve protokolü belirle
            if arp_pkt:
                # ARP paketleri güvenli kabul et
                protocol_str = "ARP"
                if dst in self.mac_to_port[dpid]:
                    out_port = self.mac_to_port[dpid][dst]
                else:
                    out_port = ofproto.OFPP_FLOOD
                actions = [parser.OFPActionOutput(out_port)]
                
            elif ip_pkt:
                # Hedef MAC adresi honeypot ise, doğrudan ilet
                if dst == self.honeypot_mac:
                    logging.info(f"Doğrudan honeypot'a giden paket: {ip_pkt.src} -> {ip_pkt.dst}")
                    out_port = self.honeypot_port
                    actions = [parser.OFPActionOutput(out_port)]
                
                # IPv4 paketleri için ML modeline sor
                elif tcp_pkt:
                    protocol_str = "TCP"
                    is_suspicious = self.query_ml_model(
                        ip_pkt.src, ip_pkt.dst, tcp_pkt.src_port, tcp_pkt.dst_port, protocol_str
                    )
                    
                    if is_suspicious:
                        # Şüpheli paketleri honeypot'a yönlendir
                        actions = self.redirect_to_honeypot(datapath, parser, ip_pkt, tcp_pkt, in_port)
                    elif dst in self.mac_to_port[dpid]:
                        # Normal paketleri hedefine yönlendir
                        out_port = self.mac_to_port[dpid][dst]
                        actions = [parser.OFPActionOutput(out_port)]
                        
                        # Normal trafik için flow rule ekle (30 saniye timeout)
                        match = parser.OFPMatch(
                            eth_type=0x0800, ip_proto=6,
                            ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst,
                            tcp_src=tcp_pkt.src_port, tcp_dst=tcp_pkt.dst_port
                        )
                        self.add_flow(datapath, 10, match, actions, idle_timeout=30)
                    else:
                        # Bilinmeyen hedef, flood yap
                        out_port = ofproto.OFPP_FLOOD
                        actions = [parser.OFPActionOutput(out_port)]
                
                elif udp_pkt:
                    protocol_str = "UDP"
                    is_suspicious = self.query_ml_model(
                        ip_pkt.src, ip_pkt.dst, udp_pkt.src_port, udp_pkt.dst_port, protocol_str
                    )
                    
                    if dst in self.mac_to_port[dpid]:
                        out_port = self.mac_to_port[dpid][dst]
                    else:
                        out_port = ofproto.OFPP_FLOOD
                    actions = [parser.OFPActionOutput(out_port)]
                
                elif icmp_pkt:
                    protocol_str = "ICMP"
                    is_suspicious = self.query_ml_model(
                        ip_pkt.src, ip_pkt.dst, 0, 0, protocol_str
                    )
                    
                    if dst in self.mac_to_port[dpid]:
                        out_port = self.mac_to_port[dpid][dst]
                    else:
                        out_port = ofproto.OFPP_FLOOD
                    actions = [parser.OFPActionOutput(out_port)]
                
                else:
                    # Diğer IP protokolleri
                    if dst in self.mac_to_port[dpid]:
                        out_port = self.mac_to_port[dpid][dst]
                    else:
                        out_port = ofproto.OFPP_FLOOD
                    actions = [parser.OFPActionOutput(out_port)]
            
            else:
                # IP olmayan paketler için (örn. IPv6)
                if dst in self.mac_to_port[dpid]:
                    out_port = self.mac_to_port[dpid][dst]
                else:
                    out_port = ofproto.OFPP_FLOOD
                actions = [parser.OFPActionOutput(out_port)]
            
            # Paketi gönder
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            out = parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id,
                in_port=in_port, actions=actions, data=data
            )
            datapath.send_msg(out)