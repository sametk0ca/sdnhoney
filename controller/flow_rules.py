from ryu.ofproto import ofproto_v1_3

def add_default_flow(datapath, parser):
    """ Varsayılan flow kuralı: Bilinmeyen paketleri controller'a gönder """
    ofproto = datapath.ofproto
    match = parser.OFPMatch()
    actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
    return (0, match, actions)

def add_learning_flow(datapath, parser, in_port, dst, out_port):
    """ MAC öğrenme için flow ekleme """
    ofproto = datapath.ofproto
    match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
    actions = [parser.OFPActionOutput(out_port)]
    return (1, match, actions)
