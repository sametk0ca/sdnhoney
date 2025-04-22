import json
import networkx as nx
import matplotlib.pyplot as plt

# JSON verisini buraya yapıştır
json_data = '''
[{"dpid": "0000000000000004", "ports": [{"dpid": "0000000000000004", "port_no": "00000003", "hw_addr": "5e:eb:58:4d:32:1a", "name": "s4-eth3"}, {"dpid": "0000000000000004", "port_no": "00000002", "hw_addr": "fe:21:dc:ce:2b:c3", "name": "s4-eth2"}, {"dpid": "0000000000000004", "port_no": "00000001", "hw_addr": "b2:8e:37:0f:06:e0", "name": "s4-eth1"}]}, {"dpid": "0000000000000003", "ports": [{"dpid": "0000000000000003", "port_no": "00000001", "hw_addr": "f6:ce:a6:09:42:ae", "name": "s3-eth1"}, {"dpid": "0000000000000003", "port_no": "00000002", "hw_addr": "12:84:5c:53:cb:c3", "name": "s3-eth2"}, {"dpid": "0000000000000003", "port_no": "00000003", "hw_addr": "7e:fc:8c:8e:78:a4", "name": "s3-eth3"}]}, {"dpid": "0000000000000006", "ports": [{"dpid": "0000000000000006", "port_no": "00000002", "hw_addr": "62:ce:a4:61:af:68", "name": "s6-eth2"}, {"dpid": "0000000000000006", "port_no": "00000003", "hw_addr": "a2:b5:4b:94:49:bf", "name": "s6-eth3"}, {"dpid": "0000000000000006", "port_no": "00000001", "hw_addr": "a2:7a:ab:b4:0c:90", "name": "s6-eth1"}]}, {"dpid": "0000000000000005", "ports": [{"dpid": "0000000000000005", "port_no": "00000002", "hw_addr": "36:47:26:e7:2f:eb", "name": "s5-eth2"}, {"dpid": "0000000000000005", "port_no": "00000003", "hw_addr": "8a:7d:bd:d5:79:0e", "name": "s5-eth3"}, {"dpid": "0000000000000005", "port_no": "00000001", "hw_addr": "6a:9d:5b:31:93:20", "name": "s5-eth1"}]}, {"dpid": "0000000000000002", "ports": [{"dpid": "0000000000000002", "port_no": "00000002", "hw_addr": "b2:ea:fd:f3:43:51", "name": "s2-eth2"}, {"dpid": "0000000000000002", "port_no": "00000003", "hw_addr": "7e:6e:b7:b2:49:09", "name": "s2-eth3"}, {"dpid": "0000000000000002", "port_no": "00000001", "hw_addr": "66:61:20:2d:ba:51", "name": "s2-eth1"}]}, {"dpid": "0000000000000007", "ports": [{"dpid": "0000000000000007", "port_no": "00000002", "hw_addr": "fa:f4:66:e4:a3:8f", "name": "s7-eth2"}, {"dpid": "0000000000000007", "port_no": "00000003", "hw_addr": "4a:68:d2:61:c0:51", "name": "s7-eth3"}, {"dpid": "0000000000000007", "port_no": "00000001", "hw_addr": "a2:d8:30:1b:35:eb", "name": "s7-eth1"}]}, {"dpid": "0000000000000001", "ports": [{"dpid": "0000000000000001", "port_no": "00000001", "hw_addr": "f2:5f:32:90:68:0f", "name": "s1-eth1"}, {"dpid": "0000000000000001", "port_no": "00000002", "hw_addr": "16:43:2c:50:42:be", "name": "s1-eth2"}]}]
'''

# JSON'u yükle
data = json.loads(json_data)

# Graph oluştur
G = nx.Graph()

# Switchleri ekle
switch_types = {}  # Switch türlerini saklamak için

for switch in data:
    dpid = switch["dpid"]
    G.add_node(dpid, label=f"S{dpid[-2:]}", type="unknown")  # Son 2 haneyi alarak isim kısalt
    switch_types[dpid] = "unknown"  # Varsayılan olarak bilinmeyen switch

# Bağlantıları ekle
for switch in data:
    dpid = switch["dpid"]
    for port in switch["ports"]:
        if "peer" in port:  
            peer_dpid = port["peer"]
            G.add_edge(dpid, peer_dpid)

# Daha düzenli bir yerleşim kullan
pos = nx.kamada_kawai_layout(G)  # Alternatif: nx.circular_layout(G)

# Switch türlerine göre renk belirle
color_map = {"core": "red", "aggregation": "orange", "edge": "skyblue"}
node_colors = ["blue" if "switch" in node else "green" for node in G.nodes()]

plt.figure(figsize=(10, 8))

# Düğümleri ve bağlantıları çiz
nx.draw(G, pos, with_labels=True, labels={n: G.nodes[n]["label"] for n in G.nodes()},
        node_color=node_colors, edge_color="gray", node_size=2000, font_size=10)

plt.title("SDN Topolojisi Görselleştirme")
plt.show()
