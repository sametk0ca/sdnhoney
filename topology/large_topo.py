from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.link import Intf
import subprocess

class LargeSDNTopo(Topo):
    def build(self):
        # Çekirdek (core) switch
        core = self.addSwitch('s1')

        # Dağıtım (aggregation) switchleri
        agg1 = self.addSwitch('s2')
        agg2 = self.addSwitch('s3')

        # Uç (edge) switchleri
        edge1 = self.addSwitch('s4')
        edge2 = self.addSwitch('s5')
        edge3 = self.addSwitch('s6')
        edge4 = self.addSwitch('s7')

        # Bağlantılar (Core → Aggregation)
        self.addLink(core, agg1)
        self.addLink(core, agg2)

        # Bağlantılar (Aggregation → Edge)
        self.addLink(agg1, edge1)
        self.addLink(agg1, edge2)
        self.addLink(agg2, edge3)
        self.addLink(agg2, edge4)

        # Hostları ekle
        for i in range(1, 9):
            host = self.addHost(f'h{i}')
            if i <= 2:
                self.addLink(host, edge1)
            elif i <= 4:
                self.addLink(host, edge2)
            elif i <= 6:
                self.addLink(host, edge3)
            else:
                self.addLink(host, edge4)

# SDN başlatma fonksiyonu
def start_network():
    topo = LargeSDNTopo()
    net = Mininet(topo=topo, controller=None, autoSetMacs=True)
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)
    net.start()
    # Fiziksel arabirimi core switch’e bağla (internet erişimi için)
    Intf('wlp4s0', node=net.get('s1'))
    CLI(net)
    net.stop()

if __name__ == '__main__':
    start_network()