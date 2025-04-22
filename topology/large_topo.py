from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info

class LargeTopo(Topo):
    def build(self):
        # Switch'ler
        s1 = self.addSwitch('s1')  # Core switch
        s2 = self.addSwitch('s2')  # Aggregation switch
        s3 = self.addSwitch('s3')  # Aggregation switch
        s4 = self.addSwitch('s4')  # Edge switch
        s5 = self.addSwitch('s5')  # Edge switch
        s6 = self.addSwitch('s6')  # Edge switch
        s7 = self.addSwitch('s7')  # Edge switch

        # Host'lar (h1'den h7'ye gerçek web sunucusu, h8'de HTTP honeypot)
        # Hata ayıklama için çıktıları log dosyasına yönlendiriyoruz
        server_cmd = 'python3 /home/samet/capstone/server/real_web_server.py > /home/samet/capstone/logs/web_server_{}.log 2>&1 &'
        h1 = self.addHost('h1', ip='10.0.0.1/24', cmd=server_cmd.format('h1'))
        h2 = self.addHost('h2', ip='10.0.0.2/24', cmd=server_cmd.format('h2'))
        h3 = self.addHost('h3', ip='10.0.0.3/24', cmd=server_cmd.format('h3'))
        h4 = self.addHost('h4', ip='10.0.0.4/24', cmd=server_cmd.format('h4'))
        h5 = self.addHost('h5', ip='10.0.0.5/24', cmd=server_cmd.format('h5'))
        h6 = self.addHost('h6', ip='10.0.0.6/24', cmd=server_cmd.format('h6'))
        h7 = self.addHost('h7', ip='10.0.0.7/24', cmd=server_cmd.format('h7'))
        
        # Honeypot host (h8)
        h8 = self.addHost('h8', ip='10.0.0.8/24', cmd='python3 /home/samet/capstone/honeypot/http_honeypot.py > /home/samet/capstone/logs/honeypot_h8.log 2>&1 &')

        # Dış host'lar (sunucu çalıştırmayacak, saldırgan gibi davranacak)
        external1 = self.addHost('external1', ip='10.0.0.9/24')
        external2 = self.addHost('external2', ip='10.0.0.10/24')

        # Switch bağlantıları
        self.addLink(s1, s2)
        self.addLink(s1, s3)
        self.addLink(s2, s4)
        self.addLink(s2, s5)
        self.addLink(s3, s6)
        self.addLink(s3, s7)

        # Host-switch bağlantıları
        self.addLink(h1, s4)
        self.addLink(h2, s4)
        self.addLink(h3, s5)
        self.addLink(h4, s5)
        self.addLink(h5, s6)
        self.addLink(h6, s6)
        self.addLink(h7, s7)
        self.addLink(h8, s7)  # h8, s7'ye bağlı
        self.addLink(external1, s1)
        self.addLink(external2, s1)

def run():
    topo = LargeTopo()
    net = Mininet(topo=topo, controller=RemoteController('c0', ip='127.0.0.1', port=6633, timeout=30), ipBase='10.0.0.0/24')
    net.addNAT().configDefault()
    net.start()
    
    # H8'in MAC adresini config dosyasına yaz (controller için)
    import configparser
    import os
    
    config = configparser.ConfigParser()
    config_path = '/home/samet/capstone/controller/controller_config.ini'
    
    if os.path.exists(config_path):
        config.read(config_path)
    
    if not config.has_section('Network'):
        config.add_section('Network')
    
    # H8'in MAC adresini al
    h8_mac = net.get('h8').MAC()
    config.set('Network', 'honeypot_mac', h8_mac)
    config.set('Network', 'honeypot_ip', '10.0.0.8')
    config.set('Network', 'honeypot_port', '8')
    
    with open(config_path, 'w') as configfile:
        config.write(configfile)
    
    print("Honeypot MAC adresi config dosyasına yazıldı:", h8_mac)
    
    CLI(net)
    
    # Topoloji durdurulmadan önce süreçleri sonlandır
    for host in net.hosts:
        host.cmd('pkill -f "real_web_server.py"')
        host.cmd('pkill -f "http_honeypot.py"')
    
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()