'''
This py script is used for spine leaf topo model
'''
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink


class MyTopo(Topo):

    def __init__(self):
        "Create custom topo."
        # Initialize topology
        Topo.__init__(self)
        # Add hosts and switches
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        h5 = self.addHost('h5')
        h6 = self.addHost('h6')
        h7 = self.addHost('h7')
        h8 = self.addHost('h8')
        h9 = self.addHost('h9')
        h10 = self.addHost('h10')
        h11 = self.addHost('h11')
        h12 = self.addHost('h12')
        h13 = self.addHost('h13')
        h14 = self.addHost('h14')
        h15 = self.addHost('h15')
        h16 = self.addHost('h16')
                
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5')
        s6 = self.addSwitch('s6')

        # Add links
        # leaf to host link bandwidth = 10 Mbit/s
        self.addLink(h1, s3, bw=20, delay='100ms')
        self.addLink(h2, s3, bw=20, delay='100ms')
        self.addLink(h3, s3, bw=20, delay='100ms')
        self.addLink(h4, s3, bw=20, delay='100ms')
        self.addLink(h5, s2, bw=20, delay='100ms')
        self.addLink(h6, s2, bw=20, delay='100ms')
        self.addLink(h7, s2, bw=20, delay='100ms')
        self.addLink(h8, s2, bw=20, delay='100ms')
        self.addLink(h9, s5, bw=20, delay='100ms')
        self.addLink(h10, s5, bw=20, delay='100ms')
        self.addLink(h11, s5, bw=20, delay='100ms')
        self.addLink(h12, s5, bw=20, delay='100ms')
        self.addLink(h13, s6, bw=20, delay='100ms')
        self.addLink(h14, s6, bw=20, delay='100ms')
        self.addLink(h15, s6, bw=20, delay='100ms')
        self.addLink(h16, s6, bw=20, delay='100ms')
        # leaf to spine link bandwidth = 40 Mbit/s
        self.addLink(s1, s3, bw=40, delay='100ms')
        self.addLink(s1, s4, bw=40, delay='100ms')
        self.addLink(s1, s5, bw=40, delay='100ms')
        self.addLink(s1, s6, bw=40, delay='100ms')
        self.addLink(s2, s3, bw=40, delay='100ms')
        self.addLink(s2, s4, bw=40, delay='100ms')
        self.addLink(s2, s5, bw=40, delay='100ms')
        self.addLink(s2, s6, bw=40, delay='100ms')
topos = {'mytopo': (lambda: MyTopo())}
