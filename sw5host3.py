'''
This py script is used for model
'''
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink


class MyTopo(Topo):
    "Simple topology example."

    def __init__(self):
        "Create custom topo."
        # Initialize topology
        Topo.__init__(self)
        # Add hosts and switches
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')

        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5')


        # Add links
        # access link bandwidth = 100 Mbit/s
        self.addLink(h1, s1, bw=100)
        self.addLink(h2, s1, bw=100)
        self.addLink(h3, s5, bw=100)
        # interior link bandwidth = 50 Mbit/s
        self.addLink(s1, s2, bw=50, delay='100ms')
        self.addLink(s1, s3, bw=50, delay='100ms')
        self.addLink(s2, s5, bw=50, delay='100ms')
        self.addLink(s3, s4, bw=50, delay='100ms')
        self.addLink(s4, s5, bw=50, delay='100ms')
topos = {'mytopo': (lambda: MyTopo())}
