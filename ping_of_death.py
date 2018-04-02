from scapy.all import *
srloop(fragment(IP(dst='10.0.0.4')/ICMP()/("X"*60000)) ) 
