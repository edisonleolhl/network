from scapy.all import *
import time
while True:
    send(IP(src='10.0.0.2',dst='10.0.0.3')/UDP())
    time.sleep(1)
    send(IP(src='10.0.0.2',dst='10.0.0.3')/TCP(dport=80))
    time.sleep(1)
    send(IP(src='10.0.0.2',dst='10.0.0.3')/ICMP())
    time.sleep(1)
