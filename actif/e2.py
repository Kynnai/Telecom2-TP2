from scapy.all import *

fichPCAP = "trace_e.pcap"

flag = 'FLAG-'

for packet in rdpcap(fichPCAP):
    if packet.haslayer(ARP):
        if packet[ARP].pdst == '192.168.1.201' and packet[ARP].op == 2 and packet[ARP].psrc != '192.168.1.201':
            flag += packet[ARP].psrc.split('.')[3]

print(flag)