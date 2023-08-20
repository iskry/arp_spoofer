#!/usr/bin/env python

import scapy.all as scapy

#op is set to 2 which is for ARP response. the default option, 1, is for ARP request
packet = scapy.ARP(op=2, pdst="192.168.122.11", hwdst="52:54:00:c5:e7:b6", psrc="192.168.122.1")
