#!/usr/bin/env python

##########################################################################################################
#
# Author: Brenyn Kissoondath
# Course: Learn Python and Ethical Hacking From Scratch - StationX
# Instructor: Zaid Al Quraishi
# Purpose: Create a dns spoofer
# Input(s): 
# Output(s): 
#
# Notes to self: 
#
##########################################################################################################
import netfilterqueue
import scapy.all as scapy

def process_packet(packet):
	scapy_packet = scapy.IP(packet.get_payload()) #convert netfilterqueue packet into scapy packet so we can use scapy filters
	print(scapy_packet.show())
	packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()