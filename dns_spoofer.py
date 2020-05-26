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


def process_packet(packet):
	print(packet)

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()