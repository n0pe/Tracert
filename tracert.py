#!/usr/bin/env python
# -*- coding: utf-8 -*-

#Tracert - Traceroute tool
#Copyright (C) 2013  n0pe

#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.

#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#GNU General Public License for more details.

#You should have received a copy of the GNU General Public License
#along with this program. If not, see <http://www.gnu.org/licenses/>.

import os, sys
import signal
import socket
import logging
from optparse import OptionParser, OptionGroup
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

#Color
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
END = '\033[0m'

def green(word):
	return GREEN + word + END

def yellow(word):
	return YELLOW + word + END

def red(word):
	return RED + word + END

print "\n"

if not os.geteuid()==0:
    print red("Run this as root!\n")
    exit(1)

class Timeout():
    """Timeout class using ALARM signal."""
    class Timeout(Exception):
        pass
 
    def __init__(self, sec):
        self.sec = sec
 
    def __enter__(self):
        signal.signal(signal.SIGALRM, self.raise_timeout)
        signal.alarm(self.sec)
 
    def __exit__(self, *args):
        signal.alarm(0)    # disable alarm
 
    def raise_timeout(self, *args):
        raise Timeout.Timeout()


def start_trace(target, proto, find, hops):
	ttl_id=0
	code = None

	while 1:
		ttl_id += 1
		try:
			with Timeout(8):
				if proto == "icmp":
					p=sr1(IP(dst=target, ttl=ttl_id)/ICMP(), verbose=False)
					code = p.type
				elif proto == "udp":
					p=sr1(IP(dst=target, ttl=ttl_id)/UDP(dport=33434), verbose=False)
					code = p.type
				else:
					p=sr1(IP(dst=target, ttl=ttl_id)/TCP(flags="S"), verbose=False)
					code = p.ack
				if p:
					try:
						hostname = socket.gethostbyaddr(p.src)
						result = str(ttl_id) + ") \t" + yellow(hostname[0]) + " ( " + yellow(p.src) + " )\n"
					except socket.error:
						result = str(ttl_id) + ") \t" + yellow(p.src) + "\n"
					
					if find != False and p.src == find:
						print green("IP Found:\n\n\t") + result
						break
					else:
						print result
						
					if proto == "icmp" and code == 0:
						break
					if proto == "udp" and code == 3:
						break
					if proto == "tcp" and code == 1:
						break
					
				else:
					print red("\nError while sending packet.\n")
					break
		except Timeout.Timeout:
			print str(ttl_id) + ") \t" + "* * *\n"
			
		if hops and (int(ttl_id) == int(hops)) == 1:
			break
			

parser = OptionParser()

parser.add_option( "-t", "--target", action="store", dest="target", default=False, help="Target address" );
parser.add_option( "-p", "--proto", action="store", dest="proto", default=False, help="Protocol (ICMP/UDP/TCP)" );
parser.add_option( "-f", "--find", action="store", dest="find", default=False, help="Find specific ip address" );
parser.add_option( "-n", "--node", action="store", dest="node", default=False, help="Number of nodes/hops" );

(o,args) = parser.parse_args()

if not o.target:
	print red("Specific target address!\n")
	exit(1)

if o.node:
	if o.node.isdigit() == False:
		print red("Specific number of hops!\n")
		exit(1)
	if int(o.node) > 255:
		print red("Number of hops is too high!\n")
		exit(1)

if o.proto:
	proto = o.proto
else:
	proto = "icmp"
	
	
start_trace(o.target, proto, o.find, o.node)
