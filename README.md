# Trace 1.0 - Traceroute tool
Copyright (C) 2013  n0pe

Trace is a simple traceroute tool written in python.
Support several type of protocol (ICMP/UDP/TCP) and functions.


### Options ###

Usage: trace.py [options]

Options:

  -h, --help            Show this help message.
  
  -t TARGET, --target=TARGET
                        Target address.
                        
  -p PROTO, --proto=PROTO
                        Protocol (ICMP/UDP/TCP).
                        
  -f FIND, --find=FIND  Find specific ip address.
  
  -n NODE, --node=NODE  Number of nodes/hops.


### Examples ###

./trace.py -t 12.13.14.15 -p tcp -n 5 -f 16.17.18.19
