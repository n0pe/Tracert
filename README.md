# Tracert 1.0 - Traceroute tool
Copyright (C) 2013  n0pe

Tracert is a simple traceroute tool written in python.
Support several type of protocol (ICMP/UDP/TCP, default is ICMP) and functions.

Dependences: <strong>python-scapy</strong>.


### Options ###

Usage: tracert.py [options]

Options:

  -h, --help            Show this help message.
  
  -t TARGET, --target=TARGET
                        Target address.
                        
  -p PROTO, --proto=PROTO
                        Protocol (ICMP/UDP/TCP).
                        
  -f FIND, --find=FIND  Find specific ip address.
  
  -n NODE, --node=NODE  Number of nodes/hops.


### Examples ###

./tracert.py -t 12.13.14.15
<br>
./tracert.py -t 12.13.14.15 -p tcp -n 5 -f 16.17.18.19
