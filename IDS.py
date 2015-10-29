#!/usr/bin/env python

import sys
import dpkt
import socket
import re

ETHERNET = 2048
DNS_PORT = '53'
SINKHOLE_FILE = 'sinkholes.txt'

def get_mac_address(mac_string):
    return ':'.join('%02x' % ord(b) for b in mac_string)

filename = sys.argv[1]
print filename
pcapfile = open(filename, 'rb')
pcap = dpkt.pcap.Reader(pcapfile)

# TO-DO Make the regular expression better encapsulate possible addresses
ip_subnet = re.compile("10.[0-9]+.[0-9]+.[0-9]+")
no_of_packets = 0
total_size = 0

for ts, buf in pcap:
    no_of_packets += 1
    total_size += len(buf)

    eth = dpkt.ethernet.Ethernet(buf)

    if eth.get_type(eth.type) == dpkt.ip.IP:
        ip = eth.data
        source = socket.inet_ntoa(ip.src)
        destination = socket.inet_ntoa(ip.dst)

        # 2 - Spoof-Test :
        if not (ip_subnet.match(source) or ip_subnet.match(destination)):
            print '[Spoofed IP address]: src:', source, 'dst:', destination

        # 3 - Unauthorized Servers :
        # Incoming Server Connection ( Catching Syn )
        if ip_subnet.match(destination):
            if not ip_subnet.match(source):
                if ip.p == dpkt.ip.IP_PROTO_TCP:
                    tcp = ip.data
                    port = str(tcp.sport)
                    if tcp.flags & dpkt.tcp.TH_SYN != 0:
                        print '[Attempted server connection]: rem:' + source + ', srv:' + destination + ', port:' + port

        # Acceptance on incoming server connection ( Catching Ack )
        if ip_subnet.match(source):
            if not ip_subnet.match(destination):
                if ip.p == dpkt.ip.IP_PROTO_TCP:
                    tcp = ip.data
                    port = str(tcp.sport)
                    if (tcp.flags & dpkt.tcp.TH_SYN != 0) and (tcp.flags & dpkt.tcp.TH_ACK != 0):
                        print '[Accepted server connection]: rem:' + source + ', srv:' + destination + ', port:' + port

        # 4 - Sinkhole Lookups
        if ip_subnet.match(source):
            if ip.p == dpkt.ip.IP_PROTO_UDP:
                udp = ip.data
                # Consider unsigned int VS String conversion here .
                port = str(udp.sport)
                if port == DNS_PORT:
                    dns = dpkt.dns.DNS(udp.data)
                    if dns.qr == 1:
                        dnsanswer = ''
                        dnshost = ''
                        for answer in dns.an:
                            if answer.type == 1:
                                dnsanswer = str(socket.inet_ntoa(answer.rdata))
                                dnshost = str(answer.name)
                            sinkholes = open(SINKHOLE_FILE, 'rb')
                            # Consider better sanitized way of checking line and sinkholes !
                            for line in sinkholes:
                                if dnsanswer in line:
                                    print '[Sinkhole Lookup]:', 'src:' + destination, ',host:' + dnshost, ',ip:' + dnsanswer

# 1 Packet Analysis
print 'Analyzed', no_of_packets, 'packets,', total_size, 'bytes'

# Spoof Testing code :
"""
Testing for accuracy of detector :

if ip_subnet.match(socket.inet_ntoa(ip.src)) or ip_subnet.match(socket.inet_ntoa(ip.dst)):
    print('Valid')
else:
    print(socket.inet_ntoa(ip.src) , socket.inet_ntoa(ip.dst))
"""
