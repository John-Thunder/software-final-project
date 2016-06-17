#!/usr/bin/env python
"""
Use DPKT to read in a pcap file and print out the contents of the packets
This example is focused on the fields in the Ethernet Frame and IP packet
"""
import dpkt
import datetime
import socket
import win_inet_pton
import json
import copy
import sys
import re
from tqdm import tqdm


def mac_addr(address):
    return ':'.join('%02x' % ord(b) for b in address)


def ip_to_str(address):
    return socket.inet_ntop(socket.AF_INET, address)
def task_status(task_id):
    with open('task/'+str(task_id)+'.txt', 'rb') as f:
        line=f.readlines()[-1].decode()
        progress= re.findall('[0-9]{1,3}\%', line)
        speed=re.findall('\d+\.\d+it\/s',line)
        get_time=re.split('\<',re.findall('\d+\:\d+<\d+\:\d+',line)[-1])
        running_time=get_time[0]
        remaining_time=get_time[1]
        return progress[-1],running_time,remaining_time,speed[-1]

def print_packets(task_id,pcap):
    """Print out information about each packet in a pcap

       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    """
    data=[]
    sys.stdout = open('task/'+str(task_id)+'.txt', 'w')
    # For each packet in the pcap process the contents
    for timestamp, buf in tqdm(pcap,file=sys.stdout,mininterval=1):
        # Print out the timestamp in UTC
        Timestamp= str(datetime.datetime.utcfromtimestamp(timestamp))

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        #print 'Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type

        # Make sure the Ethernet frame contains an IP packet
        # EtherType (IP, ARP, PPPoE, IP6... see http://en.wikipedia.org/wiki/EtherType)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            #print 'Non IP Packet type not supported %s\n' % eth.data.__class__.__name__
            continue

        # Now unpack the data within the Ethernet frame (the IP packet) 
        # Pulling out src, dst, length, fragment info, TTL, and Protocol

        ip = eth.data

        # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
        do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

        # Print out the info
        #print 'IP: %s -> %s \n' % \
        #      (ip_to_str(ip.src), ip_to_str(ip.dst))
        data.append( {"time":Timestamp,"src_ip":ip_to_str(ip.src),"dst_ip":ip_to_str(ip.dst)})
        
    return  data

        
def test():
    """Open up a test pcap file and print out the packets"""
    task_status(1)
    #with open('data/example.pcap', 'rb') as f:
    #    pcap = dpkt.pcap.Reader(f).readpkts()
    #    data=print_packets(1,pcap)
    

if __name__ == '__main__':
    test()