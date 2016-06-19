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
import pygeoip
import json
import csv
from tqdm import tqdm

def mac_addr(address):
    return ':'.join('%02x' % ord(b) for b in address)


def ip_to_str(address):
    return socket.inet_ntop(socket.AF_INET, address)

def check_protocols(port_num):
    __result={}

    return __result

def task_status(task_id):
    __result={}
    with open('task/'+str(task_id)+'.txt', 'rb') as f:
        line=f.readlines()[-1].decode()
        __result['progress']= re.findall('[0-9]{1,3}\%', line)[-1]
        __result['speed']=re.findall('\d+\.\d+it\/s',line)[-1]
        get_time=re.split('\<',re.findall('\d+\:\d+<\d+\:\d+',line)[-1])
        __result['running_time']=get_time[0]
        __result['remaining_time']=get_time[1]
        return __result

def geo_location(name,addr):
    __result={}
    gi = pygeoip.GeoIP('Geo/GeoLiteCity.dat')
    __data=gi.record_by_addr(addr)
    if __data!=None:
        __result[name+'_city']=__data['city']
        __result[name+'_country_code']=__data['country_code']
        __result[name+'_latitude']=__data['latitude']
        __result[name+'_longitude']=__data['longitude']
    else:
        __result[name+'_city']=''
        __result[name+'_country_code']=''
        __result[name+'_latitude']=''
        __result[name+'_longitude']=''
    return __result

def analyze_packets(task_id,pcap):
    __data=[]
    tcp_map,udp_map=gen_services_map()

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
        packet_info={"time":Timestamp,"src_ip":ip_to_str(ip.src),"dst_ip":ip_to_str(ip.dst)}
        if ip.p==17 and ip.data.dport in udp_map:
            packet_info.update({"protocols":udp_map[ip.data.dport],"sport":ip.data.sport,"dport":ip.data.dport})
        elif ip.p==17 and ip.data.dport not in udp_map:
            packet_info.update({"protocols":"unknown","sport":ip.data.sport,"dport":ip.data.dport})
        elif ip.p==1:
            packet_info.update({"protocols":"icmp"})
        elif (ip.data.flags & dpkt.tcp.TH_SYN ==1 ) and (ip.data.flags & dpkt.tcp.TH_ACK ==0) and ip.p==6 and ip.data.dport in tcp_map:
           packet_info.update({"protocols":tcp_map[ip.data.dport],"sport":ip.data.sport,"dport":ip.data.dport})
        else:
            packet_info.update({"protocols":"unknown","sport":ip.data.sport,"dport":ip.data.dport})
        packet_info.update(geo_location('src',ip_to_str(ip.src)))
        packet_info.update(geo_location('dst',ip_to_str(ip.dst)))

        __data.append(packet_info)
    sys.stdout=sys.__stdout__
    return  json.dumps(__data)

        
def test():
    """Open up a test pcap file and print out the packets"""
    
    with open('data/example.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f).readpkts()
        data=analyze_packets(1,pcap)
    #print task_status(1)
    with open('data/test.txt', 'w') as f:
        f.write(data)
    
    
def gen_services_map():
    tcp_map={}
    udp_map={}
    f = open('data/services_map.csv', 'r')
    for row in csv.DictReader(f):
         if row['Transport Protocol']=='tcp':
             tcp_map[row['Port Number']]=row['Service Name']
         elif  row['Transport Protocol']=='udp':
             udp_map[row['Port Number']]=row['Service Name']
    return  tcp_map,udp_map

if __name__ == '__main__':

    test()