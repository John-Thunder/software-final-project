# -*- coding: utf-8 -*-
#!/usr/bin/env python

import pygeoip
import json
import pyshark

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

def analyze_packets(pkt):
    
    try:
        protocol =  pkt.highest_layer
        src_addr = pkt.ip.src
        src_port = pkt[pkt.transport_layer].srcport
        dst_addr = pkt.ip.dst
        dst_port = pkt[pkt.transport_layer].dstport
        Timestamp = pkt.sniff_timestamp
        packet_info={"time":Timestamp,"src_ip":src_addr,"dst_ip":dst_addr,"sport":src_port,"dport": dst_port,"protocol":protocol}
        packet_info.update(geo_location('src',src_addr))
        packet_info.update(geo_location('dst',dst_addr))
        data.append(packet_info)
        #print '%s  %s:%s --> %s:%s' % (protocol, src_addr, src_port, dst_addr, dst_port)
    except AttributeError as e:
        #ignore packets that aren't TCP/UDP or IPv4
        pass
   

def test():
    """Open up a test pcap file and print out the packets"""
    pcap = pyshark.FileCapture('data\demo.pcap')
    #ssl_pcap = pyshark.FileCapture('data\easy_ssl\ssl.pcap',decode_as={'tcp.port==4433': 'ssl'},sslkey_path='data\easy_ssl\kcert.pem')
    pcap.apply_on_packets(analyze_packets)
    with open('data/demo_data_packet.txt','w') as f:
        f.write(str(data))
    

if __name__ == '__main__':
    data=[] #data 是存放return 資料的全域變數
    test()