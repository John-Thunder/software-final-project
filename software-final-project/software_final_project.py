# -*- coding: utf-8 -*-
#!/usr/bin/env python

import pygeoip
import json,sys
import pyshark
from cStringIO import StringIO


def analyze_packets(traceFile):
    cap = pyshark.FileCapture(traceFile)
    data=[]
    def network_flow(pkt):
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

    cap.apply_on_packets(network_flow)
    return data



def get_packet_detail(traceFile, number):
	cap = pyshark.FileCapture(traceFile)

	old_stdout = sys.stdout
	sys.stdout = mystdout = StringIO()

	cap[number-1].pretty_print()

	sys.stdout = old_stdout

	detail = ''

	for line in mystdout.getvalue().split('\n'):
		if line == 'self._packet_string':
			continue
		elif 'Layer ETH' in line:
			detail += '''<div class="panel panel-default">
						  <div class="panel-heading" role="tab">
						    <h4 class="panel-title">
						      <a class="packetHeader" data-target="#%(link)s">
						        <i class="fa fa-caret-right fa-rotate-90"></i>
						        %(name)s
						      </a>
						    </h4>
						  </div>
						  <div id="%(link)s" class="panel-collapse">
						    <div class="panel-body">
			''' % {'name': line[:-1], 'link': line.replace(' ', '-').strip(':')}
		elif 'Layer' in line:
			detail += '''</div>
						  </div>
						</div>
						<div class="panel panel-default">
						  <div class="panel-heading" role="tab">
						    <h4 class="panel-title">
						      <a class="packetHeader" data-target="#%(link)s">
						        <i class="fa fa-caret-right"></i>
						        %(name)s
						      </a>
						    </h4>
						  </div>
						  <div id="%(link)s" class="panel-collapse collapse">
						    <div class="panel-body">
			''' % {'name': line[:-1], 'link': line.replace(' ', '-').strip(':')}
		else:	
			keyword = line.split(': ')[0] + ': '

			try:
				value = line.split(': ')[1]
			except IndexError:
				keyword = ''
				value = line
			
			try:
				keyword = keyword.split('= ')[1]
			except IndexError:
				pass

			detail += '<p><strong>%s</strong> %s</p>\n' % (keyword, value)

	detail += '</div></div></div>'
	return detail
   
def decode_capture_file_summary(traceFile, display_filter=None):
		
	if display_filter:
		cap = pyshark.FileCapture(traceFile, keep_packets=False, only_summaries=True, display_filter=display_filter)
	else:	
		cap = pyshark.FileCapture(traceFile, keep_packets=False, only_summaries=True)

	cap.load_packets(timeout=5)

	if len(cap) == 0:
		return 0, 'No packets found or the display filter is invalid.'

	details = {
		'packets': [],
		# 'linechart': []
		}
	
	avg_length = []
	
	def decode_packet(packet):

		pkt_details = {
			'number' : packet.no,
			'length' : packet.length,
			'time' : packet.time
		}
		pkt_details['src_ip'] = packet.source
		pkt_details['dst_ip'] = packet.destination
		pkt_details['protocol'] = packet.protocol
		pkt_details['desc'] = packet.info
		
		# delta and stream aren't supported by earlier versions (1.99.1) of tshark
		try:
			pkt_details['delta'] = packet.delta
			pkt_details['stream'] = packet.stream
		except AttributeError:
			pass

		details['packets'].append(pkt_details)
		avg_length.append(int(packet.length))

	try:
		cap.apply_on_packets(decode_packet, timeout=600)
	except:
		return 0, 'Capture File is too large, please try downloading and analyzing locally.'

	
	return len(cap), details

def test():
    """Open up a test pcap file and print out the packets"""
    pcap_file='data\demo.pcap'
   
    pcap_len,details=decode_capture_file_summary(pcap_file,display_filter=None) #display_filter 是過濾器，例如可以單純顯示http封包，display_filter=http
    
    print get_packet_detail(pcap_file,1) #參數一為file，參數二是想看的packet編號的內容， 會return 一個html的內容，從數字1開始算
    output_save= analyze_packets(pcap_file) #詳細分析pcap的內容並返回地理位置，來源、目的地等資料

    

if __name__ == '__main__':
    test()