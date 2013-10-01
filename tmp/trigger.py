#!/usr/bin/python
import os,sys,re
from scapy.all import *
from optparse import OptionParser


class trigger:
	flow = IP()
	protocol = ""
	home_net = ""
	ext_net = ""
	src = ""
	sport = ""
	dst = ""
	dport = ""

	def main(self, options):
		self.home_net = options.home_net
		self.ext_net = options.ext_net

		f = open(options.rule_file)
		data = f.read().splitlines()
		f.close()

		packets = []

		for sig in data:
			content_object_list, handshake = self.proc_sig(sig)
			if handshake:
				for p in handshake:
					packets.append(p)
			p = self.build_content(handshake, content_object_list)
			packets.append(p)
			
	
		print "Done"
		print len(packets)
		for p in packets:
			print p.summary()


	def proc_sig(self,sig):
		header, body = sig.split("(")
		type, proto, self.src, self.sport, a, self.dst, self.dport = header.strip().split(" ")
		
		self.handle_proto(proto)

		self.set_flow()
		
		handshake = self.build_handshake()

		body = body[:-2]

		c_objs = []


		skip = ["rev", "sid", "reference", "msg"]
		mods = ["distance", "within", "offset", "depth", "isdataat"]
		c_types = ["content", "uricontent"]

		i = 0
		b_split = body.split(";")		

		while i != len(b_split):
			cur = b_split[i].strip()
			c = content_obj()
			if cur.find(":") == -1:
				i += 1
				continue

			type,data = cur.split(":")

			if type in skip:
				i += 1
				continue

			elif type in mods:
				print "Found mod: %s" % cur
				c_objs[-1].modifiers.append(cur)
				i += 1
				continue

			elif type in c_types:
				c.type = type
				c.data = data
				print "Appending found content: %s" % cur
				c_objs.append(c)

				i += 1
				continue

			else:
				i += 1
				continue

		#self.set_flow()

		return c_objs,handshake

	
	def build_content(self, handshake, content_list):
		#We need to handle protcols here
		#HTTP
		if self.protocol.dport == 80 or self.protocol == "http": 
			print "HTTP TRAFFIC"
			print "RuleParser.proto"
			#We need to build the headers
			#Also based on content in the objects
			ack = handshake[-1]
			headers = self.handle_http(content_list)

			p = IP(src=self.flow.src, dst=self.flow.dst)/TCP(flags="PA", sport=self.protocol.sport, dport=self.protocol.dport, seq=ack.seq, ack=ack.ack)/headers

			return p

		#if self.protocol.dport == somethingelse
		#Handle that too

	def handle_http(self, content_list):
		type = "GET"
		uri = "/"
		accept = "*/*"
		accept_encoding = "gzip, deflate"
		accept_language = "en-us"
		user_agent = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
		host = "www.malforge.com"
		connection = "Keep-Alive"	

		#Here we go through the content objects and change anything
		#that needs to be changed in the default headers
		
		http_header = "%s %s HTTP/1.1\r\nAccept: %s\r\nAccept-Language: %s\r\nAccept-Encoding: %s\r\nUser-Agent: %s\r\nHost: %s\r\nConnection: %s\r\n\r\n" % (type, uri, accept, accept_encoding, accept_language, user_agent, host, connection)
		
		return http_header

	def set_flow(self):
		port = ""
		if self.dport == "$HTTP_PORTS":
			self.protocol.dport = 80
		else:
			self.protocol.dport = int(self.dport)

		if self.sport == "any":
			self.protocol.sport = 9001
		else:
			self.protocol.sport = int(self.sport)

		home_servs = ["$HOME_NET", "$DNS_SERVERS", "$SMTP SERVERS", "$HTTP_SERVERS", "$SQL SERVERS", "$TELNET_SERVERS", "$SNMP_SERVERS"]

		m = False

		print "External Net: %s" % self.ext_net
		print "Internal Net: %s" % self.home_net

		if self.dst in home_servs:
			#Going to internal net
			self.flow.src = self.ext_net
			self.flow.dst = self.home_net
				
		elif self.src in home_servs:
			#Coming from internal net
			self.flow.src = self.home_net
			self.flow.dst = self.ext_net


	def handle_proto(self,p):
		if p == "tcp":
			self.protocol = TCP()
		elif p == "udp":
			self.protocol = UDP()
		
	def get_flow(self):
		return self.flow

	def build_handshake(self):
		#Create the ISN Numbers
		client = 1932
		server = 1059

		#Create the SYN Packet
		syn = Ether()/IP(src=self.flow.src, dst=self.flow.dst)/TCP(flags="S", sport=self.protocol.sport, dport=self.protocol.dport, seq=client)
	
		#Create the SYN ACK
		synack = Ether()/IP(src=self.flow.dst, dst=self.flow.src)/TCP(flags="SA", sport=self.protocol.dport, dport=self.protocol.sport, seq=server, ack=syn.ack+1)
		
		#Create the ACK
		ack = Ether()/IP(src=self.flow.src, dst=self.flow.dst)/TCP(flags="A", sport=self.protocol.sport, dport=self.protocol.dport, seq= syn.seq+1, ack=synack.seq+1)

		handshake = [syn, synack, ack]

		return handshake

class content_obj(object):
	def __init__(self):
		self.type = ""
		self.data = ""
		self.modifiers = []


def parseArgs():
	usage = "usage: ./trigger.py -f file -e ext_net -i home_net <-s IP>|<-w pcap>"
	parser = OptionParser(usage)

	parser.add_option("-f", help="Read in snort rule file", action="store", type="string", dest="rule_file")
	parser.add_option("-e", help="External net IP", action="store", type="string", dest="ext_net")
	parser.add_option("-i", help="Home net IP", action="store", type="string", dest="home_net")
	parser.add_option("-w", help="Write to pcap", action="store", type="string", dest="pcap")
	parser.add_option("-s", help="Send packets to IP", action="store", type="string", dest="send_ip")

	(options, args) = parser.parse_args(sys.argv)

	t = trigger()
	t.main(options)

if __name__ == "__main__":
	parseArgs()
