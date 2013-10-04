#!/usr/bin/python
'''
@author: famousjs
'''

from scapy.all import *
from Parser.RuleParser import *
from Parser.SnortConf import *
from Parser.SuriConf import *
from Generator.Payload import *
from Generator.TestSnort import *
from Generator.TestSuricata import *
from Generator.Evasion import *
from Generator.Flowbits import *
from optparse import OptionParser
import os,sys
import re
from time import sleep

class r2a:
	#Initial function sets global variables used throughout the class
	#Calls parseConf and loadRules to parse the snort configuration
	#file as well as load in the snort rules to generate packets
	def __init__(self, options):
		#Command line options
		self.options = options
		#Suricata/Snort conf variables
		
		if self.options.Dot1Q and self.options.QinQ:
		  print "You can not provide both --Dot1Q and --QinQ options. Please choose only one !"
		  sys.exit(0)
		  
		if not self.options.snort_conf and not self.options.suri_conf : 
			if not self.options.extNet or not self.options.homeNet:
				print "If no snort conf or suricata.yaml conf, please provide ExtNet and HomeNet variables via command line"
				sys.exit(0)
			else:
				self.snort_vars = SnortConf().default(self.options.extNet, self.options.homeNet)
		elif self.options.snort_conf:
			self.snort_vars = SnortConf(self.options.snort_conf).parse()
		else:
			self.snort_vars = SuriConf(self.options.suri_conf).parse()
		if self.options.extNet:
			self.snort_vars["EXTERNAL_NET"] = self.options.extNet
		if self.options.homeNet:
			self.snort_vars["HOME_NET"] = self.options.homeNet
		#Snort rules
		self.rules = self.loadRules(self.options.rule_file)
		#added to print rules into a file
		self.rules_toprint = {}  
		#sid to protocol (udp,tcp,htp...) map
		self.sid_proto = {}
		#Packet generator
		self.ContentGen = ""
		#List of packets built from rules
		self.packets = []
		#Number of alerts from snort test cases
		self.alerts = 0
		#Number of rules initially loaded
		self.rules_loaded = 0
		#Collection of SIDS loaded
		self.sids = []
		#Association of SID to Packets
		self.sidGroup = {}
		#good sids, that generated an alert
		self.goodSids = []
		#self.loaded_sids = []
		#List of Failed SIDS
		self.failSids = []
		#Used in SID reproduction
		self.count = None
		self.manual = False
		if self.options.manualNum and self.options.manualSid:
			if int(self.options.manualNum) < 1:
				self.manual = False
			else:
				self.manual = True
				self.count = int(self.options.manualNum)

	def main(self):
		#manualCount = 0
		#Regexp for avoid comments and empty lines
		pcomments = re.compile('^\s*#')
		pemptylines = re.compile('^\s*$')
		#Go through each snort rule
		for snort_rule in self.rules:
			snort_rule = snort_rule.strip()
			#Parse the snort rule using the snort parser
			comments = pcomments.search(snort_rule)
			emptylines = pemptylines.search(snort_rule)
			#If it's not a comment or an empty line...
			if not comments and not emptylines: 
				try:
					r = Rule(snort_rule)

					if self.manual and str(r.sid) == self.options.manualSid and self.count != 1:
						self.count -= 1
						self.rules.append(snort_rule)
	
					print "Building Rule: %s" % str(r.sid)
					
					self.ContentGen = PayloadGenerator(r, self.snort_vars, self.options)

					if self.ContentGen.notSupported:
						continue

					self.ContentGen.build()

					if self.options.evasion: self.evasion()

					self.sids.append(r.sid)

					prevLen = len(self.packets)
					numPackets = len(self.ContentGen.packets)
					self.sidGroup[r.sid] = (prevLen, numPackets)

					for p in self.ContentGen.packets:
						self.packets.append(p)

					if self.options.hex:
						print "\n" + self.ContentGen.hexPrint()

					self.rules_loaded += 1 
					# 
					self.rules_toprint[r.sid] = (snort_rule) 
					self.sid_proto[r.sid] = r.proto
					#
					

					sleep(0.0001)

				except:
					traceback.print_exc()
					print "Parser failed - skipping rule"
					continue

		print "Loaded %d rules succesfully!" % self.rules_loaded

		#added flowbits support
		if dict_flowbits:
		  print "Loading flowbits rules...\n\n\n"
		  FlowbitsGenerator(dict_flowbits, self.sidGroupReturn(), self.PacketsReturn(), self.sids, self.sid_proto)
		
		
		if self.packets and self.options.pcap:
			print "Writing packets to pcap..."
			self.write_packets()
			print "Finished writing packets" #we need to move that after the flowbits below !!
		

		if self.options.testSnort and self.options.pcap:
			print "Running snort test..."
			self.test_snort()

		if self.options.testSuricata and self.options.pcap:
			print "Running Suricata test..."
			self.test_suricata()

		if (self.options.testSnort or self.options.testSuricata) and self.options.failStream:
			#if not self.failSids: return
			if self.goodSids:
			  #print self.loaded_sids
			  #print self.failSids
			  #self.goodsids=list(set(self.failSids)-set(self.loaded_sids))
			  #print self.goodSids
			  for sid in self.goodSids:
				start, length = self.sidGroup[sid]
				#end = start + (length)
				if length == 1:
					r = self.packets[start]
				elif length > 1:
					r = self.packets[start:start+(length)]
					
				if self.options.Dot1Q:
				  pcap_id = "002-rule2alert_IPv4_Dot1Q"
				  wrpcap("output/goodstreams/%s-%s-public-tp-01.pcap" % (sid, pcap_id), r) 
				  good_rule = open("output/goodstreams/%s.rules" % sid,'w') 
				  good_rule.write(self.rules_toprint[sid]) 
				  good_rule.close() 
				  
				elif self.options.QinQ:
				  pcap_id = "003-rule2alert_IPv4_QinQ"
				  wrpcap("output/goodstreams/%s-%s-public-tp-01.pcap" % (sid, pcap_id), r) 
				  good_rule = open("output/goodstreams/%s.rules" % sid,'w') 
				  good_rule.write(self.rules_toprint[sid]) 
				  good_rule.close() 
				  
				else:
				  wrpcap("output/goodstreams/%s-001-rule2alert_IPv4-public-tp-01.pcap" % sid, r) 
				  good_rule = open("output/goodstreams/%s.rules" % sid,'w') 
				  good_rule.write(self.rules_toprint[sid]) 
				  #print self.rules_toprint[sid]
				  good_rule.close() 
				  
				  
				
			if self.failSids:
			  for badsid in self.failSids:
				start, length = self.sidGroup[badsid]
				#end = start + (length-1)
				if length == 1:
					r = self.packets[start]
				elif length > 1:
					r = self.packets[start:start+(length)]
				wrpcap("output/failstreams/%s-001-rule2alert-public-tp-01.pcap" % badsid, r) 
				fail_rule = open("output/failstreams/%s.rules" % badsid,'w') 
				fail_rule.write(self.rules_toprint[badsid]) 
				#print self.rules_toprint[sid] 
				fail_rule.close() 
		
			

	#Reads in the rule file specified by the user
	def loadRules(self, rule_file):
		f = open(rule_file, 'r')
		rules = f.read().splitlines()
		f.close()

		return rules
		
	def sidGroupReturn(self):
		return self.sidGroup #for use in Flowbits.py
		
	def PacketsReturn(self):
		return self.packets #for use in Flowbits.py



	def write_packets(self):
		wrpcap(self.options.pcap, self.packets)

	def test_snort(self):
		t = TestSnort(self.options.pcap, self.sids)
		self.failSids = t.run()

	def test_suricata(self):
		t = TestSuricata(self.options.pcap, self.sids, self.options)
		(self.failSids, self.goodSids) = t.run()

	def evasion(self):
		if not self.ContentGen.proto == "tcp" or not self.ContentGen.flow.established:
			return

		try:
			e = Evasion(self.ContentGen.packets)
			if self.options.evasion == "1":
				self.ContentGen.packets = e.alteredAck()
				print "Altered ACK Evsaion - Credit: %s" % e.credit

			else: return
		except:
			return

#Parses arguments that are passed in through the cli
def parseArgs():
	usage = "usage: python r2a.py [-vtT] -f rule_file -e <EXTERNAL IP> -m <HOME IP> -w pcap [-E<num>]\nEvasion Techniques in evasion.txt"
	parser = OptionParser(usage)
	
	parser.add_option("-c", help="Read in snort configuration file", action="store", type="string", dest="snort_conf")
	parser.add_option("-C", help="Read in suricata.yaml configuration file", action="store", type="string", dest="suri_conf")
	parser.add_option("-B", help="Use a Suricata binary file from a custom location", action="store", type="string", dest="suri_binary")
	parser.add_option("-L", help="Use a Suricata log directory from a custom location", action="store", type="string", dest="suri_log")
	parser.add_option("-f", help="Read in snort rule file", action="store", type="string", dest="rule_file")
	parser.add_option("-F", help="Write failed streams to pcap", action="store_true", dest="failStream")
	parser.add_option("-w", help="Name of pcap file", action="store", type="string", dest="pcap")
	parser.add_option("--Dot1Q", help="Dot1Q option - add VLAN ID", action="store_true", dest="Dot1Q")
	parser.add_option("--QinQ", help="QinQ option - add QinQ ID", action="store_true", dest="QinQ")
	
	
	parser.add_option("-v", help="Verbose hex output of raw alert", action="store_true", dest="hex")
	parser.add_option("-t", help="Test rule against current snort configuration", action="store_true", dest="testSnort")
	parser.add_option("-T", help="Test rule against current Suricata configuration", action="store_true", dest="testSuricata")
	parser.add_option("-m", help="Set $HOME_NET IP Address", action="store", type="string", dest="homeNet")
	parser.add_option("-e", help="Set $EXTERNAL_NET IP Address", action="store", type="string", dest="extNet")
	parser.add_option("-s", help="Manual SID Selection", action="store", type="string", dest="manualSid")
	parser.add_option("-n", help="Number of times to alert SID", action="store", type="string", dest="manualNum")
	parser.add_option("-E", help="Evasion Technique", action="store", type="string", dest="evasion")

	if len(sys.argv) == 1:
		parser.print_help()
		sys.exit(0)

	(options, args) = parser.parse_args(sys.argv)
	
	
	r = r2a(options)
	r.main()

if __name__ == "__main__":
	parseArgs()
