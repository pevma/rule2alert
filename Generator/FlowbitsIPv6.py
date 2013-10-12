from scapy.all import *
from Parser.RuleParser import *
# TO DO add flowbits for UDP
# 
# This code is published under GPL v2 License Terms
#
# Descrpition: Flowbits (keyword) generator
# added flowbits support
#
# Author: Peter Manev
# 10/12/2012


class FlowbitsGeneratorIPv6:
  
  def __init__(self, dict_flowbits, sidGroup, packets, total_sids_loaded, sid_to_proto_map):
    #self.packets_flowbits = []
    self.sids = total_sids_loaded # same as self.sids in main; we need that to tell the order in which the sids were loaded
    self.sid_proto = sid_to_proto_map # 111-tcp,222-udp....
    self.sidGroup = sidGroup
    self.dict_flowbits = dict_flowbits
    self.packets = packets
    self.reordered_packets_flowbits = [] #temp list used to reorder the (self.)packets list with flowbitpackets
    self.sidGroup_flowbits = {} #position of the packets for  a flowbit name that belong to flowbits, packet positioning dictionary
    self.excl_flowbit_after_creation = [] #exclude looping through the follwoing flowbits, after they have been created once from another sid
    
    self.all_flowbit_sids = [] # a list of all sids that are part of a flowbit stream ,that need stream manipulation (excluding flowbit:set only)
    self.flowbit_name_options = [] # a list to check every flowbit name's options
    
    
    for flowbit_name in dict_flowbits.keys():
      self.temp = [] #because we need to destroy it with the begining of every loop
      #
      flowbit_sids = dict_flowbits[flowbit_name].split(',')
      self.flowbit_name_options = [ word for word in flowbit_sids if word.isalpha() ]
      
      #if we have many flowbits but all of them have just "set"
      if len(set(self.flowbit_name_options)) == 1 and "set" in set(self.flowbit_name_options):
	print "found only SET in flowbit name ",  flowbit_name , dict_flowbits[flowbit_name]
	del dict_flowbits[flowbit_name]
	continue
	#
	
      #if we have only one sid for the flowbit, no matter what the condition (set,isset....)
      elif len(set([value for value in flowbit_sids if value.isdigit()])) == 1:
	#print "found only one sid for flowbit name, skiping.. ",  flowbit_name , dict_flowbits[flowbit_name]
	del dict_flowbits[flowbit_name]
	continue
      
      #currently we do not suport udp ?!! - aka -  alert udp ...flowbits:xxx
      elif "udp" in set([self.sid_proto[value] for value in flowbit_sids if value.isdigit()]):
	del dict_flowbits[flowbit_name]
	continue
      
      else:
	#redo the list so that it contains only sids
	
	self.temp[:] = [value for value in flowbit_sids if value.isdigit()]
	dict_flowbits[flowbit_name] = self.temp
	#those flowbits who have multiple options (not only "set")
	# and need their streams recrafted/changed
	
	self.all_flowbit_sids.extend(dict_flowbits[flowbit_name])
	
	
    
    #looping through the unique flowbits names to sids map
    for flowbit_name in dict_flowbits.keys():
      #print "flowbit_name in the loop: ", flowbit_name, "with sids",dict_flowbits[flowbit_name]
      
      #don't do it/create it/loop more than once through the same flowbitname :)
      if flowbit_name in self.excl_flowbit_after_creation:
	continue
      
      #looping through the sids of a unique flowbit name
      for sid in dict_flowbits[flowbit_name]:
	self.set_of_combined_flowsids = [] # destroy it everytime
	self.alpha = [] # destroy everytime
	
	#don't do it/create it/loop more than once through the same flowbitname :)
	if flowbit_name in self.excl_flowbit_after_creation:
	  break
	
	
	#print sid,  "is part of the following flowbit names" , sid_to_flowbits_names_map[sid]
	#get a list of all the sids belonging to the flowbitname(s) ,(belonging to) that THIS sid (in the for loop) is part of
	self.set_of_combined_flowsids = sorted(set([ flowsid for name in sid_to_flowbits_names_map[sid] if name in dict_flowbits.keys() for flowsid in dict_flowbits[name] ]))
	#print "self.set_of_combined_flowsids", self.set_of_combined_flowsids
	
	#extended the check - really important - check for all the sids just above - self.set_of_combined_flowsids
	# if they belong to any other flowbits and if so get all the rest of the sids from these flowbitnames
	self.alpha =  sorted(set([ alphasid for xsid in self.set_of_combined_flowsids  for name in sid_to_flowbits_names_map[xsid] if name in dict_flowbits.keys() for alphasid in dict_flowbits[name]]))
	#
	
	#now for every sid combine the unique flowbits so that we will not loop/make throught them again after we create the packets once
	self.excl_flowbit_after_creation.extend(sorted(set([name for xsid in self.alpha  for name in  sid_to_flowbits_names_map[xsid] if name in dict_flowbits.keys() ])))
	#
	
	#reordering the sids in self.alpha - original order(sequence ) of the sids in self.alpha - important for flowbits!!
	self.alpha[:] =  [self.sids[index] for index in sorted([self.sids.index(item) for item in self.alpha]) ]
	#
	
	
	
	for sid in self.alpha:
	  
	  #returns true if the sid is the first sid in the list of flowbits
	  #aka - sets the flowbit condition
	  if self.alpha.index(sid) == 0: 
	    #print "First Sid is: ", sid
	    start, length = self.sidGroup[sid]
	    sids_packets = self.packets[start:start+length]
	  
	    self.temp_packets = copy.deepcopy(sids_packets[0:5])  #temp instance, we get 3handShake, payload and ack of payload packets
	  
	    tmp_client_isn = random.randint(4096, (4**16)-1)
	    tmp_server_isn = random.randint(4096, (4**16)-1)
	  
	    #reconstructing the handshake
	    self.temp_packets[0][TCP].seq = tmp_client_isn
	    self.temp_packets[1][TCP].seq = tmp_server_isn
	    self.temp_packets[1][TCP].ack = self.temp_packets[0].seq+1
	    self.temp_packets[2][TCP].seq = self.temp_packets[0].seq+1
	    self.temp_packets[2][TCP].ack = self.temp_packets[1].seq+1
	  
	    #the PSHACK packet - payload packet
	    self.temp_packets[3][TCP].ack = self.temp_packets[2][TCP].ack
	    self.temp_packets[3][TCP].seq = self.temp_packets[2][TCP].seq
	  
	    #the ACK of the push packet
	    self.temp_packets[4][TCP].seq = self.temp_packets[3][TCP].ack 
	    self.temp_packets[4][TCP].ack = (self.temp_packets[3][TCP].seq + len(self.temp_packets[3][Raw])) 
	  
	  #if the sid is nor the first nor the last sid in the flowbit condition
	  elif not self.alpha.index(sid) == 0 and not self.alpha.index(sid) == len(self.alpha)-1:
	    #print "MIDDLE Sid is:" , sid
	    start, length = self.sidGroup[sid]
	    sids_packets = self.packets[start:start+length]
	    self.temp_packets_middle = copy.deepcopy(sids_packets[3:5])  #temp_middle instance, we get  payload,Ack for the sid
	  
	    #we apend 2 packets - data,ack
	    #packet 0 - (Data), data/payload packet
	    self.temp_packets_middle[0][TCP].seq = self.temp_packets[len(self.temp_packets)-1][TCP].ack 
	    self.temp_packets_middle[0][TCP].ack = self.temp_packets[len(self.temp_packets)-1][TCP].seq 
	    self.temp_packets_middle[0][TCP].sport = self.temp_packets[len(self.temp_packets)-1][TCP].dport 
	    self.temp_packets_middle[0][TCP].dport = self.temp_packets[len(self.temp_packets)-1][TCP].sport 
	    self.temp_packets_middle[0][IPv6].src = self.temp_packets[len(self.temp_packets)-2][IPv6].src #make sure we have the same ip, from first sid's PA
	    self.temp_packets_middle[0][IPv6].dst = self.temp_packets[len(self.temp_packets)-2][IPv6].dst #make sure we have the same ip, from first sid's PA
	    
	    
	    #packet 1 - (Ack)
	    self.temp_packets_middle[1][TCP].seq = self.temp_packets_middle[0][TCP].ack
	    self.temp_packets_middle[1][TCP].ack = self.temp_packets_middle[0][TCP].seq + len(self.temp_packets_middle[0][Raw]) 
	    self.temp_packets_middle[1][TCP].sport = self.temp_packets_middle[0][TCP].dport
	    self.temp_packets_middle[1][TCP].dport = self.temp_packets_middle[0][TCP].sport
	    self.temp_packets_middle[1][IPv6].dst = self.temp_packets_middle[0][IPv6].src
	    self.temp_packets_middle[1][IPv6].src = self.temp_packets_middle[0][IPv6].dst
	    
	    #append the reworked packets to the flowbit sid's packets - because it is the last sid in the flowbit list
	    self.temp_packets.append(self.temp_packets_middle[0])
	    self.temp_packets.append(self.temp_packets_middle[1])
	    
	  
	  #last sid in the flowbit list  
	  elif self.alpha.index(sid) == len(self.alpha)-1:
	    #print "Last Sid is:" , sid
	    start, length = self.sidGroup[sid]
	    sids_packets = self.packets[start:start+length]
	    self.temp_packets_last = copy.deepcopy(sids_packets[3:])  #temp_last instance, we get  payload,Ack,FinAck,Ack for the sid
	    
	    #we apend the last 4 packets - data,ack,fin-ack,ack
	    #packet 0 - (Data), data/payload packet
	    self.temp_packets_last[0][TCP].seq = self.temp_packets[len(self.temp_packets)-1][TCP].ack 
	    self.temp_packets_last[0][TCP].ack = self.temp_packets[len(self.temp_packets)-1][TCP].seq 
	    self.temp_packets_last[0][TCP].sport = self.temp_packets[len(self.temp_packets)-1][TCP].dport 
	    self.temp_packets_last[0][TCP].dport = self.temp_packets[len(self.temp_packets)-1][TCP].sport 
	    self.temp_packets_last[0][IPv6].src = self.temp_packets[len(self.temp_packets)-2][IPv6].src #make sure we have the same ip, from first sid's PA
	    self.temp_packets_last[0][IPv6].dst = self.temp_packets[len(self.temp_packets)-2][IPv6].dst #make sure we have the same ip, from first sid's PA
	    
	    #packet 1 - (Ack)
	    self.temp_packets_last[1][TCP].seq = self.temp_packets_last[0][TCP].ack
	    self.temp_packets_last[1][TCP].ack = self.temp_packets_last[0][TCP].seq + len(self.temp_packets_last[0][Raw]) 
	    self.temp_packets_last[1][TCP].sport = self.temp_packets_last[0][TCP].dport
	    self.temp_packets_last[1][TCP].dport = self.temp_packets_last[0][TCP].sport
	    self.temp_packets_last[1][IPv6].dst = self.temp_packets_last[0][IPv6].src
	    self.temp_packets_last[1][IPv6].src = self.temp_packets_last[0][IPv6].dst
	    
	    
	    #packet 2 - (FinAck)
	    self.temp_packets_last[2][TCP].seq = self.temp_packets_last[1][TCP].ack
	    self.temp_packets_last[2][TCP].ack = self.temp_packets_last[1][TCP].seq 
	    self.temp_packets_last[2][TCP].sport = self.temp_packets_last[1][TCP].dport
	    self.temp_packets_last[2][TCP].dport = self.temp_packets_last[1][TCP].sport
	    self.temp_packets_last[2][IPv6].dst = self.temp_packets_last[1][IPv6].src
	    self.temp_packets_last[2][IPv6].src = self.temp_packets_last[1][IPv6].dst
	    
	    #packet 3 - (Ack)
	    self.temp_packets_last[3][TCP].seq = self.temp_packets_last[2][TCP].ack
	    self.temp_packets_last[3][TCP].ack = self.temp_packets_last[2][TCP].seq + 1
	    self.temp_packets_last[3][TCP].sport = self.temp_packets_last[2][TCP].dport
	    self.temp_packets_last[3][TCP].dport = self.temp_packets_last[2][TCP].sport
	    self.temp_packets_last[3][IPv6].dst = self.temp_packets_last[2][IPv6].src
	    self.temp_packets_last[3][IPv6].src = self.temp_packets_last[2][IPv6].dst
	    
	    #append the reworked packets to the flowbit sid's packets - because it is the last sid in the flowbit list
	    self.temp_packets.append(self.temp_packets_last[0])
	    self.temp_packets.append(self.temp_packets_last[1])
	    self.temp_packets.append(self.temp_packets_last[2])
	    self.temp_packets.append(self.temp_packets_last[3])
	    
	    #find the biggest MSS in the stream
	    biggest_mss = 0
	    for p in self.temp_packets:
	      if p[TCP].window >= biggest_mss:
		biggest_mss =  p[TCP].window
	      
	    #append the packets from the flowbit name
	    #and resize the MSS
	    for p in self.temp_packets:
	      mssLen = biggest_mss 
	      p[TCP].options = []
	      p[TCP].options.append(('MSS', mssLen))
	      p[TCP].window = mssLen 
	      self.reordered_packets_flowbits.append(p)
	      
	    #beacuse this is tha last sid from the sid group that has the same flowbit
	    #we make all the sids to point to the same packets/pcap
	    prevLen = len(self.reordered_packets_flowbits) - len(self.temp_packets)
	    numPackets = len(self.temp_packets)
	    for sid in self.alpha:
	      self.sidGroup[sid] = (prevLen, numPackets)
	      
	    for i in   sorted(set([name for xsid in self.alpha  for name in  sid_to_flowbits_names_map[xsid] if name in dict_flowbits.keys() ])) :
	      self.sidGroup_flowbits[i] = (prevLen, numPackets) #currently its not used
	    #return self.sidGroup_flowbits
	    
	    
	    
	    
    #general reindexing,reordering of ALL the sids/packets after all the flowbits are done
    for sid in self.sidGroup:
      #print sid, "sid is "
      start, length = self.sidGroup[sid]
      #print start, length, "start, length"
      
      if  sid not in self.all_flowbit_sids:
	sids_packets = self.packets[start:start+length]
	for p in sids_packets:
	  self.reordered_packets_flowbits.append(p)
	
	#print "Lenght of reordered packets", len(self.reordered_packets_flowbits)
	#print "Lenghtsids packets", len(sids_packets)
	prevLen = len(self.reordered_packets_flowbits) - len(sids_packets)
	numPackets = len(sids_packets)
	self.sidGroup[sid] = (prevLen, numPackets)
	#print prevLen, numPackets, "prevLenght, numPackets"
	
      
    self.packets[:] = self.reordered_packets_flowbits #new packet order
    