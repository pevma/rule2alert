from scapy.all import *

"""
packets will always be as such
as long as it is TCP and established

packets[0] -> SYN
packets[1] -> SYN-ACK
packets[2] -> ACK
packets[3] -> DATA
packets[4] -> ACK
packets[5] -> FIN-ACK
packets[6] -> ACK
"""

class Evasion:
	def __init__(self, packets):
		self.type   = ""
		self.credit = ""
		self.packets = packets

	def alteredAck(self):
		self.credit = "Judy Novak"
		self.type   = "client"
		
		#Create the RST
		source      = self.packets[2][IP].src
		destination = self.packets[2][IP].dst
		srcport     = self.packets[2][TCP].sport
		dstport     = self.packets[2][TCP].dport
		seqnum      = self.packets[2][TCP].seq
		acknum      = self.packets[2][TCP].ack

		fakeAck = IP(src=source, dst=destination)/TCP(sport=srcport, dport=dstport, flags="A", seq=seqnum, ack=acknum+1)

		rst = IP(src=destination, dst=source)/TCP(sport=dstport, dport=srcport, flags="R", seq=acknum)

		#The rst packet needs to go after the fake rst
		store = []
		for i in range(5):
			store.append(self.packets.pop())
		store.reverse()

		#Append the fake ACK followed by the RST
		self.packets.append(fakeAck)
		self.packets.append(rst)

		#Tack on all of the original packets
		for packet in store:
			self.packets.append(packet)

		return self.packets
