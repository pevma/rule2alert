import re,binascii

class HTTP:
	
	def __init__(self):
		self.method     = "GET"
		self.uri        = "/"
		self.version    = "HTTP/1.1"
		#self.host       = "www.malforge.com"
		self.host	= "www.domain.tld"
		self.user_agent = "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.5) Gecko/20091102 Firefox/3.5.5 (.NET CLR 3.5.30729)"
		self.keep_alive = "300"
		self.connection = "keep-alive"
		self.cookie     = ''
		self.payload    = ""

	def build(self):

		#HTTP URI Normalization
		if self.uri.find("|") != -1:
			while self.uri.find("|") != -1:
				m = re.search("\|([A-F0-9\s]+)\|", self.uri)
				if not m:
					break
				total = m.group(0)
				payload = total
				val = m.group(1)
				values = []
				if len(val) > 2: 
					values = val.split(" ")
				else: 
					values.append(val)

				for v in values:
					payload = re.sub(v.strip(), binascii.unhexlify(v.strip()), payload)
					payload = re.sub(' ','',payload)

				start = self.uri.find(total)
				if start == 0:
					self.uri = payload[1:-1] + self.uri[len(total):]
				else:
					self.uri = self.uri[:start] + payload[1:-1] + self.uri[start+len(total):]
		
		if self.uri.startswith("."):
			self.uri = "test%s" % self.uri
		if not self.uri.startswith("/"):
			self.uri = "/%s" % self.uri

		self.payload = "%s %s %s\r\nHost: %s\r\nUser-Agent: %s\r\nKeep-Alive: %s\r\nConnection: %s\r\nCookie: %s\r\n\r\n" % (self.method, self.uri, self.version, self.host, self.user_agent, self.keep_alive, self.connection, self.cookie)
	
		#if self.cookie:
		#	self.payload = "%sCookie: %s\r\n" % (self.payload, self.cookie)

		#Add the additional return newline to the headers
		#self.payload = "%s\r\n" % self.payload

	def check(self, payload):
		m = re.search("(?P<key>[\w\-]+)(\\\:|\:|\|3a\|)\s+(?P<value>[\w\s/\.;\-\:\(\)]+)", payload)
		if m:
			key = m.group("key")
			value = m.group("value")

			#HTTP Normalization
			if key == "User-Agent":
				self.user_agent = value
				if self.user_agent.endswith("\r\n"):
					self.user_agent = self.user_agent[:-2]
			if key == "Host":
				self.host = value
			if key == "Cookie":
				self.cookie = value

		else:
			if payload.find("GET") != -1:
				self.method = "GET"
			if payload.find("POST") != -1:
				self.method = "POST"

