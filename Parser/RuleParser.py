# This code is published under GPL v2 License Terms
#
# Descrpition: General Purpose rule parser
#
# Author: Pablo Rincon Crespo 
# Author: Josh Smith
# 5/12/2009
#
# Author: Peter Manev
# 11/11/2012

import re,sys
from binascii import *
import RevRegex2

class RuleUriContent:
    def __init__(self, uricontent):
        # check for negated uricontent option
        if uricontent[0] == "!":
            self.negated = True
            self.uricontent = uricontent[1:]
        else:
            self.negated = False
            self.uricontent = uricontent
        # Strip quotes.. "'s
        if self.uricontent[0] == '"':
            self.uricontent = self.uricontent[1:-1]

    def __str__(self):
        r = "RuleUriContent:\n"
        r = r + " - uricontent: "+ self.uricontent
        r = r + "\n" + " - negated: "+ str(self.negated)
        return r + "\n"

class RuleContent:
    content = ""
    payload = None
    def __init__(self, content):
      
        # check for negated content option
        if content[0] == "!":
            self.negated = True
            self.content = content[1:]
        else:
            self.negated = False
            self.content = content
        # Strip quotes.. "'s
        if self.content[0] == '"':
            self.content = self.content[1:-1]

        # build payload (to avoid hex)
        self.payload = ''
        if len(self.content) > 0: 
            flag=0
            tmp = ""
            i = 0
            while i < len(self.content):
                if self.content[i]=="|" and (i>0 and self.content[i-1]!='\\' or i==0) and flag == 0:
                    flag = 1
                    i = i + 1
                    continue

                if self.content[i]=="|" and i>0 and self.content[i-1]!='\\' and flag == 1:
                    flag = 0
                    i = i + 1
                    continue

                if self.content[i]==" " and flag == 1:
                    i = i + 1
                    continue

                if flag == 1:
                    tmp = tmp + a2b_hex(self.content[i:i+2])
                    i = i + 1
                else:
                    tmp = tmp + self.content[i]
                    
                i = i + 1

            if not self.negated:
                self.payload = tmp
            else:
                for i in range(0,len(tmp)):
                    # We start changing the first char, so if the length is 1, we have no problem
                    if i % 2 == 0:
                        # We copy the payload with changed values (so it should not match)
                        if tmp[i] != ".":
                            self.payload = "."
                        else:
                            # if the character we were going to replace with a dot, was a dot, use another, so now, the payload is really different
                            self.payload = "-"
                    else:
                        self.payload = tmp[i]

        
        self.nocase = None
        self.rawbytes = None
        self.depth = None
        self.offset = None
        self.distance = None
        self.within = None
        self.http_client_body = None
        self.http_cookie = None
        self.http_header = None
        self.http_method = None
        self.http_uri = None
        self.fast_pattern = None
        self.isHTTP = False

    def __str__(self):
        r = "RuleContents:\n"
        r = r + " - content: "+ self.content
        r = r + "\n" + " - negated: "+ str(self.negated)
        r = r + "\n" + " - real payload: \n--START--\n"+ str(self.payload) + "\n--END--"
        r = r + "\n" + " - real payload length: "+ str(len(self.payload))
        r = r + "\n" + " - nocase: "+ str(self.nocase)
        r = r + "\n" + " - rawbytes: "+ str(self.rawbytes)
        r = r + "\n" + " - depth: "+ str(self.depth)
        r = r + "\n" + " - offset: "+ str(self.offset)
        r = r + "\n" + " - distance: "+ str(self.distance)
        r = r + "\n" + " - within: "+ str(self.within)
        r = r + "\n" + " - http_client_body: "+ str(self.http_client_body)
        r = r + "\n" + " - http_cookie: "+ str(self.http_cookie)
        r = r + "\n" + " - http_header: "+ str(self.http_header)
        r = r + "\n" + " - http_method: "+ str(self.http_method)
        r = r + "\n" + " - http_uri: "+ str(self.http_uri)
        #r = r + "\n" + " - dsize: "+ str(self.dsize)
        r = r + "\n" + " - fast_pattern: "+ str(self.fast_pattern) + "\n"
        
        return r
        
class RuleFlowbits:
  global dict_flowbits
  dict_flowbits= {} 
  #dictionary containing a flowbit name -> sids map
  
  global sid_to_flowbits_names_map
  sid_to_flowbits_names_map= {} 
  # dict containing sid to flowbitnames in that sid

  
  def __init__(self, flowbits_lst, sid_str):
    #self.add_flowbit_name = None
    sid_to_flowbits_names_map[sid_str] = [] 
    #containing a list of sid -> flowbitnames
    
    if flowbits_lst:
      for fl in flowbits_lst:
	if "noalert" in fl:
	  continue #skipping flowbits:noalert !!
	  #
	add_flowbit_name = fl.split(',')[1]
	
	#map all the flowbit names that exist in a sid
	sid_to_flowbits_names_map[sid_str].append(add_flowbit_name)
	  
	if add_flowbit_name in dict_flowbits:
	  dict_flowbits[add_flowbit_name] += ","+sid_str+","+(fl.split(',')[0])
	else:
	  dict_flowbits[add_flowbit_name] = sid_str+","+(fl.split(',')[0])
    else:
	del sid_to_flowbits_names_map[sid_str] 
	#since at the beginning  of the function we create an empty 
	#flowbit list for every sid_str, 
	# if none, we need to remove the sid from the sid->flowbitname map
    
       
       
   
  
  
  def __str__(self):
        r = "Rule Flowbits:\n"
        r = r + " - flowbits: "+ sid_to_flowbits_names_map[sid_str]
        return r + "\n"
  
class Flow:
    def __init__(self, flowstr):
        self.stateless = False
        self.established = False
        self.from_client = False
        self.from_server = False
        self.to_client = False
        self.to_server = False
        self.no_stream= False
        self.stream_only= False

        p = re.compile(r'((?P<stateless>stateless)|(?P<established>established))')
        m = p.search(flowstr)

        if m and m.group("stateless") != None:
            self.stateless = True

        if m and m.group("established") != None:
            self.established = True

        #p = re.compile(r'((?P<stateless>stateless)|(?P<established>established))?')
        p = re.compile(r'((?P<to_server>to_server)|(?P<to_client>to_client))')
        m = p.search(flowstr)

        if m and m.group("to_client") != None:
            self.to_client = True

        if m and m.group("to_server") != None:
            self.to_server = True

        p = re.compile(r'((?P<from_client>from_client)|(?P<from_server>from_server))')
        m = p.search(flowstr)

        if m and m.group("from_client") != None:
            self.from_client = True

        if m and m.group("from_server") != None:
            self.from_server = True

        p = re.compile(r'((?P<stream_only>stream_only)|(?P<no_stream>no_stream))')
        m = p.search(flowstr)

        if m and m.group("stream_only") != None:
            self.stream_only = True

        if m and m.group("no_stream") != None:
            self.no_stream = True

    def __str__(self):
        r = "Flow: "
        f = False
        if self.stateless:
            if f:
                r = r + ", "
            r = r + "stateless"
            f=True
        if self.established:
            if f:
                r = r + ", "
            r = r + "established"
            f=True
        if self.from_client:
            if f:
                r = r + ", "
            r = r + "from_client"
            f=True
        if self.from_server:
            if f:
                r = r + ", "
            r = r + "from_server"
            f=True
        if self.to_client:
            if f:
                r = r + ", "
            r = r + "to_client"
            f=True
        if self.to_server:
            if f:
                r = r + ", "
            r = r + "to_server"
            f=True
        if self.no_stream:
            if f:
                r = r + ", "
            r = r + "no_stream"
            f=True
        if self.stream_only:
            if f:
                r = r + ", "
            r = r + "stream_only"
            f=True
        return r + "\n"

class Rule:
    raw=''
    type=''
    proto=''
    rawsources=''
    rawsrcports=''
    direc=''
    rawdestinations=''
    rawdesports=''
    rawoptions=''
    

    # We should implement all the options as attibutes, and this list should be empty in newer versions
    options=[]

    contents=[]
    uricontents=[]
    flow=None
    flowbits=None #added for flowbits support
    msg=''
    sid =''
    dsize =''
    dsize_list=''

    def __init__(self,rule):
        #We need to flatten the rule here for pcre
        #r = RevRegex(rule)
	if rule.find("pcre") != -1:
		rule = RevRegex2.main(rule)
        #r.flatten()
        #rule = r.rule

	try:
		p = re.compile(r'^(?P<general>[^\(]+)\s*\((?P<rawoptions>.*)\)\s*$')
		m = p.search(rule)
        	general = m.group("general")
        	rawoptions = m.group("rawoptions")
	except:
		#Error parsing rule
		return
    
        if general != None and rawoptions != None:
            pg = re.compile(r'(?P<type>[^\s]+)\s+(?P<proto>[^\s]+)\s+(?P<rawsources>[^\s]+)\s+(?P<rawsrcports>[^\s]+)\s+(?P<direc>[^\s]+)\s+(?P<rawdestinations>[^\s]+)\s+(?P<rawdesports>[^\s]+)\s*')
            m = pg.search(general)

            self.type = m.group('type')
            self.proto = m.group('proto')
            self.rawsources = m.group('rawsources')
            self.rawsrcports = m.group('rawsrcports')
            self.direc = m.group('direc')
            self.rawdestinations = m.group('rawdestinations')
            self.rawdesports = m.group('rawdesports')
            self.rawoptions = rawoptions
            
            po = re.compile(r'\s*([^;]+[^\\])\s*;')
            optlist = po.findall(rawoptions) #there it is 
            self.options = []
            self.contents = []
            self.uricontents = []
            self.flow = None #set to none default
            self.flowbits = [] #set to none default
            self.isHTTP = False
            

	    #here we check if we have any sort of "content" in the rule
	    #if no content option is found - we simply put "None"
	    if not [xcon for xcon in optlist if "content:" in xcon]:
	      print "!!--no content found in the rule--!!"
	      c = RuleContent("None")
	      self.contents.append(c)

            for i in optlist:
                pi = re.compile(r'^(?P<key>[^:]+)(\s*:\s*(?P<value>.*))?\s*$')
                mi = pi.search(i)
                k = mi.group("key")
                v = mi.group("value")
                
                if v == None:
                    v = True
		
		
                if k == "flow":
                    self.flow=Flow(v)
                    continue

                # Add as attributes the options that will not be "duplicated"
                # For options that can be duplicated/repeated do a list, like self.contents
                
                if k == "sid":
                    self.sid = v
                    if self.flowbits:
		      RuleFlowbits(self.flowbits ,self.sid)
                    continue

                if k == "msg":
                    self.msg=v
                    continue

                if k == "uricontent":
                    self.isHTTP = True
                    c = RuleUriContent(v)
                    self.uricontents.append(c)
                    continue

		if k == "content":
		  c = RuleContent(v)
		  self.contents.append(c)
		  continue
		  
		if k == "flowbits":
		  self.flowbits.append(v)
		  continue
		
		if k == "dsize":
		    
		    #it is a global variable, #not content modifier
		    # - hence we get it here
		    self.dsize = v
		    #self.dsize_list = re.split(r'(\D)', self.dsize)
		    self.dsize_list = re.findall(r'\d+|\D+', self.dsize)
		    continue
		
		if k == "rawbytes":
		  continue
		
		#To Do - "tag" has to be supported the proper way - 
		#but not needed at the moment.
		if k == "tag":
		  continue
		
		if k == "reference":
		  continue
		if k == "classtype":
		  continue
		if k == "rev":
		  continue
		
		#this is to make rules with "threshold:...., count 1" ONLY 
		#pass and be made.
		#since it is only 1 count of the alert/pcap needed. 
		#count MORE than one (1) - would not be forged/made
		# TO DO - count >1
		if k == "threshold":
		  if "count 1" in v:
		    print v
		    continue
		

                # modifiers for contents
                #if len(self.contents) > 0:
                #    for clast in self.contents:
                 #       pass
                clast = ""
                if len(self.contents) > 0:
                    clast = self.contents[-1]
                else:
                    continue
                if k == "nocase":
                    clast.nocase = v
                    continue
                if k == "rawbytes":
                    clast.rawbytes = v
                    continue
                if k == "depth":
                    clast.depth = int(v)
                    continue
                if k == "offset":
                    clast.offset = int(v)
                    continue
                if k == "distance":
                    clast.distance = int(v)
                    continue
                if k == "within":
                    clast.within = int(v)
                    continue
                if k == "http_client body":
                    clast.isHTTP = True
                    clast.http_client_body = v
                    continue
                if k == "http_cookie":
                    clast.isHTTP = True
                    clast.http_cookie = v
                    continue
                if k == "http_header":
                    clast.isHTTP = True
                    clast.http_header = v
                    continue
                if k == "http_method":
                    clast.isHTTP = True
                    clast.http_method = v
                    continue
                if k == "http_uri":
                    clast.isHTTP = True
                    clast.http_uri = v
                    #print [z.content for z in self.contents ][-1] 
                    #- returns the content that http_uri keyword modifies 
                    #as a string
                    
                    #print [z.content for z in self.contents ][-1:] 
                    #- returns the content that http_uri keyword modifies 
                    #as a list
                    
                    #basically content:"BLABLA"; http_uri; 
                    #[EQUALS] uricontent:"BLABLA" !!
                    #so we need to make it uricontnet
                    http_uri_content = [z.content for z in self.contents ][-1]
                    c = RuleUriContent(http_uri_content)
                    self.uricontents.append(c)
                    
                    #then we need to delete/destroy the "content"/"payload"
                    #so that it is only the uricontent left
                    #otherwise we end up with both "content" and "uricontent"
                    for z in self.contents:
		      if z.content == http_uri_content:
			z.content = ''
			z.payload = ''
                    continue
                if k == "fast_pattern":
                    clast.fast_pattern = v
                    continue
		  
		else:
		  print "\nUnsupported keyword! Error parsing rule contents\n" +str(rule)
		  return 1
		  #break

                self.options.append([k,v])
                
                
        
        else:
            print "Error loading rule " +str(rule)
        
        

    def __str__(self):
        r = "\nGeneral Fields:\n"
        r = r + "\n" + "type: "+ self.type
        r = r + "\n" + "proto: "+ self.proto
        r = r + "\n" + "rawsources: "+ self.rawsources
        r = r + "\n" + "sports: "+ self.rawsrcports
        r = r + "\n" + "direc: "+ self.direc
        r = r + "\n" + "dests: "+ self.rawdestinations
        r = r + "\n" + "dports: "+ self.rawdesports

        r = r + "\n\nOption Fields:\n"
        r = r + "\n" + "msg: "+ self.msg
        r = r + "\n" + "sid: "+ self.sid
        
        r = r + "\n\nGlobal Variables:\n"
        r = r + "\n" + "dsize: "+ self.dsize

        if self.flow != None:
            r = r + "\n" + self.flow.__str__()

        for o in self.uricontents:
            r = r + "\n" + o.__str__() 

        for o in self.contents:
            r = r + "\n" + o.__str__()

        r = r + "\n" + "Other Options:\n"
        for o in self.options:
            r = r + o[0] +":"+ str(o[1]) + ";\n"

        r = r + "\n" + "Options in raw: "+ self.rawoptions + "\n"
        return r

