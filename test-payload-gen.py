from Parser.RuleParser import *
from Generator.Payload import *

testrule='alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET TROJAN \"Generic Dropper Post (FarmTime? var)"; flow:stateless,to_server; content:"POST "; depth:5; uricontent:!"mod="; uricontent:"&act="; content:"|0d 0a 0d 0a|farmTime="; content:"&ownerId="; distance:10; content:"&farmKey"; distance:0; classtype:trojan-activity; rev:1;) '

print "Parsing rule " +testrule
r= Rule(testrule)
print r

# Here we pass all the contents but later we will pass all the rule (so we can process uricontents, and pcres too
ContentGen = PayloadGenerator(r.contents)
ContentGen.build()
ContentGen.hexPrint()
ContentGen.asciiPrint()
ContentGen.PrintOffsets()
# ContentGen.payload <-
