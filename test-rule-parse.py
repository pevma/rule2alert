from Parser.RuleParser import *

testrule='alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET TROJAN \"Generic Dropper Post (FarmTime? var)"; flow:stateless,to_server; content:"POST "; depth:5; uricontent:"mod="; uricontent:"&act="; content:"|0d 0a 0d 0a|farmTime="; content:"&ownerId="; distance:0; content:"&farmKey"; distance:0; classtype:trojan-activity; sid:2010451; ftpbounce; rev:1;)'

r = Rule(testrule)

'''
print r.flow
print r.rawdestinations
print r.rawdesports
print r.rawsources
print r.rawsrcports

for c in r.contents:
    print c
'''

print r
