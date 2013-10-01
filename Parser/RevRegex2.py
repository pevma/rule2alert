'''
Created on Oct 26, 2009

@author: martin
'''
from compiler.pycodegen import TRY_FINALLY
import sys,traceback
import sre_parse
from sre_constants import *
import re
import _sre

_LITERAL_CODES = set([LITERAL, NOT_LITERAL])
_REPEATING_CODES = set([REPEAT, MIN_REPEAT, MAX_REPEAT])
_SUCCESS_CODES = set([SUCCESS, FAILURE])
_ASSERT_CODES = set([ASSERT, ASSERT_NOT])

lookuptable = {
	CATEGORY_DIGIT : 48, # '0' char
	CATEGORY_NOT_DIGIT: 65, # 'A' char
	CATEGORY_SPACE : 32, # space
	CATEGORY_NOT_SPACE: 65, # 'A' char
	CATEGORY_WORD: 65, # 'A' char
	CATEGORY_NOT_WORD: 33, # ! char
	CATEGORY_LINEBREAK:12, # linebreak
	CATEGORY_NOT_LINEBREAK: 65, # 'A' char
	CATEGORY_LOC_WORD: 65, # 'A' char
	CATEGORY_LOC_NOT_WORD: 33, # ! char
	CATEGORY_UNI_DIGIT : 48, # '0' char
	CATEGORY_UNI_NOT_DIGIT: 65, # 'A' char
	CATEGORY_UNI_SPACE : 32, # space
	CATEGORY_UNI_NOT_SPACE: 65, # 'A' char
	CATEGORY_UNI_WORD: 65, # 'A' char
	CATEGORY_UNI_NOT_WORD: 33, # ! char
	CATEGORY_UNI_LINEBREAK:12, # linebreak
	CATEGORY_UNI_NOT_LINEBREAK: 65 # 'A' char
			 }


class OutputContainer:
	def __init__(self):
		self._repeat = 1
		self._outputchars = []
	
	def getChars(self):
		return self._outputchars
	
	def append(self, _obj):
#		print "APPEND: %s" % _obj
		#Are we dealing with another outputcontainer?
		if hasattr(_obj, "getChars"):
#			print "Adding char %s %s times" % (_obj, self._repeat)
			chars = _obj.getChars()
			while(self._repeat > 0):
				self._outputchars.extend(chars)
				self._repeat = self._repeat - 1
		else:	
	#		print "Adding char %s %s times" % (_obj, self._repeat)
			while(self._repeat > 0):
			#Otherwise, just a char
				self._outputchars.append(_obj)
				self._repeat = self._repeat - 1
			
		self._repeat = 1
	def out(self, arg):
		pass
#		print "debug %s" % arg
	def repeat(self, arg):
		self._repeat = arg
	def toPythonDeclaration(self):
		str = "["
		for char in self._outputchars:
			str += "%s," % char
#			if char > 31 and char < 127:
#				str += chr(char)
#			else :
#				str += "\\x%s" % hex(char)
		str += "]"
		return str
	
	def __str__(self):
		str = ""
		for char in self._outputchars:
			str += chr(char)
		return str

def dbg(arg):
	pass
	#print "debug: %s" % arg
def getNot(arg):
	for char in range(255):
		for notchar in arg:
				if char not in arg: return char
	
def _simple(av):
	# check if av is a "simple" operator
	lo, hi = av[2].getwidth()
	if lo == 0 and hi == MAXREPEAT:
		raise error, "nothing to repeat"
	return lo == hi == 1 and av[2][0][0] != SUBPATTERN

def _reverse_in(inspecifier):
	out = OutputContainer()
	#print "IN: %s" % inspecifier
	invert = None
	for op, av in inspecifier:
		if op is NEGATE:
			#print "NOT"
			invert = []
		elif op is LITERAL:
			if invert is not None:
				invert.append(av)   
			else:
				out.append(av)
				break
		elif op is RANGE:
			if invert is not None:
				invert.append(av[0])   
			else:
				out.append(av[0])
				break
		elif op is CATEGORY:
			if invert is not None:
				invert.append(lookuptable[av])   
			else:
				out.append(lookuptable[av])
				break
		else:
			raise error, "internal: unsupported set operator"
	if invert is not None:
		#print "Not: %s" % invert
		valid = getNot(invert)
		#print "GetNot: %s" % valid
		out.append(valid)
			
	return out
def reverse(pattern):
	dbg(pattern)
	LITERAL_CODES = _LITERAL_CODES
	REPEATING_CODES = _REPEATING_CODES
	SUCCESS_CODES = _SUCCESS_CODES
	ASSERT_CODES = _ASSERT_CODES
	flags = 0
	out = OutputContainer()
	emit = out.out
	for op, av in pattern:
		if op is LITERAL:
			out.append(av)
		elif op is NOT_LITERAL:
			out.append(getNot([av]))
		elif op is IN:
			out.append(_reverse_in(av))
		elif op is ANY:
			out.append(lookuptable[CATEGORY_DIGIT])
		elif op in REPEATING_CODES:
			dbg("REPEATING_CODES")
			if flags & SRE_FLAG_TEMPLATE:
				raise error, "internal: unsupported template operator"
			elif _simple(av) and op is not REPEAT:
				out.repeat(av[0])
				subpattern = reverse(av[2])
				out.append(subpattern)
			else:
				print "NOT IMPL not _simple(av) in REPEATING CODES"
		elif op is SUBPATTERN:
			if av[0]:
				subpattern = reverse(av[1])
				out.append(subpattern)
		elif op in SUCCESS_CODES:
			emit(OPCODES[op])
		
		elif op is CALL:
			print "NOT IMPL CALL"
			dbg("op is CALL")
		elif op is AT:
			pass
		elif op is BRANCH:
			dbg("op is BRANCH")
			subpattern = reverse(av[1][0])
			out.append(subpattern)
		elif op is CATEGORY:
			print "op is CATEGORY"
			emit(lookuptable[av])
		elif op is GROUPREF:
			print "NOT IMPL Groupref"
			dbg("op is GROUPREF")
		elif op is GROUPREF_EXISTS:
			print "NOT IMPL Groupref exists"
			dbg("op is GROUPREF_EXISTS")
		else:
			raise ValueError, ("unsupported operand type", op)
	return out


def doReversing(p):
#	p = 'ab*de.gh+i{10}'
#	p = re.compile()
	dbg("Pattern:" + p)
	pattern = sre_parse.parse(p, 0) 
	out = reverse(pattern)
	return out

def main(rule):
	pcres = re.findall('pcre:\s*"(.*?)";',rule)
	uri = False
	out = ''
	for pcre in pcres:
		if not (pcre.startswith('/') or pcre.startswith('m/')): return None
		goodFormat = re.search('^m?\/(.*)\/([UGBmsiR]*$)',pcre)
		if not goodFormat: return None

		tmp = goodFormat.group(1)
		print tmp
		options = goodFormat.group(2)
		if options.find("U") != -1: uri = True

		result = str(doReversing(tmp))
		if uri:
			res = re.sub(' ','%20',result)
			out = 'uricontent:"%s";' % res
			print out
		else:
			out = 'content:"%s";' % result
			print out
		if out:
			start = rule.find("pcre:")
			end = start + rule[start:].find('";') + 2
			rule = rule[:start] + out + rule[end:]
			out = ''

		return rule
