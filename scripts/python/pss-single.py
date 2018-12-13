import weechat
import xmpp
import json
import sys
import time
import os
import fcntl
import tempfile
from websocket import create_connection

# internal mods
from pss.tools import Stream

# consts
PSS_VERSION = "0.1.7"
PSS_FIFO_POLL_DELAY = 500

# error values
PSS_EOK = 0
PSS_ESTATE = 1
PSS_ESOCK = 2
PSS_EREMOTEINVAL = 3
PSS_ELOCALINVAL = 4

# pss node connections
pss = {}

# nick to PssContact mappings in memory
nicks = {}

# topic we will be using for this messenger service
topic = "0xdeadbee2"

# path to scripts
scriptPath = ""

# signal hook to catch path to scripts
loadSigHook = None

# file that stores all nick/key/addr
# is it append
# \todo replace with ENCRYPTED key/value store
storeFile = None

# stream processor
stream = Stream()


# all weechat scripts must run this as first function
weechat.register("pss", "lash", PSS_VERSION, "GPLv3", "single-node pss chat", "pss_stop", "")

# levels:
# 1 = info
# 2 = in
# 3 = out
# 255 = debug
def wOut(level, bufs, prefix, content):

	pfxString = ""

	if len(bufs) == 0:
		bufs = [""]

	# parse the level	
	#if level == 255 and weechat.config_get_plugin("debug"):
	if level == 255:
		pfxString = weechat.color("black,white") + "DEBUG:" + prefix
	elif level == 0:
		pfxString = weechat.color("red") + prefix	
	elif level == 1:
		pfxString = weechat.color("blue") + prefix	
	elif level == 2:
		pfxString = weechat.color("green") + prefix	
	elif level == 3:
		pfxString = weechat.color("yellow") + prefix	
	else:
		return

	# write to all requested buffers
	for b in bufs:
		weechat.prnt(b, pfxString + "\t" + content)



# perform a single read from pipe
# \todo byte chunked reads, when messages arrive faster than one per loop need to reassemble individual msgs
def msgPipeRead(pssName, countLeft):

	msg = ""
	displayFrom = ""
	fromKey = ""

	if pss[pssName].pIn == -1:	
		return weechat.WEECHAT_RC_ERROR

	try:	
		msg = os.read(pss[pssName].pIn, 1024)
	except OSError as e:
		#weechat.prnt("", "(no read)")
		return weechat.WEECHAT_RC_OK

	wOut(255, [""], "", "read: " + msg)
	weechat.prnt(pss[pssName].buf, msg)
	return weechat.WEECHAT_RC_OK
	processed = stream.process(msg)

	for o in processed['results']:
		r = ""
		try:
			r = json.loads(o)
		except Exception as e:
			weechat.prnt("", "skipping invalid receive: " + r)
			return weechat.WEECHAT_RC_OK

		# resolve the nick if it exists
		fromKey = r['params']['result']['Key']
		if fromKey in nicks:
			displayFrom = nicks[fromKey].nick
		else:
			displayFrom = str(fromKey[2:10])

		msgSrc = r['params']['result']['Msg'][2:].decode("hex")
		weechat.prnt(pss[pssName].buf, weechat.color("green") + displayFrom + " <-\t" + msgSrc)

	# if the connection status has changed, output the appropriate notification
	if pss[pssName].inputConnected:
		if not processed['status']:
			pss[pssName].inputConnected = False
			weechat.prnt(pss[pssName].buf, weechat.color("red") + "o-x o\t" + "disconnected from '" + pssName + "'")
			weechat.prnt("", weechat.color("red") + "o-x o\t" + "disconnected from '" + pssName + "'")
	else:
		if processed['status']:
			pss[pssName].inputConnected = True
			weechat.prnt(pss[pssName].buf, weechat.color("green") + "o===o\t" + "connected to '" + pssName + "'")
			weechat.prnt("", weechat.color("green") + "o===o\t" + "connected to '" + pssName + "'")

	return weechat.WEECHAT_RC_OK

# Executed after subprocess returns.
# \todo shut down node connection on subprocess return
def recvHandle(pssName, cmd, rc, out, err):
	if rc != 0:
		print "ohno: " + err
		return weechat.WEECHAT_RC_ERROR

	return weechat.WEECHAT_RC_OK

# object representing a single recipient
# \todo move to separate package
class PssContact:
	nick = ""
	key = ""
	address = ""
	src = ""

	def __init__(self, nick, key, addr, src):
		if not pss_is_pubkey(key):
			raise Exception("invalid key " + key)

		if not pss_is_address(addr):
			raise Exception("invalid address " + addr)

		self.nick = nick
		self.key = key
		self.address = addr
		self.src = src

# object encapsulating pss node connection
# \todo move to separate package
class Pss:
	connected = False
	inputConnected = False
	base = ""
	key = ""
	err = 0
	errstr = ""
	contacts = {}
	seq = 0
	ws = None
	name = ""
	run = False
	buf = None
	pIn = -1
	pOut = -1
	pInName = ""
	pOutName = ""

	def __init__(self, name):
		""" set the pss instance name and create the fifo for catching msgs from subprocess
		"""
		self.name = name

		# create the socket pair for the websocket process
		self.pInName = tempfile.gettempdir() + "/pss_weechat_" + self.name + "_in.fifo"
		if os.path.exists(self.pInName):
			os.unlink(self.pInName)
		os.mkfifo(self.pInName)

		self.pOutName = tempfile.gettempdir() + "/pss_weechat_" + self.name + "_out.fifo"
		if os.path.exists(self.pOutName):
			os.unlink(self.pOutName)
		os.mkfifo(self.pOutName)

		print "nammmme " + name + "  out " + self.pOutName

	def connect(self):

		self.ws = None
		try:
			self.ws = create_connection("ws://" + weechat.config_get_plugin(self.name + "_url") + ":" + weechat.config_get_plugin(self.name + "_port"))
		except Exception as e:
			self.err = PSS_ESOCK
			self.errstr = "could not connect to pss " + self.name + " on " + weechat.config_get_plugin(self.name + "_url") + ":" + weechat.config_get_plugin(self.name + "_port")
			return False
	
		self.ws.send(pss_new_call(self.seq, "baseAddr", []))
		self.seq += 1
		resp = json.loads(self.ws.recv())

		if not pss_is_address(resp['result']):
			self.err = PSS_EREMOTEINVAL
			self.errstr = "received bogus base address " + resp['result']
			return False

		base = resp['result']
			
		self.ws.send(pss_new_call(self.seq, "getPublicKey", []))
		self.seq += 1
		resp = json.loads(self.ws.recv())

		if not pss_is_pubkey(resp['result']):
			self.err = PSS_EREMOTEINVAL
			self.errstr = "received bogus pubkey " + resp['result']
			return False

		key = resp['result']

#		self.self.ws.send(pss_new_call(self.seq, "subscribe", ["receive", topic, False, False]))
#		self.self.ws.recv()
#		self.seq += 1

		self.run = True
		self.key = key
		self.base = base

		self.pIn = os.open(self.pInName, os.O_RDONLY | os.O_NONBLOCK)
		#weechat.hook_process("python2 " + scriptPath + "/pss-fetch.py " + self.name + " " + weechat.config_get_plugin(self.name + "_url") + " " + weechat.config_get_plugin(self.name + "_port") + " " + topic, 0, "recvHandle", currentPssName)
		weechat.hook_process("python2 " + scriptPath + "/pss-fetch.py " + self.name + " " + weechat.config_get_plugin(self.name + "_url") + " " + weechat.config_get_plugin(self.name + "_port") + " " + topic, 0, "recvHandle", self.name)

		# get ack from read open on the other end of outgoing pipe
		os.read(self.pIn, 1)

		self.pOut = os.open(self.pOutName, os.O_WRONLY)

		weechat.hook_timer(PSS_FIFO_POLL_DELAY, 0, 0, "msgPipeRead", self.name)

		self.buf = weechat.buffer_new("pss_" + self.name, "buf_in", self.name, "buf_close", self.name)
		weechat.buffer_set(self.buf, "title", "PSS '" + self.name + "' | node: " + weechat.config_get_plugin(self.name + "_url") + ":" + weechat.config_get_plugin(self.name + "_port") + " | key  " + self.key[2:10] + " | address " + self.base[2:10])

		self.connected = True
		for c in nicks:
			if nicks[c].src == self.key:
				self.add(nicks[c].nick, nicks[c].key, nicks[c].address)

		wOut(1, ["pss_" + self.name], "!!!", "Please note that this is not a chat room. All messages display here have been sent one-to-one.\n"
		"To send a message, first type the nick, then a space, then the message\n\n"
		)
#		weechat.prnt(self.buf, "!!!\tFor now there's on way to know if the recipient got the message. Patience, please. It's coming.")
#		weechat.prnt(self.buf, "!!!\tIf the script works, please tell me. If it doesn't please tell me - " + weechat.color("cyan,underline") + "https://github.com/nolash/weechat-tools")
		return True


	def add(self, nick, pubkey, address):
		contact = None

		if self.ws == None or not self.connected:
			self.err = PSS_ESTATE
			self.errstr = "pss " + self.name + " not connected"
			return False
	
		try:
			contact = PssContact(nick, pubkey, address, self.key)
		except Exception as e:
			self.err = PSS_ELOCALINVAL
			self.errstr = "invalid input for add: " + repr(e)
			return False
	
		# \todo check success	
		self.ws.send(pss_new_call(self.seq, "setPeerPublicKey", [pubkey, topic, address]))
		self.ws.recv()
		self.seq += 1

		self.contacts[nick] = contact
		addrLabel = ""
		keyLabel = ""

		try:
			addrLabel = pss_label(address)
		except:
			addrLabel = "0x"

		# \todo maybe redundant check for corruption here as pubkey can't be short
		try:
			keyLabel = pss_label(pubkey)
		except:
			return False
		
		weechat.prnt(self.buf, weechat.color("blue") + "+++\tadded '" + nick + "' to node (key: 0x" + keyLabel + ", addr: " + addrLabel + ")")
		return True

	def send(self, nick, msg):
		if not nick in self.contacts:
			self.err = PSS_ELOCALINVAL
			self.errstr = "no such nick " + nick
			return False

		if not self.connected:
			self.err = PSS_ESOCK
			self.errstr = "not connected"
			return False

		wOut(255, [], "", "fd in " + str(self.pIn))	
		wOut(255, [], "", "fd out " + str(self.pOut))	
		os.write(self.pOut, pss_new_call(self.seq, "sendAsym", [self.contacts[nick].key, topic, pss_strToHex(msg)]))
		#self.ws.send(pss_new_call(self.seq, "sendAsym", [self.contacts[nick].key, topic, pss_strToHex(msg)]))
		self.seq += 1

		weechat.prnt(self.buf, weechat.color("yellow") + nick + " ->\t" + msg)
		#resp = self.ws.recv()
		#weechat.prnt("", "result from send: " + resp)
		return True

	def error(self):
		errobj = {
			"code": self.err,
			"description": self.errstr
		}
		self.err = 0
		self.errstr = ""
		return errobj

	def close(self):
		self.connected = False
		self.run = False
		self.ws.close()
		os.close(self.pIn)
		os.close(self.pOut)
		os.unlink(self.pInName)
		os.unlink(self.pOutName)

def buf_in(pssName, buf, inputdata):
	global nicks, pss

	try:
		sepIndex = inputdata.index(" ")
	except:
		weechat.prnt(buf, "%s???\tempty message not allowed" % weechat.color("red"))
		return weechat.WEECHAT_RC_ERROR

	nick = inputdata[0:sepIndex]
	if not nick in pss[pssName].contacts:
		weechat.prnt(buf, "%s???\tunknown contact '" % weechat.color("red") + nick + "'" )
		return weechat.WEECHAT_RC_ERROR

	pss[pssName].send(nick, inputdata[sepIndex:])
	return weechat.WEECHAT_RC_OK

def buf_close(pssName, buf):
	pss[pssName].close()
	return weechat.WEECHAT_RC_OK

# \todo use better func
def pss_strToHex(str):
	res = ""
	for s in str:
		res += "{:02x}".format(ord(s))

	return "0x" + res

# \todo
def pss_is_address(addr):
	return True		

# \todo
def pss_is_pubkey(pubkey):
	return True		

def pss_label(hx):
	l = 10
	p = ""
	try:
		if hx[0:2] != "0x":
			raise Exception("invalid hex string")
	except:
		raise Exception("invalid hex string")

	if len(hx) < 10:
		l = len(hx)
	elif(hx) > 10:
		p = "..."

	return hx[0:l] + p

def pss_handle(data, buf, args):
	global pss

	# \todo remove consecutive
	argslist = args.split(" ")

	# create a new pss instance
	if (argslist[0] == "new"):
		if argslist[1] in pss:
			weechat.prnt("", "pss " + argslist[1] + " already exists")
			return weechat.WEECHAT_RC_ERROR
		
		weechat.prnt("", "added pss " + argslist[1])
		pss[argslist[1]] = Pss(argslist[1])
		weechat.config_set_plugin(argslist[1] + "_url", "127.0.0.1")
		weechat.config_set_plugin(argslist[1] + "_port", "8546")
		return weechat.WEECHAT_RC_OK

	# do not continue if we don't have a pss instance with this name
	elif not argslist[0] in pss:
		weechat.prnt("", "pss " + argslist[1] + " does not exist")
		return weechat.WEECHAT_RC_ERROR



	# readable var names
	currentPssName = argslist[0]
	currentPss = pss[currentPssName]
	subCmd = argslist[1]



	# command "set" controls config variables for the plugin	
	if (subCmd == "set"):
		if not weechat.config_is_set_plugin(currentPssName + "_" + argslist[2]):
			weechat.prnt("", "invalid option name " + argslist[2])
			return weechat.WEECHAT_RC_ERROR
		if not pss_check_option(argslist[2], argslist[3]):
			weechat.prnt("", "invalid option value " + argslist[3] + " for option " + argslist[2])
			return weechat.WEECHAT_RC_ERROR
		weechat.config_set_plugin(currentPssName + "_" + argslist[2], argslist[3])
		weechat.prnt("", "option " + currentPssName + "_" + argslist[2] + " set to " + argslist[3])	



	# handle the connect command
	elif subCmd == "connect":

		wOut(2, [], "0-> 0", "connecting to '" + currentPssName + "'")
		if not currentPss.connect():
			wOut(0, [], "0-x 0", "connect to '" + currentPssName + "' failed: " + currentPss.error()['description'])
			return weechat.WEECHAT_RC_ERROR


	# add a recipient to the address books of plugin and node
	elif subCmd == "add":
		nick = ""
		key = ""
		addr = ""

		if len(argslist) != 5:
			weechat.prnt("", "not enough arguments for add")
			return weechat.WEECHAT_RC_ERROR

		nick = argslist[2]
		key = argslist[3]
		addr = argslist[4]
			
		if not currentPss.add(nick, key, addr):
			weechat.prnt("", "add contact error: " + currentPss.error()['description'])
			return weechat.WEECHAT_RC_ERROR

		nicks[key] = PssContact(nick, key, addr, currentPssName)
		storeFile.write(nick + "\t" + key + "\t" + addr + "\t" + currentPss.key + "\n")

	elif subCmd == "send":
		if len(argslist) < 4:
			weechat.prnt("", "not enough arguments for send")
			return weechat.WEECHAT_RC_ERROR

		if not currentPss.send(argslist[2], " ".join(argslist[3:])):
			weechat.prnt("", "send fail: " + currentPss.error()['description'])
			return weechat.WEECHAT_RC_ERROR

	elif subCmd == "key" or subCmd == "pubkey":
		weechat.prnt("", "[" + currentPssName + ".key] " + currentPss.key)

	elif subCmd == "addr" or subCmd == "address":
		weechat.prnt("", "[" + currentPssName + ".address] " + currentPss.base)

	elif subCmd == "stop":
		currentPss.close()

	else:
		return weechat.WEECHAT_RC_ERROR

	return weechat.WEECHAT_RC_OK	

	
def pss_stop():
	for name in pss:
		pss[name].close()
		weechat.prnt("", "pss '" + name + "' websocket connection closed")

	return weechat.WEECHAT_RC_OK

def pss_check_option(name, value):
	return True

def pss_new_call(callid, method, args):
	return json.dumps({
		'json-rpc': '2.0',
		'id': callid,
		'method': 'pss_' + method,
		'params': args,
	})

# signal handlers
def pss_sighandler_load(data, sig, sigdata):
	global scriptPath, storeFile, nicks

	if not os.path.basename(sigdata) == "pss-single.py":
		return weechat.WEECHAT_RC_OK	

	scriptPath = os.path.dirname(sigdata)
	if not os.path.exists(scriptPath + "/pss-fetch.py"):
		weechat.prnt("", "retrieval daemon script not found. plugin will NOT work. please reload")
		weechat.unhook_all()
		return weechat.WEECHAT_RC_ERROR

	# load all existing contacts to nicks mapping
	try:
		f = open(scriptPath + "/.pss-contacts", "r", 0600)
		while 1:
			record = f.readline()
			if len(record) == 0:
				break	
			(nick, key, addr, src) = record.split("\t")
			# chop newline
			if ord(src[len(src)-1]) == 0x0a:
				src = src[:len(src)-1]
			nicks[key] = PssContact(nick, key, addr, src)
			weechat.prnt("", "contact added '" + nick + "' (0x" + key[2:10] + ")")

		f.close()
	except IOError as e:
		weechat.prnt("", "could not open contact store " + scriptPath + "/.pss-contacts: " + repr(e))
		pass
		
	storeFile = open(scriptPath + "/.pss-contacts", "a", 0600)

	# debug output confirming receive signal
	weechat.prnt("", "(" + repr(sig) + ") using scriptpath " + scriptPath)
	weechat.unhook(loadSigHook)
	return weechat.WEECHAT_RC_OK_EAT

# unload cleanly
def pss_sighandler_unload(data, sig, sigdata):
	global storeFile

	if not os.path.basename(sigdata) == "pss-single.py":
		return weechat.WEECHAT_RC_OK	

	storeFd.close()
	return weechat.WEECHAT_RC_OK_EAT

loadSigHook = weechat.hook_signal(
	"python_script_loaded",
	"pss_sighandler_load",
	""
)


weechat.hook_signal(
	"python_script_unloaded",
	"pss_sighandler_unload",
	""
)

cmd_main = weechat.hook_command(
	"pss",
	"connect to pss node and manage local contact list",
	"<cmd|name> [<arguments>]",
	"            new: add new pss instance\n"
	" <name>     set: set option for pss connection (see below)\n"
	" <name> connect: connect to node\n"
	" <name>     add: add public key and address pair to node and nick map\n"
	" <name>    stop: disconnect from node\n"
	" <name>     key: display public key\n"
	" <name>    addr: display overlay address\n"
	"\n"
	"Valid options:\n"
	"\n"
	"\thost: hostname of node\n"
	"\tport: port of node\n"
	"\n",
	"what is this then?",
	"pss_handle",
	"")
