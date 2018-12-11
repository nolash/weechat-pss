import weechat
import xmpp
import json
import sys
import time
import os
import fcntl
import tempfile
from websocket import create_connection

# consts
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

# all weechat scripts must run this as first function
weechat.register("pss", "lash", "0.1.3", "GPLv3", "single-node pss chat", "pss_stop", "")

# perform a single read from pipe
# \todo byte chunked reads, when messages arrive faster than one per loop need to reassemble individual msgs
def msgPipeRead(pssName, countLeft):

	msg = ""
	displayFrom = ""
	fromKey = ""
	r = ""

	if pss[pssName].pip == -1:	
		return weechat.WEECHAT_RC_ERROR

	try:	
		msg = os.read(pss[pssName].pip, 1024)
	except OSError as e:
		#weechat.prnt("", "(no read)")
		return weechat.WEECHAT_RC_OK

	try:
		r = json.loads(msg)
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
	weechat.prnt(pss[pssName].buf, displayFrom + " <-\t" + msgSrc)

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
		self.addr = addr
		self.src = src

# object encapsulating pss node connection
# \todo move to separate package
class Pss:
	connected = False
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
	pip = -1
	pipName = ""

	def __init__(self, name):
		""" set the pss instance name and create the fifo for catching msgs from subprocess
		"""
		self.name = name
		self.pipName = tempfile.gettempdir() + "/pss_weechat_" + self.name + ".fifo"
		if os.path.exists(self.pipName):
			os.unlink(self.pipName)
		self.pip = os.mkfifo(self.pipName)

	def connect(self):
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

		self.ws.send(pss_new_call(self.seq, "subscribe", ["receive", topic, False, False]))
		self.ws.recv()
		self.seq += 1

		self.run = True
		self.key = key
		self.base = base

		self.buf = weechat.buffer_new("pss_" + self.name, "buf_in", self.name, "buf_close", self.name)
		weechat.buffer_set(self.buf, "title", "PSS '" + self.name + "' | node: " + weechat.config_get_plugin(self.name + "_url") + ":" + weechat.config_get_plugin(self.name + "_port") + " | key  " + self.key[2:10] + " | address " + self.base[2:10])

		self.connected = True
		for c in nicks:
			if nicks[c].src == self.key:
				# \todo 
				weechat.prnt(self.buf, "+++\tadded '" + nicks[c].nick + "' to node (key: 0x" + self.key[2:10] + ", addr: " + self.base + ")")
				self.add(nicks[c].nick, key, self.base)
			
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
		weechat.prnt("", "added contact " + nick + ": " + pubkey + " => " + address)
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
	
		self.ws.send(pss_new_call(self.seq, "sendAsym", [self.contacts[nick].key, topic, pss_strToHex(msg)]))
		self.seq += 1

		weechat.prnt(self.buf, nick + " ->\t" + msg)
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
		os.close(self.pip)
		os.unlink(self.pipName)

def buf_in(pssName, buf, inputdata):
	weechat.prnt("", "got in buf " + pssName + ": " + inputdata)
	return weechat.WEECHAT_RC_OK

def buf_close(pssName, buf):
	weechat.prnt("", "close buf " + pssName)
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

def pss_handle(data, buf, args):
	global pss

	argslist = args.split(" ")

	if (argslist[0] == "new"):
		try:	
			_ = pss[argslist[1]]	
		except:
			weechat.prnt("", "added pss " + argslist[1])
			pss[argslist[1]] = Pss(argslist[1])
			weechat.config_set_plugin(argslist[1] + "_url", "127.0.0.1")
			weechat.config_set_plugin(argslist[1] + "_port", "8546")
			return weechat.WEECHAT_RC_OK

		weechat.prnt("", "pss " + argslist[1] + " already exists")
		return weechat.WEECHAT_RC_ERROR

	elif not argslist[0] in pss:
		#weechat.prnt("", "pss " + argslist[1] + " does not exist")
		return weechat.WEECHAT_RC_ERROR
	
	
	if (argslist[1] == "set"):
		if not weechat.config_is_set_plugin(argslist[0] + "_" + argslist[2]):
			weechat.prnt("", "invalid option name " + argslist[2])
			return weechat.WEECHAT_RC_ERROR
		if not pss_check_option(argslist[2], argslist[3]):
			weechat.prnt("", "invalid option value " + argslist[3] + " for option " + argslist[2])
			return weechat.WEECHAT_RC_ERROR
		weechat.config_set_plugin(argslist[0] + "_" + argslist[2], argslist[3])
		weechat.prnt("", "option " + argslist[0] + "_" + argslist[2] + " set to " + argslist[3])	

	elif argslist[1] == "connect":

		if not pss[argslist[0]].connect():
			weechat.prnt("", "connect failed: " + pss[argslist[0]].error()['description'])
			return weechat.WEECHAT_RC_ERROR
		# \todo find option to get the correct path	
		weechat.hook_process("python2 " + scriptPath + "/pss-fetch.py " + argslist[0] + " " + weechat.config_get_plugin(pss[argslist[0]].name + "_url") + " " + weechat.config_get_plugin(pss[argslist[0]].name + "_port") + " " + topic, 0, "recvHandle", argslist[0])
		time.sleep(1)
		pss[argslist[0]].pip = os.open("/tmp/pss_weechat_" + argslist[0] + ".fifo", os.O_RDONLY | os.O_NONBLOCK)
		weechat.hook_timer(PSS_FIFO_POLL_DELAY, 0, 0, "msgPipeRead", argslist[0])

	elif argslist[1] == "add":
		nick = ""
		key = ""
		addr = ""

		if len(argslist) != 5:
			weechat.prnt("", "not enough arguments for add")
			return weechat.WEECHAT_RC_ERROR

		nick = argslist[2]
		key = argslist[3]
		addr = argslist[4]
			
		if not pss[argslist[0]].add(nick, key, addr):
			weechat.prnt("", "add contact error: " + pss[argslist[0]].error()['description'])
			return weechat.WEECHAT_RC_ERROR

		nicks[key] = PssContact(nick, key, addr, argslist[0])
		storeFile.write(nick + "\t" + key + "\t" + addr + "\t" + pss[argslist[0]].key + "\n")

	elif argslist[1] == "send":
		if len(argslist) < 4:
			weechat.prnt("", "not enough arguments for send")
			return weechat.WEECHAT_RC_ERROR

		if not pss[argslist[0]].send(argslist[2], " ".join(argslist[3:])):
			weechat.prnt("", "send fail: " + pss[argslist[0]].error()['description'])
			return weechat.WEECHAT_RC_ERROR

	elif argslist[1] == "key" or argslist[1] == "pubkey":
		weechat.prnt("", "[" + argslist[0] + ".key] " + pss[argslist[0]].key)

	elif argslist[1] == "addr" or argslist[1] == "address":
		weechat.prnt("", "[" + argslist[0] + ".address] " + pss[argslist[0]].base)

	elif argslist[1] == "stop":
		pss[argslist[0]].close()

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
