import weechat
import xmpp
import json
import sys
import time
import thread
import os
import fcntl
from websocket import create_connection

PSS_EOK = 0
PSS_ESOCK = 1
PSS_EREMOTEINVAL = 2
PSS_ELOCALINVAL = 3

pss = {}
topic = "0xdeadbee2"

weechat.register("pss", "lash", "0.0.1", "MIT", "single-node pss chat over XMPP", "pss_stop", "")

def looop(pssName, countLeft):

	msg = ""

	if pss[pssName].pip == -1:	
		return weechat.WEECHAT_RC_ERROR

	try:	
		msg = os.read(pss[pssName].pip, 1024)
	except OSError as e:
		#weechat.prnt("", "(no read)")
		return weechat.WEECHAT_RC_OK

	r = json.loads(msg)
	msgSrc = r['params']['result']['Msg'][2:].decode("hex")
	weechat.prnt(pss[pssName].buf, msgSrc)

	return weechat.WEECHAT_RC_OK

def recvHandle(pssName, cmd, rc, out, err):
	if rc != 0:
		print "ohno: " + err
		return weechat.WEECHAT_RC_ERROR

	return weechat.WEECHAT_RC_OK

class PssContact:
	nick = ""
	key = ""
	address = ""

	def __init__(self, nick, key, addr):
		if not pss_is_pubkey(key):
			raise Exception("invalid key " + key)

		if not pss_is_address(addr):
			raise Exception("invalid address " + addr)

		self.nick = nick
		self.key = key
		self.addr = addr

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
		self.pipName = "/tmp/pss_weechat_" + self.name + ".fifo"
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
		
		weechat.prnt("", "pss addr: " + self.base)
		weechat.prnt("", "pss key: " + self.key)

		self.buf = weechat.buffer_new("pss_" + self.name, "buf_in", self.name, "buf_close", self.name)
		weechat.buffer_set(self.buf, "title", "pss - " + self.name + " (" + weechat.config_get_plugin(self.name + "_url") + ":" + weechat.config_get_plugin(self.name + "_port"))
		self.connected = True
		return True


	def add(self, nick, pubkey, address):
		contact = None
		try:
			contact = PssContact(nick, pubkey, address)
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
		if self.contacts[nick] == None:
			self.err = PSS_ELOCALINVAL
			self.errstr = "no such nick " + nick
			return False

		if not self.connected:
			self.err = PSS_ESOCK
			self.errstr = "not connected"
			return False
	
		self.ws.send(pss_new_call(self.seq, "sendAsym", [self.contacts[nick].key, topic, pss_strToHex(msg)]))
		self.seq += 1

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
		self.Run = False
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

	if (argslist[0] == "add"):
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

	elif pss[argslist[0]] == None:
		weechat.prnt("", "pss " + argslist[1] + " does not exist")
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
		weechat.hook_process("python2 /home/lash/.weechat/python/pss-fetch.py " + argslist[0] + " " + weechat.config_get_plugin(pss[argslist[0]].name + "_url") + " " + weechat.config_get_plugin(pss[argslist[0]].name + "_port") + " " + topic, 0, "recvHandle", argslist[0])
		time.sleep(1)
		pss[argslist[0]].pip = os.open("/tmp/pss_weechat_" + argslist[0] + ".fifo", os.O_RDONLY | os.O_NONBLOCK)
		weechat.hook_timer(500, 0, 0, "looop", argslist[0])
		print "timers ok"

	elif argslist[1] == "add":
		if len(argslist) != 5:
			weechat.prnt("", "not enough arguments for add")
			return weechat.WEECHAT_RC_ERROR

		if not pss[argslist[0]].add(argslist[2], argslist[3], argslist[4]):
			weechat.prnt("", "error: " + pss.error()['description'])
			return weechat.WEECHAT_RC_ERROR

	elif argslist[1] == "send":
		if len(argslist) < 4:
			weechat.prnt("", "not enough arguments for send")
			return weechat.WEECHAT_RC_ERROR

		if not pss[argslist[0]].send(argslist[2], " ".join(argslist[3:])):
			weechat.prnt("", "send fail: " + pss[argslist[0]].error()['description'])
			return weechat.WEECHAT_RC_ERROR

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
	


cmd_main = weechat.hook_command(
	"pss",
	"description of pss",
	"arg summary",
	"arg detail heading",
	"arg details"
	"arg details line two",
	"pss_handle",
	"")
