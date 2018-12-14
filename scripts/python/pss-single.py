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
PSS_BUFPFX_OK = 0
PSS_BUFPFX_ERROR = 1
PSS_BUFPFX_WARN = 2
PSS_BUFPFX_INFO = 3
PSS_BUFPFX_IN = 10
PSS_BUFPFX_OUT = 11
PSS_BUFPFX_DEBUG = 255

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
	if level == PSS_BUFPFX_DEBUG:
		pfxString = weechat.color("black,white") + "DEBUG:" + prefix
	elif level == PSS_BUFPFX_ERROR:
		pfxString = weechat.color("white,red") + prefix	
	elif level == PSS_BUFPFX_INFO:
		pfxString = weechat.color("white,blue") + prefix	
	elif level == PSS_BUFPFX_IN:
		pfxString = weechat.color("green") + prefix	
	elif level == PSS_BUFPFX_OK:
		pfxString = weechat.color("white,green") + prefix	
	elif level == PSS_BUFPFX_OUT:
		pfxString = weechat.color("yellow") + prefix	
 	elif level == PSS_BUFPFX_WARN:
		pfxString = weechat.color("black,orange") + prefix	
	else:
		return

	# write to all requested buffers
	for b in bufs:
		weechat.prnt(b, pfxString + "\t" + content)



# perform a single read from pipe
# \todo byte chunked reads, when messages arrive faster than one per loop need to reassemble individual msgs
def msgPipeRead(pssName, countLeft):

	# the received message
	msg = ""

	# data to display in nick column
	displayFrom = ""

	# holds sender key
	fromKey = ""

	# incoming fifo must be ready
	if pss[pssName].pIn == -1:	
		return weechat.WEECHAT_RC_ERROR

	# get the data	
	# \todo how to handle failure
	try:	
		msg = os.read(pss[pssName].pIn, 1024)
	except OSError as e:
		return weechat.WEECHAT_RC_OK

	# parse the stream, and build whole stanzas
	# will also detect connection events, using the last one found as the current state
	# \todo remove json handling to websocket comms background process
	processed = stream.process(msg)
	wOut(PSS_BUFPFX_DEBUG, [], "", "read: " + msg)

	# loop through all built stanzas
	for o in processed['results']:
	
		# holds content data structure 
		r = ""

		# check if data is valid	
		try:
			r = json.loads(o)
			_ = r['params']['result']
		except Exception as e:
			wOut(PSS_BUFPFX_DEBUG, [], "", "skipping invalid receive: " + o)
			return weechat.WEECHAT_RC_OK
	
		# resolve the nick if it exists
		fromKey = r['params']['result']['Key']
		if fromKey in nicks:
			displayFrom = nicks[fromKey].nick
		else:
			displayFrom = str(fromKey[2:10])

		# decode contents and display in buffer
		msgSrc = r['params']['result']['Msg'][2:].decode("hex")
		wOut(PSS_BUFPFX_IN, [pss[pssName].buf], displayFrom + " <-", msgSrc)

	# if the connection status has changed, output the appropriate notification
	if pss[pssName].inputConnected:
		if not processed['status']:
			pss[pssName].inputConnected = False
			wOut(PSS_BUFPFX_ERROR, ["", pss[pssName].buf], "0-x 0", "disconnected from '" + pssName + "'")
	else:
		if processed['status']:
			pss[pssName].inputConnected = True
			wOut(PSS_BUFPFX_OK, ["", pss[pssName].buf], "0---0", "connected to '" + pssName + "'")

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
# \todo remove direct websocket comms and get node key and addr from background process
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


	# open sockets and get initial data
	def connect(self):

		self.ws = None
		try:
			self.ws = create_connection("ws://" + weechat.config_get_plugin(self.name + "_url") + ":" + weechat.config_get_plugin(self.name + "_port"))
		except Exception as e:
			self.err = PSS_ESOCK
			self.errstr = "could not connect to pss " + self.name + " on " + weechat.config_get_plugin(self.name + "_url") + ":" + weechat.config_get_plugin(self.name + "_port")
			return False

		# get the node adress	
		self.ws.send(pss_new_call(self.seq, "baseAddr", []))
		self.seq += 1
		resp = json.loads(self.ws.recv())

		# verify address
		if not pss_is_address(resp['result']):
			self.err = PSS_EREMOTEINVAL
			self.errstr = "received bogus base address " + resp['result']
			return False
		base = resp['result']
		
		# retrieve the node key	data
		self.ws.send(pss_new_call(self.seq, "getPublicKey", []))
		self.seq += 1
		resp = json.loads(self.ws.recv())
	
		# verify key
		if not pss_is_pubkey(resp['result']):
			self.err = PSS_EREMOTEINVAL
			self.errstr = "received bogus pubkey " + resp['result']
			return False

		key = resp['result']

		# open sockets to websocket comms background process
		# we need them so fail if we don't succeed
		try:
			self.pIn = os.open(self.pInName, os.O_RDONLY | os.O_NONBLOCK)
		except OSError as e:
			wOut(PSS_BUFPFX_ERROR, [], "!!!", "Unable to open incoming FIFO for '" + self.name + "'")
			return False

		try:	
			self.pOut = os.open(self.pOutName, os.O_WRONLY)
		except OSError as e:
			wOut(PSS_BUFPFX_ERROR, [], "!!!", "Unable to open incoming FIFO for '" + self.name + "'")	
			return False

		# now we're in the clear
		# finish setting up object properties
		self.run = True
		self.key = key
		self.base = base

		# create the buffer window for the pss node
		self.buf = weechat.buffer_new("pss_" + self.name, "buf_in", self.name, "buf_close", self.name)
		weechat.buffer_set(self.buf, "title", "PSS '" + self.name + "' | node: " + weechat.config_get_plugin(self.name + "_url") + ":" + weechat.config_get_plugin(self.name + "_port") + " | key  " + self.key[2:10] + " | address " + self.base[2:10])

		# MOTD of sorts
		wOut(PSS_BUFPFX_INFO, [self.buf], "!!!", "Please note that this is not a chat room. All messages display here have been sent one-to-one.\n"
		"To send a message, first type the nick, then a space, then the message.\n"
		"For now there's on way to know if the recipient got the message. Patience, please. It's coming.\n"
		"If the script works, please tell me. If it doesn't please tell me - " + weechat.color("cyan,underline") + "https://github.com/nolash/weechat-tools\n\n"
		)

		# add all nicks in the plugin's memory nick map
		# that match the pubkey of the node to the node's recipient address book
		self.connected = True
		for c in nicks:
			if nicks[c].src == self.key:
				self.add(nicks[c].nick, nicks[c].key, nicks[c].address)

		
		return True
	


	# adds recipient to node
	def add(self, nick, pubkey, address):

		# holds the newly created contact object
		contact = None

		# brief address and key for display in buffer
		addrLabel = ""
		keyLabel = ""

		# no use if we're not connected
		if self.ws == None or not self.connected:
			self.err = PSS_ESTATE
			self.errstr = "pss " + self.name + " not connected"
			return False

		# create the contact object	
		try:
			contact = PssContact(nick, pubkey, address, self.key)
		except Exception as e:
			self.err = PSS_ELOCALINVAL
			self.errstr = "invalid input for add: " + repr(e)
			return False

		# add to node and object cache
		# \todo check success	
		self.ws.send(pss_new_call(self.seq, "setPeerPublicKey", [pubkey, topic, address]))
		self.ws.recv()
		self.seq += 1
		self.contacts[nick] = contact

		# format output 
		try:
			addrLabel = pss_label(address)
		except:
			addrLabel = "0x"

		# \todo maybe redundant check for corruption here as pubkey can't be short
		try:
			keyLabel = pss_label(pubkey)
		except:
			return False
	
		# give response to user	
		wOut(PSS_BUFPFX_INFO, [self.buf], "+++", "added '" + nick + "' to node (key: 0x" + keyLabel + ", addr: " + addrLabel + ")")
		return True



	# send message to registered recipient
	def send(self, nick, msg):

		# recipient must already be added
		if not nick in self.contacts:
			self.err = PSS_ELOCALINVAL
			self.errstr = "no such nick " + nick
			return False

		# check if we have connection
		# \todo store outgoing messages until online on temporary network loss
		if not self.connected:
			self.err = PSS_ESOCK
			self.errstr = "not connected"
			return False

		# send the message	
		os.write(self.pOut, pss_new_call(self.seq, "sendAsym", [self.contacts[nick].key, topic, "0x" + msg.encode("hex")]))
		self.seq += 1

		# give response to user
		wOut(PSS_BUFPFX_OUT, [self.buf], nick + " ->", msg)
		return True



	# retrieve last error from object
	def error(self):
		errobj = {
			"code": self.err,
			"description": self.errstr
		}
		self.err = 0
		self.errstr = ""
		return errobj



	# close down connections
	def close(self):
		self.connected = False
		self.run = False
		self.ws.close()
		os.close(self.pIn)
		os.close(self.pOut)
		os.unlink(self.pInName)
		os.unlink(self.pOutName)



# handle inputs to buffer that are not slash commands
# currently all input is handled as messages to send
# where the string before the first whitespace is taken as the nick of the recipient
# the recipient must have been previously added to the node
def buf_in(pssName, buf, inputdata):
	global nicks, pss

	# parse nick and message
	# \todo handle extra whitespace after nick
	try:
		sepIndex = inputdata.index(" ")
	except:
		wOut(PSS_BUFPFX_ERROR, [], "???", "empty message not allowed" % weechat.color("red"))
		return weechat.WEECHAT_RC_ERROR

	# check if the recipient is registered
	nick = inputdata[0:sepIndex]
	if not nick in pss[pssName].contacts:
		wOut(PSS_BUFPFX_ERROR, [], "???", "unknown contact '" % weechat.color("red") + nick + "'" ) 
		return weechat.WEECHAT_RC_ERROR

	# send message
	pss[pssName].send(nick, inputdata[sepIndex:])
	return weechat.WEECHAT_RC_OK



# when buffer is closed, node should also close down
def buf_close(pssName, buf):
	pss[pssName].close()
	return weechat.WEECHAT_RC_OK



# check validity of address 
# \todo implement
# \todo move to util package
def pss_is_address(addr):
	return True		



# check validity of key format
# \todo implement
# \todo move to util package
def pss_is_pubkey(pubkey):
	return True		



# hex excerpt for display
# \todo move to util package
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



# handle slash command inputs
def pss_handle(data, buf, args):
	global pss


	# \todo remove consecutive whitespace
	argslist = args.split(" ")


	# if the command is "new"
	# we create a new pss instance
	# \todo save server name so we can recall across sessions
	# \todo implement list command for stored pss instances
	if (argslist[0] == "new"):
		if argslist[1] in pss:
			wOut(PSS_BUFPFX_ERROR, [], "!!!", "pss " + argslist[1] + " already exists")
			return weechat.WEECHAT_RC_ERROR
		
		weechat.config_set_plugin(argslist[1] + "_url", "127.0.0.1")
		weechat.config_set_plugin(argslist[1] + "_port", "8546")
		pss[argslist[1]] = Pss(argslist[1])
		wOut(PSS_BUFPFX_OK, [], "+++", "added pss " + argslist[1])
		return weechat.WEECHAT_RC_OK


	# do not continue if we don't have a pss instance with this name
	elif not argslist[0] in pss:
		wOut(PSS_BUFPFX_ERROR, [], "!!!", "pss " + argslist[1] + " does not exist")
		return weechat.WEECHAT_RC_ERROR


	# from here we have an active pss
	# and we should have a subcommand aswell
	# first let's make the var names easily readable
	currentPssName = argslist[0]
	currentPss = pss[currentPssName]
	subCmd = argslist[1]


	# then process subcommands

	# command "set" controls config variables for the plugin	
	if (subCmd == "set"):

		# verify that the key is a valid option
		if not weechat.config_is_set_plugin(currentPssName + "_" + argslist[2]):
			wOut(PSS_BUFPFX_ERROR, [], "!!!",  "invalid option name " + argslist[2])
			return weechat.WEECHAT_RC_ERROR
	
		# verify the value is a valid option for the key
		if not pss_check_option(argslist[2], argslist[3]):
			wOut(PSS_BUFPFX_ERROR, [], "!!!", "invalid option value " + argslist[3] + " for option " + argslist[2])
			return weechat.WEECHAT_RC_ERROR

		# set it and tell user the good news
		weechat.config_set_plugin(currentPssName + "_" + argslist[2], argslist[3])
		wOut(PSS_BUFPFX_OK, [], "+++", "option " + currentPssName + "_" + argslist[2] + " set to " + argslist[3])


	# handle the connect command
	elif subCmd == "connect":

		# start the websocket comms background process
		wOut(PSS_BUFPFX_WARN, [], "0-> 0", "connecting to '" + currentPssName + "'")
		weechat.hook_process(
			"python2 " + scriptPath + "/pss-fetch.py " + currentPssName + " " + weechat.config_get_plugin(currentPssName + "_url") + " " + weechat.config_get_plugin(currentPssName + "_port") + " " + topic,
			0,
			"recvHandle",
			currentPssName
		)

		# start the sockets in the pss instance
		if not currentPss.connect():
			wOut(PSS_BUFPFX_ERROR, [], "0-x 0", "connect to '" + currentPssName + "' failed: " + currentPss.error()['description'])
			return weechat.WEECHAT_RC_ERROR

		# start reading from the incoming socket
		# if we had threads we could use select, but no such luck in weechat scripts 
		weechat.hook_timer(PSS_FIFO_POLL_DELAY, 0, 0, "msgPipeRead", currentPssName)


	# add a recipient to the address books of plugin and node
	elif subCmd == "add":
		nick = ""
		key = ""
		addr = ""

		# input sanity check
		if len(argslist) != 5:
			wOut(PSS_BUFPFX_ERROR, [], "!!!", "not enough arguments for add")
			return weechat.WEECHAT_RC_ERROR

		# legible varnames
		nick = argslist[2]
		key = argslist[3]
		addr = argslist[4]
		
		# backend add recipient call	
		if not currentPss.add(nick, key, addr):
			wOut(PSS_BUFPFX_ERROR, [], "!!!", "add contact error: " + currentPss.error()['description'])
			return weechat.WEECHAT_RC_ERROR

		# refresh the plugin memory map version of the recipient
		nicks[key] = PssContact(nick, key, addr, currentPssName)

		# append recipient to file for reinstating across sessions
		storeFile.write(nick + "\t" + key + "\t" + addr + "\t" + currentPss.key + "\n")


	# send a message to a recipient
	elif subCmd == "send":
		if len(argslist) < 4:
			wOut(PSS_BUFPFX_ERROR, [], "!!!", "not enough arguments for send")
			return weechat.WEECHAT_RC_ERROR

		if not currentPss.send(argslist[2], " ".join(argslist[3:])):
			wOut(PSS_BUFPFX_ERROR, [], "!!!", "send fail: " + currentPss.error()['description'])
			return weechat.WEECHAT_RC_ERROR


	# output node key
	elif subCmd == "key" or subCmd == "pubkey":
		wOut(PSS_BUFPFX_INFO, ["", currentPss.buf], currentPssName + ".key", currentPss.key)


	# output node base address
	elif subCmd == "addr" or subCmd == "address":
		wOut(PSS_BUFPFX_INFO, ["", currentPss.buf], currentPssName + ".addr", currentPss.base)


	# stop connection
	# \todo also kill the subprocess 
	# \todo ensure clean shutdown so conncet can be called over
	elif subCmd == "stop":
		currentPss.close()


	# invalid input
	else:
		return weechat.WEECHAT_RC_ERROR

	
	# all good
	return weechat.WEECHAT_RC_OK	



# top level teardown of plugin and thus all connections
def pss_stop():
	for name in pss:
		pss[name].close()
		wOut(PSS_BUFPFX_INFO, [], "!!!", "pss '" + name + "' websocket connection closed")

	return weechat.WEECHAT_RC_OK



# check validity of an option key
# \todo implement
def pss_check_option(name, value):
	return True



# json-rpc stanza builder
# \todo move to websocket comms layer
def pss_new_call(callid, method, args):
	return json.dumps({
		'json-rpc': '2.0',
		'id': callid,
		'method': 'pss_' + method,
		'params': args,
	})



# signal handler for load
# catches the script path used to locate other required resources
def pss_sighandler_load(data, sig, sigdata):
	global scriptPath, storeFile, nicks

	# ignore if not our load signal
	if not os.path.basename(sigdata) == "pss-single.py":
		return weechat.WEECHAT_RC_OK	

	# parse dir and check if websocket comms script is there
	# bail if it's not 
	# \todo UNLOAD plugin on fail
	scriptPath = os.path.dirname(sigdata)
	if not os.path.exists(scriptPath + "/pss-fetch.py"):
		weechat.prnt("", "retrieval daemon script not found. plugin will NOT work. please reload")
		weechat.unhook_all()
		return weechat.WEECHAT_RC_ERROR

	# read the contacts database and populate the nicks plugin memory map 
	# by applying them sequentially
	# if it can't be found, we simply skip it, but telle the user
	try:
		f = open(scriptPath + "/.pss-contacts", "r", 0600)
		while 1:
			# if there is a record
			# split fields on tab and chop newline
			record = f.readline()
			if len(record) == 0:
				break	
			(nick, key, addr, src) = record.split("\t")
			if ord(src[len(src)-1]) == 0x0a:
				src = src[:len(src)-1]

			# add it to the map and report
			nicks[key] = PssContact(nick, key, addr, src)
			wOut(PSS_BUFPFX_INFO, [], "+++", "contact loaded from db '" + nick + "' (0x" + key[2:10] + ")")

		f.close()
	except IOError as e:
		wOut(PSS_BUFPFX_WARN, [], "!!!", "could not open contact store " + scriptPath + "/.pss-contacts: " + repr(e))
	
	# open file for append (and create if not exist)
	# \todo postfix db name with username
	storeFile = open(scriptPath + "/.pss-contacts", "a", 0600)

	# debug output confirming receive signal
	wOut(PSS_BUFPFX_DEBUG, [], "", "(" + repr(sig) + ") using scriptpath " + scriptPath)

	# signal is not needed anymore now, unhook and stop it from propagating
	weechat.unhook(loadSigHook)
	return weechat.WEECHAT_RC_OK_EAT



# unload cleanly
def pss_sighandler_unload(data, sig, sigdata):
	global storeFile

	if not os.path.basename(sigdata) == "pss-single.py":
		return weechat.WEECHAT_RC_OK	

	storeFd.close()
	return weechat.WEECHAT_RC_OK_EAT



# set up hooks and commands

loadSigHook = weechat.hook_signal(
	"python_script_loaded",
	"pss_sighandler_load",
	""
)

unloadSigHook = weechat.hook_signal(
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
