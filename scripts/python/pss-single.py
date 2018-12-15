import weechat
import os
import pss # plugin package, nothing official

# consts
PSS_VERSION = "0.1.10"
PSS_FIFO_POLL_DELAY = 500
PSS_BUFPFX_OK = 0
PSS_BUFPFX_ERROR = 1
PSS_BUFPFX_WARN = 2
PSS_BUFPFX_INFO = 3
PSS_BUFPFX_IN = 10
PSS_BUFPFX_OUT = 11
PSS_BUFPFX_DEBUG = 255


# pss node connections
psses = {}

# hook for ws read fd
hookFds = {}

# buffers
bufs = {}

# nick to PssContact mappings in memory
nicks = {}

# path to scripts
scriptPath = ""

# signal hook to catch path to scripts
loadSigHook = None

# file that stores all nick/key/addr
# is it append
# \todo replace with ENCRYPTED key/value store
storeFile = None

# stream processor
stream = pss.Stream()


# all weechat scripts must run this as first function
weechat.register("pss", "lash", PSS_VERSION, "GPLv3", "single-node pss chat", "pss_stop", "")

# levels:
# 1 = info
# 2 = in
# 3 = out
# 255 = debug
def wOut(level, oBufs, prefix, content):

	pfxString = ""

	if len(oBufs) == 0:
		oBufs = [""]

	# parse the level	
	#if level == 255 and weechat.config_get_plugin("debug"):
	if level == PSS_BUFPFX_DEBUG:
		pfxString = weechat.color("240") + "DEBUG:" + prefix
	elif level == PSS_BUFPFX_ERROR:
		pfxString = weechat.color("red") + prefix	
	elif level == PSS_BUFPFX_INFO:
		pfxString = weechat.color("blue") + prefix	
	elif level == PSS_BUFPFX_IN:
		pfxString = weechat.color("green") + prefix	
	elif level == PSS_BUFPFX_OK:
		pfxString = weechat.color("green") + prefix	
	elif level == PSS_BUFPFX_OUT:
		pfxString = weechat.color("yellow") + prefix	
 	elif level == PSS_BUFPFX_WARN:
		pfxString = weechat.color("3") + prefix	
	else:
		return

	# write to all requested buffers
	for b in oBufs:
		weechat.prnt(b, pfxString + "\t" + content)



# perform a single read from pipe
def msgPipeRead(pssName, fd):

	# the received message
	msg = ""

	# data to display in nick column
	displayFrom = ""

	# holds sender key
	fromKey = ""

	# on disconnect we have invalid fd(?)
	if fd < 0:
		return weechat.WEECHAT_RC_ERROR

	# get the data	
	# \todo how to handle failure
	try:	
		msg = os.read(fd, 1024)
	except OSError as e:
		return weechat.WEECHAT_RC_OK

	# parse the stream, and build whole stanzas
	# will also detect connection events, using the last one found as the current state
	# \todo remove json handling to websocket comms background process
	processed = stream.process(msg)

	# loop through all built stanzas
	for o in processed['results']:
	
		# holds content data structure 
		r = ""

		# check if data is valid	
		try:
			r = pss.rpc_parse(o)
			_ = r['params']['result']
		except Exception as e:
			wOut(PSS_BUFPFX_DEBUG, [], "", "skipping invalid receive: " + repr(o))
			return weechat.WEECHAT_RC_OK
	
		# decode contents and display in buffer
		msgSrc = r['params']['result']['Msg'][2:].decode("hex")

		# resolve the nick if it exists
		fromKey = r['params']['result']['Key']
		if fromKey in nicks:
			displayFrom = nicks[fromKey].nick
			wOut(PSS_BUFPFX_IN, [buf_get(pssName, "chat", displayFrom, True)], displayFrom, msgSrc)
		else:
			displayFrom = pss.label(fromKey, 8)
			buf = buf_get(pssName, "chat", pss.label(fromKey, 16), False)
			wOut(PSS_BUFPFX_IN, [buf], displayFrom, msgSrc)

	return weechat.WEECHAT_RC_OK



# gets the buffer matching the type and the name given
# creates if it doesn't exists
def buf_get(pssName, typ, name, known):

	# \todo integrity check of input data
	bufname = "pss." + pssName + "." + typ + "." + name

	try:
		buf = weechat.buffer_search("python", bufname)
	except Exception as e:
		return ""

	if buf == "":
		shortname = ""
		if known:
			shortname = "pss:" + name
		else:
			shortname = "pss:" + name[:8]

		buf = weechat.buffer_new(bufname, "buf_in", pssName, "buf_close", pssName)
		weechat.buffer_set(buf, "short_name", shortname)
		weechat.buffer_set(buf, "title", name + " @ PSS '" + pssName + "' | node: " + weechat.config_get_plugin(psses[pssName].host + "_url") + ":" + weechat.config_get_plugin(psses[pssName].port + "_port") + " | key  " + pss.label(psses[pssName].key) + " | address " + pss.label(psses[pssName].base))
		weechat.buffer_set(buf, "hotlist", weechat.WEECHAT_HOTLIST_PRIVATE)
		plugin = weechat.buffer_get_pointer(buf, "plugin")
		name = weechat.plugin_get_name(plugin)
		bufs[bufname] = buf

	return buf


# handle inputs to buffer that are not slash commands
# currently all input is handled as messages to send
# where the string before the first whitespace is taken as the nick of the recipient
# the recipient must have been previously added to the node
def buf_in(pssName, buf, inputdata):
	global psses

	bufname = weechat.buffer_get_string(buf, "name")
	pssName, typ, name = bufname[4:].split(".")

	# check if the recipient is registered
#	nick = inputdata[0:sepIndex]
#	if not nick in psses[pssName].contacts:
#		wOut(PSS_BUFPFX_ERROR, [], "???", "unknown contact '" % weechat.color("red") + nick + "'" ) 
#		return weechat.WEECHAT_RC_ERROR

	# send message
	# \todo move to common function for /pss send
	if psses[pssName].send(name, inputdata):
		wOut(PSS_BUFPFX_OUT, [buf], "you", inputdata)
	else:
		wOut(PSS_BUFPFX_ERROR, [buf], "!!!", "send fail: " + psses[pssName].error()['description'])

	return weechat.WEECHAT_RC_OK



# when buffer is closed, node should also close down
def buf_close(pssName, buf):
	return weechat.WEECHAT_RC_OK



# handle slash command inputs
def pss_handle(data, buf, args):
	global psses


	# \todo remove consecutive whitespace
	argslist = args.split(" ")


	# if the command is "new"
	# we create a new pss instance
	# \todo save server name so we can recall across sessions
	# \todo implement list command for stored pss instances
	if (argslist[0] == "new"):
		if argslist[1] in psses:
			weechat.window_search_with_buffer(bufs[argslist[1]])
			wOut(PSS_BUFPFX_DEBUG, [], "", "pss " + argslist[1] + " already exists")
			return weechat.WEECHAT_RC_ERROR
		
		weechat.config_set_plugin(argslist[1] + "_url", "127.0.0.1")
		weechat.config_set_plugin(argslist[1] + "_port", "8546")
		psses[argslist[1]] = pss.Pss(argslist[1])
		wOut(PSS_BUFPFX_OK, [], "+++", "added pss " + argslist[1])
		return weechat.WEECHAT_RC_OK


	# do not continue if we don't have a pss instance with this name
	elif not argslist[0] in psses:
		wOut(PSS_BUFPFX_ERROR, [], "!!!", "pss " + argslist[1] + " does not exist")
		return weechat.WEECHAT_RC_ERROR


	# from here we have an active pss
	# and we should have a subcommand aswell
	# first let's make the var names easily readable
	currentPssName = argslist[0]
	currentPss = psses[currentPssName]
	subCmd = argslist[1]


	# then process subcommands

	# command "set" controls config variables for the plugin	
	if (subCmd == "set"):

		k = argslist[2] 
		v = argslist[3]
		# verify that the key is a valid option
		if not weechat.config_is_set_plugin(currentPssName + "_" + k):
			wOut(PSS_BUFPFX_ERROR, [], "!!!",  "invalid option name " + k)
			return weechat.WEECHAT_RC_ERROR
	
		# verify the value is a valid option for the key
		if not pss_check_option(k, v):
			wOut(PSS_BUFPFX_ERROR, [], "!!!", "invalid option value " + v + " for option " + k)
			return weechat.WEECHAT_RC_ERROR

		# set it and tell user the good news
		weechat.config_set_plugin(currentPssName + "_" + k, v)
		if k == "host":
			currentPss.host = v

		if k == "port":
			currentPss.port = v 

		wOut(PSS_BUFPFX_OK, [], "+++", "option " + currentPssName + "_" + k + " set to " + v)


	# handle the connect command
	elif subCmd == "connect":

		# start the websocket comms background process
		wOut(PSS_BUFPFX_WARN, [], "0-> 0", "connecting to '" + currentPssName + "'")

		# start the sockets in the pss instance
		if not currentPss.connect():
			wOut(PSS_BUFPFX_ERROR, [], "0-x 0", "connect to '" + currentPssName + "' failed: " + currentPss.error()['description'])
			return weechat.WEECHAT_RC_ERROR

		# create the buffer window 
		# assign it to the pss node
		# weechat.buffer_new("pss_" + currentPssName, "buf_in", currentPssName, "buf_close", currentPssName)
		# weechat.buffer_set(currentPss.buf, "title", "PSS '" + currentPssName + "' | node: " + weechat.config_get_plugin(currentPssName + "_url") + ":" + weechat.config_get_plugin(currentPssName + "_port") + " | key  " + pss.label(currentPss.key) + " | address " + pss.label(currentPss.base))
		
		# MOTD of sorts
		#wOut(PSS_BUFPFX_INFO, [currentPss.buf], "!!!", "Please note that this is not a chat room. All messages display here have been sent one-to-one.\n"
		#"To send a message, first type the nick, then a space, then the message.\n"
		#"For now there's on way to know if the recipient got the message. Patience, please. It's coming.\n"
		#"If the script works, please tell me. If it doesn't please tell me - " + weechat.color("cyan,underline") + "https://github.com/nolash/weechat-tools\n\n"
		#)

		wOut(PSS_BUFPFX_OK, [], "0---0", "connected to '" + currentPssName + "'")

		# add all nicks in the plugin's memory nick map
		# that match the pubkey of the node to the node's recipient address book
		for c in nicks:
			if nicks[c].src == currentPss.key:
				if currentPss.add(nicks[c].nick, nicks[c].key, nicks[c].address):

					wOut(PSS_BUFPFX_INFO, [], "+++", "added '" + nicks[c].nick + "' to node (key: 0x" + pss.label(currentPss.key) + ", addr: " + pss.label(currentPss.base) + ")")
				else:
					wOut(PSS_BUFPFX_DEBUG, [], "", "nick " + c + " not added: " + currentPss.error()['description'])

		# process websocket io
		hookFds[currentPssName] = weechat.hook_fd(currentPss.ws.fileno(), 1, 0, 0, "msgPipeRead", currentPssName)


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
		nicks[key] = pss.PssContact(nick, key, addr, currentPssName)

		# append recipient to file for reinstating across sessions
		storeFile.write(nick + "\t" + key + "\t" + addr + "\t" + currentPss.key + "\n")

		# open the buffer if it doesn't exist
		buf_get(pssName, "chat", nick)	


	# send a message to a recipient
	elif subCmd == "send" or subCmd == "msg":

		if len(argslist) < 3:
			wOut(PSS_BUFPFX_ERROR, [], "!!!", "not enough arguments for send")
			return weechat.WEECHAT_RC_ERROR

		nick = argslist[2]
		msg = " ".join(argslist[3:])
		
		if not currentPss.is_nick(nick):
			wOut(PSS_BUFPFX_ERROR, [], "!!!", "invalid nick " + nick)
			return weechat.WEECHAT_RC_ERROR

		buf = buf_get(currentPssName, "chat", nick)

		if not pss.is_message(msg):
			wOut(PSS_BUFPFX_DEBUG, [], "", "invalid message " + msg)
			return weechat.WEECHAT_RC_ERROR

		if currentPss.send(nick, msg):
			# open the buffer if it doesn't exist
			wOut(PSS_BUFPFX_OUT, [buf], "you", msg)
		else:
			wOut(PSS_BUFPFX_ERROR, [], "!!!", "send fail: " + currentPss.error()['description'])
			return weechat.WEECHAT_RC_ERROR


	# output node key
	elif subCmd == "key" or subCmd == "pubkey":
		wOut(PSS_BUFPFX_INFO, [], currentPssName + ".key", currentPss.key)


	# output node base address
	elif subCmd == "addr" or subCmd == "address":
		wOut(PSS_BUFPFX_INFO, [], currentPssName + ".addr", currentPss.base)


	# stop connection
	# \todo also kill the subprocess 
	# \todo ensure clean shutdown so conncet can be called over
	elif subCmd == "stop":
		weechat.unhook(hookFds[currentPssName])
		wOut(PSS_BUFPFX_INFO, [], "!!!", "disconnected from " + currentPssName)
		currentPss.close()
		#del psses[currentPssName]


	# invalid input
	else:
		return weechat.WEECHAT_RC_ERROR

	
	# all good
	return weechat.WEECHAT_RC_OK	



# top level teardown of plugin and thus all connections
def pss_stop():
	for name in psses:
		psses[name].close()
		wOut(PSS_BUFPFX_INFO, [], "!!!", "pss '" + name + "' websocket connection closed")

	return weechat.WEECHAT_RC_OK



# check validity of an option key
# \todo implement
def pss_check_option(name, value):
	return True



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
			nicks[key] = pss.PssContact(nick, key, addr, src)
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
