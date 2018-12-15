import weechat
import os
import pss # plugin package, nothing official

# consts
PSS_VERSION = "0.1.11"
PSS_FIFO_POLL_DELAY = 500
PSS_BUFPFX_OK = 0
PSS_BUFPFX_ERROR = 1
PSS_BUFPFX_WARN = 2
PSS_BUFPFX_INFO = 3
PSS_BUFPFX_IN = 10
PSS_BUFPFX_OUT = 11
PSS_BUFPFX_DEBUG = 255

PSS_BUFTYPE_NODE = 1
PSS_BUFTYPE_DM = 2
PSS_BUFTYPE_CHAT = 3

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
# \todo move this to a method of Pss object, so we can evaluate rpc replies to commands (such as setPeerPublicKey
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
			wOut(PSS_BUFPFX_DEBUG, [bufs[pssName]], "", "skipping invalid receive: " + repr(o))
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
	if psses[pssName].send(name, inputdata):
		wOut(PSS_BUFPFX_OUT, [buf], "you", inputdata)
	else:
		wOut(PSS_BUFPFX_ERROR, [buf[pssName]], "!!!", "send fail: " + psses[pssName].error()['description'])

	return weechat.WEECHAT_RC_OK



# when buffer is closed, node should also close down
def buf_close(pssName, buf):

	return weechat.WEECHAT_RC_OK


# node buffer close
def buf_node_close(pssName, buf):
	wOut(PSS_BUFPFX_DEBUG, [buf], "", "(noop node buf close)")
	return weechat.WEECHAT_RC_OK


# given a buffer, returns dict describing which context this buffer represents
def buf_get_context(buf):
	r = {
		"t": 0, # type
		"n": "", # node
		"h": "", # remote handle
	}
	bufname = weechat.buffer_get_string(buf, "name")
	flds = bufname.split(".")

	#for f in flds:
	#	wOut(PSS_BUFPFX_DEBUG, [], "", "bufname parse fld: " + str(f))
	
	# all pss context nodes have pss as the first field
	if flds[0] != "pss":
		return r

	elif flds[1] == "node":
		r['t'] = PSS_BUFTYPE_NODE,
		r['n'] = flds[2]

	return r

# handle slash command inputs
def pss_handle(data, buf, args):
	return buf_node_in(data, buf, args)


# handle node inputs	
def buf_node_in(pssName, buf, args):

	global psses

	ctx = {}
	currentPss = None
	argv = ""
	argc = 0

	# parse cmd input 
	# \todo remove consecutive whitespace
	argv = args.split(" ")
	argc = len(argv)

	# wOut(PSS_BUFPFX_DEBUG, [], "", "buffer " + pssName + " bufname " + weechat.buffer_get_string(buf, "name"))

	# first we handle commands that are node independent	

	# the connect command is the same for any context
	if argv[0] == "connect":

		host = ""
		port = ""
		pssName = "" 
	
		if argc < 2:
			wOut(PSS_BUFPFX_ERROR, [], "!!!", "invalid command <TODO insert help text>")
		pssName = argv[1]

		if argc > 2:
			host = argv[2]	
		
		if argc > 3:
			port = argv[3]	
			
		if pssName in psses:
			existingBuf = weechat.buffer_search("python", "pss.node." + pssName)
			if existingBuf != "":
				wOut(PSS_BUFPFX_DEBUG, [], "", "pss " + pssName + " already exists, changing to that buffer")
				weechat.buffer_set(bufs[pssName], "display", 1)
				return weechat.WEECHAT_RC_OK

			if host == "":
				host = weechat.config_get_plugin(pssName + "_url", host)

			if port == "":
				port = weechat.config_get_plugin(pssName + "_port", port)
	
			wOut(PSS_BUFPFX_DEBUG, [], "", "pss " + target + " already exists")
		else:
			psses[pssName] = pss.Pss(pssName)
			wOut(PSS_BUFPFX_OK, [], "+++", "added pss " + pssName)


		# regardless of if we have the node already, store the connection parameters for later for this node name	
		weechat.config_set_plugin(pssName + "_url", host)
		weechat.config_set_plugin(pssName + "_port", port)

	
		# if we made it here we don't have a buffer for this node already
		# so create it and merge the node buffer with core so we can do the neat ctrl-x trick
		bufs[pssName] = weechat.buffer_new("pss.node." + pssName, "buf_node_in", pssName, "buf_node_close", pssName)
		weechat.buffer_set(bufs[pssName], "short_name", "pss."+ pssName)
		weechat.buffer_set(bufs[pssName], "title", "PSS '" + pssName + "' | not connected")
		weechat.buffer_merge(bufs[pssName], weechat.buffer_search_main())
		weechat.buffer_set(bufs[pssName], "display", "1")


		# now that we have the buffer up we have somewhere to write output relevant to this connection
		# we can proceed with connection in the pss instance
		wOut(PSS_BUFPFX_WARN, [bufs[pssName]], "0-> 0", "connecting to '" + pssName + "'")
		if not psses[pssName].connect():
			wOut(PSS_BUFPFX_ERROR, [bufs[pssName]], "0-x 0", "connect to '" + pssName + "' failed: " + psses[targetbode].error()['description'])
			return weechat.WEECHAT_RC_ERROR
		wOut(PSS_BUFPFX_OK, [bufs[pssName]], "0---0", "connected to '" + pssName + "'")

		
		# provided the connection went ok
		# add all nicks in the plugin's memory nick map
		# that match the pubkey of the node to the node's recipient address book
		for c in nicks:
			if nicks[c].src == psses[pssName].key:
				if psses[pssName].add(nicks[c].nick, nicks[c].key, nicks[c].address):
					wOut(PSS_BUFPFX_INFO, [bufs[pssName]], "+++", "added '" + nicks[c].nick + "' to node (key: " + pss.label(psses[pssName].key) + ", addr: " + pss.label(psses[pssName].base) + ")")
				else:
					wOut(PSS_BUFPFX_DEBUG, [bufs[pssName]], "", "nick " + c + " not added: " + psses[pssName].error()['description'])


		# start processing inputs on the websocket
		hookFds[pssName] = weechat.hook_fd(psses[pssName].get_fd(), 1, 0, 0, "msgPipeRead", pssName)
		return weechat.WEECHAT_RC_OK

	# get the context we're getting the command in
	# if we are not in pss context, 
	# the we assume that the first argument is the name of the node
	# /pss oc add someone key addr
	# becomes
	# /pss add someone key addr
	# and "oc" is set to pssName
	# \todo consider exception for connect-command
	ctx = buf_get_context(buf)
	wOut(PSS_BUFPFX_DEBUG, [], "", "ctx: " + repr(ctx['t']) + " n " + ctx['n'])
	if ctx['t'] == 0:
		if  argv[0] != "connect":
			pssName = argv[0]
			argv = argv[1:]
			argc -= 1
	else:
		pssName = ctx['n']

	# see if we already have this node registered
	if not pssName in psses:
		wOut(PSS_BUFPFX_ERROR, [], "!!!", "unknown pss connection '" + pssName + "'")
		return weechat.WEECHAT_RC_ERROR
	currentPss = psses[pssName]


	# add a recipient to the address books of plugin and node
	# \todo currently overwritten if same pubkey and different addr, should be possible to have both, maybe even one-shots special command with dark address where entry is deleted after message sent!!!
	if argv[0] == "add":

		nick = ""
		key = ""
		addr = ""

		# input sanity check
		if argc < 3:
			wOut(PSS_BUFPFX_ERROR, [bufs[currentPssName]], "!!!", "not enough arguments for add <TODO: help output>")
			return weechat.WEECHAT_RC_ERROR

		# puny human varnames
		nick = argv[1]
		key = argv[2]
		if argc == 4:
			addr = argv[3]
		else:
			addr = "0x"
		
		# backend add recipient call	
		if not currentPss.add(nick, key, addr):
			wOut(PSS_BUFPFX_ERROR, [bufs[pssName]], "!!!", "add contact error: " + currentPss.error()['description'])
			return weechat.WEECHAT_RC_ERROR

		# refresh the plugin memory map version of the recipient
		nicks[key] = currentPss.get_contact(nick)

		# append recipient to file for reinstating across sessions
		storeFile.write(nick + "\t" + key + "\t" + addr + "\t" + currentPss.key + "\n")

		# open the buffer if it doesn't exist
		buf_get(pssName, "chat", nick, True)	

		wOut(PSS_BUFPFX_INFO, [bufs[pssName]], "!!!", "added contact '" + nicks[key].nick + "' to '" + pssName + "' (key: " + pss.label(key) + ", addr: " + pss.label(addr) + ")")


	# send a message to a recipient
	elif argv[0] == "send" or argv[0] == "msg":

		if len(argv) < 3:
			wOut(PSS_BUFPFX_ERROR, [bufs[pssName]], "!!!", "not enough arguments for send")
			return weechat.WEECHAT_RC_ERROR

		nick = argv[1]
		msg = " ".join(argv[2:])
	
		# \todo handle hex address only	
		if not currentPss.have_nick(nick):
			wOut(PSS_BUFPFX_ERROR, [bufs[pssName]], "!!!", "invalid nick " + nick)
			return weechat.WEECHAT_RC_ERROR

		buf = buf_get(pssName, "chat", nick, True)
		# \todo remove the bufs dict, since we can use weechat method for getting it
		bufs[weechat.buffer_get_string(buf, "name")] = buf

		if not pss.is_message(msg):
			wOut(PSS_BUFPFX_DEBUG, [bufs[pssName]], "", "invalid message " + msg)
			return weechat.WEECHAT_RC_ERROR

		return buf_in(pssName, buf, msg)

	# output node key
	elif argv[0] == "key" or argv[0] == "pubkey":
		wOut(PSS_BUFPFX_INFO, [bufs[pssName]], pssName + ".key", currentPss.key)


	# output node base address
	elif argv[0] == "addr" or argv[0] == "address":
		wOut(PSS_BUFPFX_INFO, [bufs[pssName]], pssName + ".addr", currentPss.base)


	# stop connection
	# \todo also kill the subprocess 
	# \todo ensure clean shutdown so conncet can be called over
	elif argv[0] == "stop":
		weechat.unhook(hookFds[pssName])
		wOut(PSS_BUFPFX_INFO, [bufs[pssName]], "!!!", "disconnected from " + pssName)
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
			try: 
				nicks[key] = pss.PssContact(nick, key, addr, src)
			# \todo delete the record from the contact store
			except:
				wOut(PSS_BUFPFX_ERROR, [], "!!!", "stored contact '" + nick + "' has invalid data, skipping")
				continue

			wOut(PSS_BUFPFX_INFO, [], "+++", "pss contact loaded from db '" + nick + "' (0x" + key[2:10] + ")")

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

	storeFile.close()
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
	"THIS HELP OUTPUT IS STALE AND INSUFFICENT. LOOK AT THE README INSTEAD",
	"\n",
	"<cmd|name> [<arguments>]",
	" <name> connect: connect to node\n"
	" <name>     add: add new contact\n"
	" <name>     msg: send message to contact\n"
	" <name>    stop: disconnect from node\n"
	" <name>     key: display public key\n"
	" <name>    addr: display overlay address\n"
	"\n",
	"(if this displays anywhere please tell me)",
	"pss_handle",
	"")
