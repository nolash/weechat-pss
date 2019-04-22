import weechat
import os
import time
import sys
import socket
import fcntl

# consts
PSS_VERSION = "0.5.0"
PSS_BUFPFX_OK = 0
PSS_BUFPFX_ERROR = 1
PSS_BUFPFX_WARN = 2
PSS_BUFPFX_INFO = 3
PSS_BUFPFX_IN = 10
PSS_BUFPFX_OUT = 11
PSS_BUFPFX_DEBUG = 255

PSS_BUFTYPE_NODE = "\x10"
PSS_BUFTYPE_ROOM = "\x01"
PSS_BUFTYPE_CHAT = "\x11"

PSS_DEFAULT_NICK = "me"

PSS_FEEDBOX_PERIOD = 1000
PSS_FEEDQUEUE_SIZE = 10
PSS_ROOM_PERIOD = PSS_FEEDBOX_PERIOD


## Represents one individual command
class ApiItem:

	def __init__(self, itemid):
		self.id = itemid
		self.err = 0
		self.header = b''
		self.data = b''
		self.datalength = 0
		self.src = b''


	def put(self, data):
		self.data += data
		self.datalength += len(data)

	
	def finalize(self, mode):
		self.header = bytearray(struct.pack(">H", self.id))
		self.header[0] |= (self.err & 0xff) << 5
		self.header.append(mode)
		self.src += self.header
		self.src += struct.pack(">I", len(self.data))
		self.src += self.data
		return self.src


## Assembles individual commands from the socket data stream
class ApiParser:


	def __init__(self):
		self.item = None


	## Process input data
	#
	# \param data input
	# \return tuple: (ApiItem, remaining data) if a complete command is parsed, (None, None) if end of command not found (or 0-length data)
	def put(self, data):
		if len(data) == 0:
			return (None, None)
		if self.item == None:
			itemid = (data[0] & 31) << 8
			itemid += data[1]
			self.item = ApiItem(itemid)
			self.remaining = struct.unpack(">I", data[3:7])[0]
			self.item.header = data[:3]
			self.item.src = data[:7]
			datalength = struct.unpack(">I", data[3:7])
			self.item.datalength = datalength[0]
			data = data[7:]

		cap = len(data)
		if cap > self.remaining:
			cap = self.remaining
		self.item.data += data[:cap]
		self.item.src += data[:cap]
		self.remaining -= cap
		if self.remaining == 0:
			item = self.item
			self.item = None 
			return (item, data[cap:])
		return (None, None)


class Client:

	def __init__(self, name, host="127.0.0.1", wsport="8546", bzzport="8500"):
		self.nick = name
		self.buf = None
		self.loop = None
		self.sock = None

		self.parser = ApiParser()




# singleton store of context information to use across hook calls
class EventContextStore:
	store = {}

	def put(self, ctx):
		k = str(id(ctx))
		self.store[k] = ctx
		return k


	def get(self, idstr):
		ctx = self.store[idstr]
		del self.store[idstr]
		return ctx



	
# context is a common object for keeping track of context of an incoming event 
class EventContext:
	
	def __init__(self):
		self.type = 0
		self.node = ""
		self.name = ""
		self.reset(0, "", "")
		self.buf = None
		self.err = ""


	def reset(self, typ, node, name):
		self.type = typ
		self.node = node
		self.name = name
		self.bufname = self.to_buffer_name()
		

	def to_buffer_name(self):
		if self.type == PSS_BUFTYPE_CHAT:
			self.bufname = "pss." + self.node + ".chat." + self.name
		elif self.type == PSS_BUFTYPE_ROOM:
			self.bufname = "pss." + self.node + ".room." + self.name
		else:
			self.bufname = "pss." + self.node

		return self.bufname


	def is_root(self):
		return self.type == 0


	def is_room(self):
		return self.type == PSS_BUFTYPE_ROOM


	def is_chat(self):
		return self.type == PSS_BUFTYPE_CHAT


	def set_name(self, name):
		self.name = name


	def set_node(self, node):
		self.node = node


	def set_pss(self, pss):
		self.pss = pss
		self.node = pss.get_name()


	def set_bzz(self, bzz):
		self.bzz = bzz


	def set_buffer(self, buf, bufname):
		self.buf = buf
		self.bufname = bufname


	def get_name(self):
		return self.name


	def get_node(self):
		return self.node


	def get_bzz(self):
		return self.bzz


	def get_pss(self):
		return self.pss


	def get_buffer(self):
		return self.buf


	def parse_buffer(self, buf):
		self.buf = buf
		self.bufname = weechat.buffer_get_string(buf, "name")

		flds = self.bufname.split(".")
#		for f in flds:
#			wOut(
#				PSS_BUFPFX_DEBUG,
#				[],
#				"",
#				"bufname parse fld: " + str(f)
#			)
		
		# all pss context nodes have pss as the first field
		if flds[0] != "pss":
			return False
		elif flds[1] == "node":
			self.type = PSS_BUFTYPE_NODE
			self.node = flds[2]
			self.name = flds[2]	
		elif flds[2] == "chat":
			self.type = PSS_BUFTYPE_CHAT
			self.node = flds[1]
			self.name = flds[3]	
		elif flds[2] == "room":
			self.type = PSS_BUFTYPE_ROOM
			self.node = flds[1]
			self.name = flds[3]	

		return True


	def __str__(self):
		return str(self.type) + "|" + self.node + "|" + self.name + "|" + repr(self.pss)


# contexts across buffer calls
#
# \todo remind why this was useful again
ctxstore = EventContextStore()

# all connection buffers
conns = {}

# all weechat scripts must run this as first function
weechat.register("pss", "lash", PSS_VERSION, "GPLv3", "single-node pss and swarm feeds chat", "pss_stop", "")

# what dir we are working in. set on load
scriptpath = ""

def handle_in(nodename, _):

	node = conns[nodename]
	fd = node.sock.fileno()
	try:
		select.select([fd], [], [], 0.05)
		(item, _) = node.parser.put(node.sock.recv(1024))
		if item != None:
			wOut(PSS_BUFPFX_DEBUG, [], ":-/", "have item: {}".item.data)

		#while leftovers != None:	
		#	(item, leftovers) = node.parser.put(node.sock.recv(1024))

	except:
		wOut(PSS_BUFPFX_DEBUG, [], ":-/", "nothing on socket")

	return weechat.WEECHAT_RC_OK
		
	
def handle_croak(data, cmd, retval, out, err):
	# we can proceed with connection in the pss instance
	wOut(
		PSS_BUFPFX_WARN,
		[data],
		"!!!",
		"server died!: " + err,
	)
	return weechat.WEECHAT_RC_OK


## handle node inputs	
# 
# /todo make both ports customizable
def pss_handle(pssName, buf, args):

	# context is only used for acvie nodes
	ctx = EventContext()

	# parse cmd input 
	# \todo remove consecutive whitespace
	argv = args.split(" ")
	argc = len(argv)

	# first we handle commands that are node independent	

	# the connect command is the same for any context
	# \todo rollback on connect fail
	if argv[0] == "connect":

		host = "127.0.0.1"
		port = "8546"
	
		if argc < 2:
			wOut(PSS_BUFPFX_ERROR, [], "!!!", "invalid command <TODO insert help text>")
		ctx.set_node(argv[1])

		if argc > 2:
			host = argv[2]	
		
		if argc > 3:
			port = argv[3]	


		if ctx.get_node() in conns:
			existingBuf = weechat.buffer_search("python", "pss.node." + ctx.get_node())
			if existingBuf != "":
				wOut(PSS_BUFPFX_DEBUG, [], "", "pss " + ctx.get_node() + " already exists, changing to that buffer")
				weechat.buffer_set(bufs[ctx.get_node()], "display", "1")
				return weechat.WEECHAT_RC_OK

			if host == "":
				host = weechat.config_get_plugin(ctx.get_node() + "_url", host)

			if port == "":
				port = weechat.config_get_plugin(ctx.get_node() + "_port", port)
	
			wOut(PSS_BUFPFX_DEBUG, [], "", "pss " + ctx.get_node() + " already exists")


		# regardless of if we have the node already, store the connection parameters for later for this node name	
		#weechat.config_set_plugin(ctx.get_node() + "_url", host)
		#weechat.config_set_plugin(ctx.get_node() + "_port", port)
	
		# if we made it here we don't have a buffer for this node already
		# so create it and merge the node buffer with core so we can do the neat ctrl-x trick
		buf = weechat.buffer_new("pss.node." + ctx.get_node(), "buf_node_in", ctx.get_node(), "buf_close", ctx.get_node())
		weechat.buffer_set(buf, "short_name", "pss."+ ctx.get_node())
		weechat.buffer_set(buf, "title", "PSS '" + ctx.get_node() + "' | not connected")
		weechat.buffer_merge(buf, weechat.buffer_search_main())
		weechat.buffer_set(buf, "display", "1")
		ctx.parse_buffer(buf)
		ctxid = ctxstore.put(ctx)

		# now that we have the buffer up we have somewhere to write output relevant to this connection
		# we can proceed with connection in the pss instance
		wOut(
			PSS_BUFPFX_WARN,
			[buf],
			"0-> 0",
			"connecting to '" + ctx.get_node() + "'"
		)

		newconn = Client(ctx.get_node())
		res = weechat.hook_process_hashtable(
			"/usr/bin/python3",
			{
				"arg1": "-s",
				"arg2": "{}/swarm_server.py".format(scriptpath),
				"arg3": scriptpath,
				"arg4": ctx.get_node()
			},
			0,
			"handle_croak",
			""
		)
		sys.stderr.write("res: " + res)
#		except 
#			wOut(PSS_BUFPFX_ERROR, [buf], "0-x 0", "connect to '" + ctx.get_node() + "' failed: " + error)
#			return weechat.WEECHAT_RC_ERROR
		
	
#		wOut(PSS_BUFPFX_OK, [buf], "0---0", "connected to '" + ctx.get_node() + "'")
#		wOut(PSS_BUFPFX_OK, [], "+++", "added pss " + ctx.get_node())

		time.sleep(0.25)		

		opentries = 10
		sockfile = "{}/bzzchat_{}.sock".format(scriptpath, ctx.get_node())
		sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		fcntl.fcntl(sock, fcntl.F_SETFL, os.O_NONBLOCK)
		while opentries > 0:
			try:	
				sock.connect(sockfile)
				wOut(PSS_BUFPFX_DEBUG, [], "!!!", "sock connect ok {}".format(sock.fileno()))
				opentries = 0
				newconn.sock = sock
				newconn.loop = weechat.hook_timer(250, 0, 0, "handle_in", ctx.get_node())
				newconn.buf = buf

				# store the connection in global connection dict	
				conns[ctx.get_node()] = newconn
				return weechat.WEECHAT_RC_OK

			except Exception as e:
				wOut(PSS_BUFPFX_DEBUG, [], "...", "socket fail on {} - {} tries left ({})".format(sockfile, opentries, e))
				opentries -= 1
				time.sleep(0.25)
			
		wOut(PSS_BUFPFX_ERROR, [], "???", "connection server failed")
		return weechat.WEECHAT_RC_ERROR


# top level teardown of plugin and thus all connections
def pss_stop():
	for c in conns.values():
		c.sock.close()
	return weechat.WEECHAT_RC_OK


# when buffer is closed, node should also close down
def buf_close(pssName, buf):
	return weechat.WEECHAT_RC_OK


###################
# SIGNAL HANDLERS
###################

# signal handler for load
# catches the script path used to locate other required resources
def pss_sighandler_load(data, sig, sigdata):
	global scriptpath

	entrycount = 0
	okcount = 0

	# ignore if not our load signal
	if not os.path.basename(sigdata) == "swarm2.py":
		return weechat.WEECHAT_RC_OK	

	scriptpath = os.path.dirname(sigdata)
	
	# signal is not needed anymore now, unhook and stop it from propagating
	weechat.unhook(loadSigHook)
	return weechat.WEECHAT_RC_OK_EAT



# unload cleanly
def pss_sighandler_unload(data, sig, sigdata):

	for s in socks:
		s.close()

	cache.close()
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
	"\n"
	"<cmd|name> [<arguments>]"
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

# writes to weechat console
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


