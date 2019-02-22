# \todo WIP consistent representation of pubkeys in objects (65 bytes, binary)

import weechat
import os
import sys
import pss # plugin package, nothing official

# consts
PSS_VERSION = "0.4.0"
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

# cache handles in-memory representations
# of contacts, feeds, rooms and swarm nodes
cache = None

# hook for ws read fd
hookFds = {}

# hook for swarm gateway socket
hookSocks = []

# hook for feed queue processing timers
hookTimers = []

# feed outbox
# 32 is a reasonable buffer as we're talking about human input frequency
# and flush every second
feedOutQueue = pss.Queue(PSS_FEEDQUEUE_SIZE)

# buffers
# \todo deprecate this global, always use EventContext instead
bufs = {}

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


# FeedUpdate encapsulates a single update to be sent on the network
class FeedUpdate:

	def __init__(self, ctx, data):
		self.ctx = ctx
		self.data = data



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


ctxstore = EventContextStore()

	
# context is a common object for keeping track of context of an incoming event 
class EventContext:
	
	def __init__(self):
		self.type = 0
		self.node = ""
		self.name = ""
		self.reset(0, "", "")
		self.pss = None
		self.bzz = None
		self.buf = None


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
		for f in flds:
			wOut(
				PSS_BUFPFX_DEBUG,
				[],
				"",
				"bufname parse fld: " + str(f)
			)
		
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


###########################
# PLUGIN REQUISITES
###########################

# top level teardown of plugin and thus all connections
def pss_stop():
	return weechat.WEECHAT_RC_OK


# all weechat scripts must run this as first function
weechat.register("pss", "lash", PSS_VERSION, "GPLv3", "single-node pss and swarm feeds chat", "pss_stop", "")


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




##########################
# SOCKET IO
##########################

# \todo remove unsuccessful hooks
def pss_connect(ctxid, status, tlsrc, sock, error, ip):

	ctx = ctxstore.get(ctxid)

	if status != weechat.WEECHAT_HOOK_CONNECT_OK:
		wOut(PSS_BUFPFX_ERROR, [], "???", "swarm gateway connect failed (" + str(status) + "): " + error )
		return weechat.WEECHAT_RC_ERROR

	wOut(
		PSS_BUFPFX_INFO,
		[],
		"!!!",
		"swarm gateway connected on " + ctx.get_name() + ", sock " + repr(sock)
	)
	agent = pss.Agent(ctx.get_pss().get_host(), 8500, sock)

	bzz = pss.Bzz(agent)
	cache.add_bzz(bzz, ctx.get_name())
	ctx.set_bzz(bzz)

	# provided the connection went ok
	# add all nicks in the plugin's memory nick map
	# that match the pubkey of the node to the node's recipient address book
	savedcontacts = []
	try:
		savedcontacts = cache.update_node(ctx.get_node())
	# if it fails it just means we have no saved entries for that node
	except: 
		pass

	for c in savedcontacts:
		wOut(
			PSS_BUFPFX_INFO,
			[ctx.get_buffer()],
			"+++",
			"added cached contact '" + c.get_nick() + "' to node '" + ctx.get_node() + "'"
		)

	return weechat.WEECHAT_RC_OK


_tmp_chat_queue_hash = {}
_tmp_room_queue_hash = {}
_tmp_room_dirty = False

# handles all outgoing feed sends
# \todo run in separate process with ipc
# \todo provide and use proper accessors for chats and rooms
def processFeedOutQueue(pssName, _):
	global  _tmp_chat_queue_hash, _tmp_room_dirty

	# \todo change to lasthsh
	for publickey in cache.chats.keys():
		try:
			coll = cache.chats[publickey][pssName]
			if _tmp_chat_queue_hash[pssName] != coll.senderfeed.lasthsh:
				sys.stderr.write("update feed " + pssName + ":" + publickey.encode("hex") + "\naddr: " + cache.chats[publickey][pssName].senderfeed.obj.account.get_address().encode("hex") + "\n")
				coll.senderfeed.obj.update(coll.senderfeed.lasthsh)
				_tmp_chat_queue_hash[pssName] = coll.senderfeed.lasthsh
		except:
			pass

	for roomname in cache.rooms.keys():
		try:
			room = cache.get_room(roomname)
			if _tmp_room_queue_hash[roomname] != room.feedcollection.senderfeed.lasthsh:
				sys.stderr.write("update room " + roomname + ":" + room.feedcollection.senderfeed.obj.account.get_public_key().encode("hex") + "\naddr: " + room.feedcollection.senderfeed.obj.account.get_address().encode("hex") + "\n")
				room.feedcollection.senderfeed.obj.update(room.feedcollection.senderfeed.lasthsh)
				_tmp_room_queue_hash[roomname] = room.feedcollection.senderfeed.lasthsh
				_tmp_room_dirty = True
		except Exception as e:
			raise(e)
	
	return weechat.WEECHAT_RC_OK



# \todo conceal feed queries in room obj
def roomRead(pssName, _):
#	global _tmp_room_dirty
#
#	if not _tmp_room_dirty:
#		return weechat.WEECHAT_RC_OK
#
#	_tmp_room_dirty = False

	outbufs = []
	for r in cache.rooms.values():

		msgs = []

		ctx = EventContext()
		ctx.reset(PSS_BUFTYPE_ROOM, pssName, r.get_name())

		r.feedcollection.gethead(cache.get_active_bzz())

		msgs = r.feedcollection.get()
		sys.stderr.write("getting feed for room: " + repr(r) + "\n" + "msglen" + repr(len(msgs)))

		for m in msgs:

			# use set nick if message sender is self
			# \todo eliminate, move to instant feedback on send for self
			contact = None
			nick = ""
			ps = cache.get_pss(ctx.get_node())
			if ps.get_public_key() == m.key:
				contact = ps.account
				nick = cache.get_nodeself(ctx.get_node())
			# \todo use binary key repr in nicks dict
			else:
				contact = cache.get_contact_by_public_key(m.key)
				nick = contact.get_nick()

			msg = r.extract_message(m.content, contact)

			buf = weechat.buffer_search("python", ctx.to_buffer_name()) #bufname)
			wOut(
				PSS_BUFPFX_DEBUG,
				[],
				"!!!",
				"writing to room buf " + ctx.to_buffer_name() + " for room " + r.get_name()
			)
			wOut(
				PSS_BUFPFX_IN,
				[buf],
				nick,
				msg
			)


	return weechat.WEECHAT_RC_OK	


# perform a single read from incoming pss websocket file descriptor
# \todo move this to a method of Pss object, so we can evaluate rpc replies to commands (such as setPeerPublicKey
def msgPipeRead(pssName, fd):

	# the received message
	msg = ""

	# data to display in nick column
	displayFrom = ""

	# holds sender key
	fromKey = ""
	fromKeyHex = ""

	# whether or not this is a nick already registered in cache
	# \todo possibly redundant, should be able to tell from cache directly
	known = False

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
			wOut(
				PSS_BUFPFX_DEBUG,
				[bufs[pssName]],
				"",
				"skipping invalid receive: " + repr(o)
			)
			return weechat.WEECHAT_RC_OK
	
		# decode contents and display in buffer
		msgSrc = r['params']['result']['Msg'][2:].decode("hex")

		# resolve the nick if it exists
		fromKeyHex = pss.clean_pubkey(r['params']['result']['Key'])
		fromKey = fromKeyHex.decode("hex")

		# \todo add pss name and sender nick name to ctx
		ctx = EventContext()
		ctx.set_pss(cache.get_pss(pssName))
		try:
			contact = cache.get_contact_by_public_key(fromKey)
			displayFrom = contact.get_nick()
			known = True
		except Exception as e:
			sys.stderr.write("exception in get  contact: " + repr(e) + "\n")
			displayFrom = pss.label(fromKeyHex, 8)
			# \todo without metadata we have no way of knowing the overlay, so it has to be empty
			contact = pss.PssContact(displayFrom, ctx.get_pss().get_public_key())
			contact.set_public_key(fromKey)
			contact.set_overlay("")
			ctx.get_pss().add(contact)
			cache.add_contact(contact)

		ctx.reset(PSS_BUFTYPE_CHAT, pssName, displayFrom)
		# write the message to the buffer
		wOut(
			PSS_BUFPFX_IN,
			[buf_get(ctx, known)],
			displayFrom,
			msgSrc
		)

	return weechat.WEECHAT_RC_OK




#############################
# WEECHAT BUFFER HANDLING
#############################

# gets the buffer matching the type and the name given
# creates if it doesn't exists
# \todo rename bufname to more precise term
def buf_get(ctx, known):
	global _tmp_room_queue_hash, _tmp_room_dirty

	haveBzz = False
	# \todo integrity check of input data
	bufname = ctx.to_buffer_name()

	wOut(
		PSS_BUFPFX_DEBUG,
		[],
		"!!!",
		"generated bufname " + bufname
	)

	buf = weechat.buffer_search("python", bufname)

	if ctx.is_room() and ctx.get_bzz() == None:
		raise RuntimeError("gateway needed for multiuser chats over swarm")

	
	if buf == "":

		# for debug only
		pss_publickey_hex = pss.rpchex(ctx.get_pss().get_public_key())
		pss_overlay_hex = pss.rpchex(ctx.get_pss().get_overlay())

		# chat is DM between two parties
		if ctx.is_chat():
		
			shortname = "pss:" + ctx.get_name()
			# set up the buffer
			ctx.set_buffer(weechat.buffer_new(bufname, "buf_in", ctx.get_node(), "buf_close", ctx.get_node()), bufname)
			weechat.buffer_set(ctx.get_buffer(), "short_name", shortname)
			weechat.buffer_set(ctx.get_buffer(), "title", ctx.get_name() + " @ PSS '" + ctx.get_node() + "' | node: " + weechat.config_get_plugin(ctx.get_pss().get_host() + "_url") + ":" + weechat.config_get_plugin(ctx.get_pss().get_port() + "_port") + " | key  " + pss.label(pss_publickey_hex) + " | address " + pss.label(pss_overlay_hex))
			weechat.buffer_set(ctx.get_buffer(), "hotlist", weechat.WEECHAT_HOTLIST_PRIVATE)
			weechat.buffer_set(ctx.get_buffer(), "display", "1")
			plugin = weechat.buffer_get_pointer(ctx.get_buffer(), "plugin")

			bufs[bufname] = buf


		# room is multiuser conversation
		elif ctx.is_room():
	
			shortname = "pss#" + ctx.get_name()

			buf = weechat.buffer_new(bufname, "buf_in", ctx.get_node(), "buf_close", ctx.get_node())
			weechat.buffer_set(buf, "short_name", shortname)
			weechat.buffer_set(buf, "title", "#" + ctx.get_node() + " @ PSS '" + ctx.get_node() + "' | node: " + weechat.config_get_plugin(ctx.get_pss().get_host() + "_url") + ":" + weechat.config_get_plugin(ctx.get_pss().get_port() + "_port") + " | key  " + pss.label(ctx.get_pss().get_public_key().encode("hex")) + " | address " + pss.label(ctx.get_pss().get_overlay().encode("hex")))
			weechat.buffer_set(buf, "hotlist", weechat.WEECHAT_HOTLIST_PRIVATE)
			weechat.buffer_set(buf, "nicklist", "1")
			weechat.buffer_set(buf, "display", "1")
			weechat.nicklist_add_group(buf, "", "me", "weechat.color.nicklist_group", 1)
			weechat.nicklist_add_nick(buf, "me", ctx.get_node(), "bar_fg", "", "bar_fg", 1)
	
			plugin = weechat.buffer_get_pointer(buf, "plugin")
			bufs[bufname] = buf
			
			if cache.get_room_count() == 0:
				hookTimers.append(weechat.hook_timer(PSS_ROOM_PERIOD, 0, 0, "roomRead", ctx.get_node()))
			wOut(
				PSS_BUFPFX_DEBUG,
				[],
				"roomdbg",
				str(bufs[bufname])
			)

			# create new room
			(room, loaded) = cache.add_room(ctx.get_name(), ctx.get_node())
			if loaded:
				_tmp_room_queue_hash[ctx.get_name()] = room.feedcollection.senderfeed.lasthsh
				_tmp_room_dirty = True

			wOut(
				PSS_BUFPFX_DEBUG,
				[],
				"",
				"loaded room " + repr(cache.get_room(ctx.get_name()))
			)

			for p in room.get_participants():
				buf_room_add(buf, p.get_nick())

		else:
			raise RuntimeError("invalid buffer type")

	else:
		ctx.set_buffer(buf, bufname)

	return ctx.get_buffer()



# handle inputs to buffer that are not slash commands
# currently all input is handled as messages to send
# where the string before the first whitespace is taken as the nick of the recipient
# the recipient must have been previously added to the node
def buf_in(pssName, buf, inputdata):


	ctx = EventContext()
	ctx.parse_buffer(buf)
	ctx.set_pss(cache.get_pss(ctx.get_node()))
	sys.stderr.write("parsed ctx: " + str(ctx))
	wOut(
		PSS_BUFPFX_DEBUG,
		[],
		"<<<",
		"input in " + ctx.get_name()
	)

	if ctx.is_room():
		room = cache.get_room(ctx.get_name())
		for f in room.feedcollection.feeds.keys():
			sys.stderr.write("f is " + repr(f) + "\n")	
		hsh = room.send(inputdata)
		sys.stderr.write("room update: " + hsh + "\n")
		

	else:
		# send message
		try:
			ctx.get_pss().send(cache.get_contact_by_nick(ctx.get_name()), inputdata)
			wOut(
				PSS_BUFPFX_OUT,
				[ctx.get_buffer()],
				"you",
				inputdata
			)
			
		except Exception as e:
			wOut(
				PSS_BUFPFX_ERROR,
				[buf],
				"!!!",
				"send fail: " + repr(e)
			)
			return weechat.WEECHAT_RC_ERROR

		peercontact = cache.get_contact_by_nick(ctx.get_name())
		feedcoll = cache.chats[peercontact.get_public_key()][ctx.get_node()]
		# \todo should not do direct write, should go via msg object
		hsh = feedcoll.write(inputdata)
		sys.stderr.write("wrote update to swarm, got " + hsh + "\n")


	return weechat.WEECHAT_RC_OK



# when buffer is closed, node should also close down
def buf_close(pssName, buf):
	cache.close_node(pssName)
	return weechat.WEECHAT_RC_OK


# \todo broken
def pss_invite(pssName, nick, room):
	#bufname = buf_generate_name(pssName, "room", nick)
	#feeds[bufname] = pss.Feed(bzzs[pssName].agent, psses[pssName].get_account(), "d" + pss.publickey_to_address(remotekeys[nick]))
	contact = cache.get_contact_by_nick(nick)
	#nickkey = remotekeys[nick]
	#contact = nicks[nickkey]
	room.add(nick, contact)
	#wOut(PSS_BUFPFX_DEBUG, [], "", "added room feed with topic " + feeds[bufname].topic.encode("hex"))


def buf_room_add(buf, nick, groupname=""):
	if weechat.nicklist_search_group(buf, "", "members") == "":
		weechat.nicklist_add_group(buf, "", "members", "weechat.color.nicklist_group", 1)
	weechat.nicklist_add_nick(buf, groupname, nick, "bar_fg", "", "bar_fg", 1)




############################
# COMMANDS HANDLING
############################


# handle node inputs	
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

		if cache.have_node_name(ctx.get_node()):	
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
		weechat.config_set_plugin(ctx.get_node() + "_url", host)
		weechat.config_set_plugin(ctx.get_node() + "_port", port)

	
		# if we made it here we don't have a buffer for this node already
		# so create it and merge the node buffer with core so we can do the neat ctrl-x trick
		bufs[ctx.get_node()] = weechat.buffer_new("pss.node." + ctx.get_node(), "buf_node_in", ctx.get_node(), "buf_close", ctx.get_node())
		weechat.buffer_set(bufs[ctx.get_node()], "short_name", "pss."+ ctx.get_node())
		weechat.buffer_set(bufs[ctx.get_node()], "title", "PSS '" + ctx.get_node() + "' | not connected")
		weechat.buffer_merge(bufs[ctx.get_node()], weechat.buffer_search_main())
		weechat.buffer_set(bufs[ctx.get_node()], "display", "1")


		# now that we have the buffer up we have somewhere to write output relevant to this connection
		# we can proceed with connection in the pss instance
		wOut(
			PSS_BUFPFX_WARN,
			[bufs[ctx.get_node()]],
			"0-> 0",
			"connecting to '" + ctx.get_node() + "'"
		)
	
		pssnode = pss.Pss(ctx.get_node(), host, port)

		if not pssnode.connect():
			wOut(PSS_BUFPFX_ERROR, [bufs[ctx.get_node()]], "-1-x 0", "connect to '" + ctx.get_node() + "' failed: " + cache.get_pss(ctx.get_node()).error()['description'])
			return weechat.WEECHAT_RC_ERROR

		wOut(PSS_BUFPFX_OK, [bufs[ctx.get_node()]], "0---0", "connected to '" + ctx.get_node() + "'")

		_tmp_chat_queue_hash[ctx.get_node()] = ""
		cache.add_node(pssnode)

		wOut(PSS_BUFPFX_OK, [], "+++", "added pss " + ctx.get_node())

		
		# save what we've accomplished so far in the context, to be passed to the hook
		ctx.parse_buffer(bufs[ctx.get_node()])
		ctx.set_pss(cache.get_pss(ctx.get_node()))
		ctx.set_bzz(cache.get_active_bzz())
		# \todo temporary solution, swarm gateway should be set explicitly or at least we need to be able to choose port
		ctxid = ctxstore.put(ctx)
		hookSocks.append(weechat.hook_connect("", host, 8500, 0, 0, "", "pss_connect", ctxid))
		


		# start processing inputs on the websocket
		hookFds[ctx.get_node()] = weechat.hook_fd(cache.get_pss(ctx.get_node()).get_fd(), 1, 0, 0, "msgPipeRead", ctx.get_node())
		hookTimers.append(weechat.hook_timer(PSS_FEEDBOX_PERIOD, 0, 0, "processFeedOutQueue", ctx.get_node()))

		# set own nick for this node
		# \todo use configurable global default nick
		# \todo clean up messy pubkey slicing (should be binary format in pss obj)
		cache.set_nodeself(ctx.get_node(), PSS_DEFAULT_NICK)
		
		return weechat.WEECHAT_RC_OK


	# get the context we're getting the command in
	# if we are not in pss context, 
	# the we assume that the first argument is the name of the node
	# /pss oc add someone key addr
	# becomes
	# /pss add someone key addr
	# and "oc" is set to pssName
	# \todo consider exception for connect-command

	ctx.parse_buffer(buf)
	if ctx.is_root():
		ctx.set_node(argv[0])
		argv = argv[1:]
		argc -= 1

	try:
		ctx.set_pss(cache.get_pss(ctx.get_node()))
		ctx.set_bzz(cache.get_active_bzz())
	except:
		wOut(
			PSS_BUFPFX_ERROR,
			[],
			"!!!",
			"unknown pss connection '" + ctx.get_node() + "'"
		)
		return weechat.WEECHAT_RC_ERROR


	# set configuation values
	if argv[0] == "set":
		if argc < 3:
			wOut(PSS_BUFPFX_ERROR, [], "!!!", "insufficient number of arguments <TODO help output")
			return weechat.WEECHAT_RC_ERROR

		k = argv[1]
		v = argv[2]

		# for now we handle privkeys directly
		# we will read keystore jsons in near future instead, though
		if k == "pk":
			try:
				privkey = pss.clean_privkey(v)
			except:
				wOut(PSS_BUFPFX_ERROR, [], "!!!", "invalid key format")
				return weechat.WEECHAT_RC_ERROR
			try:
				pssnode = cache.get_pss(ctx.get_node())
				pssnode.set_account_write(privkey.decode("hex"))
				cache.update_node_contact_feed(pssnode)
			except KeyError as e:
				pass
			except ValueError as e:
				wOut(PSS_BUFPFX_ERROR, [], "!!!", "set account fail: " + str(e))
				return weechat.WEECHAT_RC_ERROR
		else:
			wOut(PSS_BUFPFX_ERROR, [], "!!!", "unknown config key")
			return weechat.WEECHAT_RC_ERROR
					
		wOut(PSS_BUFPFX_DEBUG, [], "!!!", "set pk to " + v + " for " + ctx.get_node())

		weechat.WEECHAT_RC_OK	
	


	# add a recipient to the address books of plugin and node
	# \todo currently overwritten if same pubkey and different addr, should be possible to have both, maybe even one-shots special command with dark address where entry is deleted after message sent!!!
	elif argv[0] == "add":

		nick = ""
		pubkeyhx = ""
		overlayhx = ""

		# input sanity check
		if argc < 3:
			wOut(
				PSS_BUFPFX_ERROR,
				[ctx.get_buffer()],
				"!!!",
				"not enough arguments for add <TODO: help output>"
			)
			return weechat.WEECHAT_RC_ERROR

		# puny human varnames
		nick = argv[1]
		pubkeyhx = argv[2]
		if argc == 4:
			overlayhx = argv[3]
		else:
			overlayhx = "0x"
		
		# backend add recipient call	
		pubkey = pss.clean_pubkey(pubkeyhx).decode("hex")
		overlay = pss.clean_overlay(overlayhx).decode("hex")
		try:
			newcontact = pss.PssContact(nick, ctx.get_pss().get_public_key())
			newcontact.set_public_key(pubkey)
			newcontact.set_overlay(overlay)
			ctx.get_pss().add(newcontact)
			cache.add_contact(newcontact, True)
		except Exception as e:
			wOut(
				PSS_BUFPFX_ERROR,
				[ctx.get_buffer()],
				"!!!",
				"add contact error: " + repr(e)
			)
			return weechat.WEECHAT_RC_ERROR

		ctx.reset(PSS_BUFTYPE_CHAT, ctx.get_node(), nick)

		# refresh the plugin memory map version of the recipient
		wOut(
			PSS_BUFPFX_DEBUG,
			[],
			"!!!",
			"added key " + pubkeyhx + " to nick " + nick + " node " + ctx.get_node()
		)

		# retrieve the buffer (create if it doesn't exist)
		buf_get(ctx, True)	
		wOut(
			PSS_BUFPFX_INFO,
			[ctx.get_buffer()],
			"!!!",
			"added contact '" + ctx.get_name() + "' to '" + ctx.get_node() + "' (key: " + pss.label(pubkeyhx) + ", addr: " + pss.label(overlayhx) + ")"
		)


	# send a message to a recipient
	elif argv[0] == "send" or argv[0] == "msg":

		nick = ""
		msg = ""

		# verify input
		if argc < 2:
			wOut(
				PSS_BUFPFX_ERROR,
				[ctx.get_buffer()],
				"!!!",
				"not enough arguments for send"
			)
			return weechat.WEECHAT_RC_ERROR

		nick = pss.clean_nick(argv[1])
		if argc > 2:
			msg = " ".join(argv[2:])

		# check that the contact is known in the cache
		contact = None
		try:
			contact = cache.get_contact_by_nick(nick)
		except:
			wOut(
				PSS_BUFPFX_ERROR,
				[ctx.get_buffer()],
				"!!!",
				"invalid nick " + nick
			)
			return weechat.WEECHAT_RC_ERROR

		ctx.reset(PSS_BUFTYPE_CHAT, ctx.get_node(), nick)
		buf = buf_get(ctx, True)

		# if no message body we've just opened the chat window
		if msg != "":
			if not pss.is_message(msg):
				wOut(
					PSS_BUFPFX_DEBUG,
					[ctx.get_buffer()],
					"",
					"invalid message " + msg
				)
				return weechat.WEECHAT_RC_ERROR

			return buf_in(ctx.get_node(), buf, msg)


	# create/join existing chat room
	# \todo broken 
	elif argv[0] == "join":

		room = ""

		if argc < 2:
			wOut(
				PSS_BUFPFX_ERROR,
				[ctx.get_buffer()],
				"!!!",
				"not enough arguments for join"
			)
			return weechat.WEECHAT_RC_ERROR

		room = argv[1]
		ctx.reset(PSS_BUFTYPE_ROOM, ctx.get_node(), room)

		if not ctx.get_name() in _tmp_room_queue_hash:
			_tmp_room_queue_hash[ctx.get_name()] = pss.zerohsh

		# start buffer for room
		buf_get(ctx, True)


	# invite works in context of chat rooms, and translates in swarm terms to
	# adding one separate feed encoded with the invited peer's key
	# room argument can be omitted if command is issued om channel to invite to
	# note feeds are currently unencrypted
	# \todo broken
	elif argv[0] == "invite":

		nick = ""
		roomname = ""

		if argc < 2:
			wOut(
				PSS_BUFPFX_ERROR,
				[ctx.get_buffer()],
				"!!!",
				"not enough arguments for invite"
			)

		# if missing channel argument get bufname command was issued in
		# and derive channel name from it if we can (fail if not)
		elif argc < 3:
			if not ctx.is_room():
				wOut(
					PSS_BUFPFX_ERROR,
					[ctx.get_buffer()],
					"!!!",
					"unknown channel '" + ctx.get_name() + "'"
				)
				return weechat.WEECHAT_RC_ERROR
	
		else:
			ctx.set_name(argv[2])

		nick = pss.clean_nick(argv[1])

		# check if room exists
		# if it does, perform invitation
		try:
			#roombufname = buf_generate_name(pssName, "room", roomname)
			roombufname = ctx.to_buffer_name()
			room = cache.get_room(ctx.get_name()) #roombufname)
			pss_invite(pssName, nick, room)
			wOut(
				PSS_BUFPFX_DEBUG,
				[],
				"!!!",
				"added " + nick + " to " + ctx.get_name()
			)
			# if neither the previous fail, add the nick to the buffer
			roombuf = weechat.buffer_search("python", roombufname)
			buf_room_add(roombuf, nick)

		except KeyError as e: # keyerror catches both try statements
			wOut(
				PSS_BUFPFX_ERROR,
				[ctx.get_buffer()],
				"!!!",
				"Unknown room or nick: " + str(e)
			)


	# output node key
	elif argv[0] == "key" or argv[0] == "pubkey":
		wOut(
			PSS_BUFPFX_INFO,
			[ctx.get_buffer()],
			ctx.get_node() + ".key",
			ctx.get_pss().get_public_key().encode("hex")
		)


	# output node base address
	elif argv[0] == "addr" or argv[0] == "address":
		wOut(
			PSS_BUFPFX_INFO,
			[ctx.get_buffer()],
			ctx.get_node() + ".addr",
			ctx.get_pss().get_overlay().encode("hex")
		)


	# set nick for pss node
	elif argv[0] == "nick":
		try:
			if len(argv) > 1:
				nick = pss.clean_nick(argv[1])
				cache.set_nodeself(ctx.get_node(), nick)
			wOut(
				PSS_BUFPFX_INFO,
				[ctx.get_buffer()],
				ctx.get_node(),
				"nick is '" + cache.get_nodeself(ctx.get_node()) + "'"
			)
		except ValueError as e:
			wOut(
				PSS_BUFPFX_ERROR,
				[ctx.get_buffer()],
				"!!!",
				"Invalid nick: " + argv[1]
			)
			
	# stop connection
	# \todo also kill the subprocess 
	# \todo ensure clean shutdown so conncet can be called over
	elif argv[0] == "stop":
		weechat.unhook(hookFds[ctx.get_node()])
		wOut(
			PSS_BUFPFX_INFO,
			[ctx.get_buffer()],
			"!!!",
			"disconnected from " + ctx.get_node()
		)
		cache.close_node(ctx.get_node())


	# invalid input
	else:
		return weechat.WEECHAT_RC_ERROR

	
	# all good
	return weechat.WEECHAT_RC_OK	





###################
# SIGNAL HANDLERS
###################

# signal handler for load
# catches the script path used to locate other required resources
def pss_sighandler_load(data, sig, sigdata):
	global cache

	entrycount = 0
	okcount = 0

	# ignore if not our load signal
	if not os.path.basename(sigdata) == "swarm.py":
		return weechat.WEECHAT_RC_OK	

	# parse dir and check if websocket comms script is there
	# bail if it's not 
	# \todo UNLOAD plugin on fail
	cache = pss.Cache(os.path.dirname(sigdata), PSS_FEEDQUEUE_SIZE)
	
	# read the contacts database and populate the nicks plugin memory map 
	# by applying them sequentially
	# if it can't be found, we simply skip it, but telle the user
	try:
		(entrycount, okcount) = cache.load_store()
		
	except IOError as e:
		wOut(
			PSS_BUFPFX_WARN,
			[],
			"!!!",
			"could not open contact store " + scriptPath + "/.pss-contacts: " + repr(e)
		)
		return weechat.WEECHAT_RC_ERROR

	wOut(
		PSS_BUFPFX_DEBUG,
		[],
		"<<<",
		"successfully imported " + str(okcount) + " of " + str(entrycount) + " store entries"
	)
	
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
