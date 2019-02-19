# \todo WIP consistent representation of pubkeys in objects (65 bytes, binary)

import weechat
import os
import sys
import pss # plugin package, nothing official

# consts
PSS_VERSION = "0.3.2"
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
feedOutQueue = pss.Queue(10)

# buffers
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


# context is a common object for keeping track of context of an incoming event 
class EventContext:
	
	def __init__(self, name):
		self.type = 0
		self.node = ""
		self.nick = ""
		self.pss = None
		self.bzz = None
		self.buf = None
		self.bufname = ""


	def is_root(self):
		return self.type == 0



	def parse_buffer(self, buf):
		self.buf = buf
		self.bufname = weechat.buffer_get_string(buf, "name")

		flds = bufname.split(".")
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
		elif flds[2] == "chat":
			self.type = PSS_BUFTYPE_CHAT
			self.node = flds[1]
			self.nick = flds[3]	
		elif flds[2] == "room":
			self.type = PSS_BUFTYPE_ROOM
			self.node = flds[1]
			self.handle = flds[3]	

		return True


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

def processFeedOutQueue(pssName, _):
	while 1:
		update = feedOutQueue.get()
		if update == None:
			#wOut(PSS_BUFPFX_DEBUG, [], ">>>", "no feed updates for " + pssName)
			break

		try:
			hsh = bzzs[pssName].add(update.data)
			wOut(PSS_BUFPFX_DEBUG, [], ">>>", "bzz sent for " + pssName + "." + update.name + ": " + hsh)
			feedKey = buf_generate_name(update.nod, update.typ, update.name)
			r = feeds[feedKey].update(hsh)
			wOut(PSS_BUFPFX_DEBUG, [], ">>>", "feed sent for " + pssName + "." + update.name + ": " + r)
		except IOError as e:
			wOut(PSS_BUFPFX_ERROR, [buf], "!!!", "add feed for " + pssName + "." + update.name + " fail: " + psses[pssName].error()['description'])
			return weechat.WEECHAT_RC_ERROR

	return weechat.WEECHAT_RC_OK



# \todo conceal feed queries in room obj
def roomRead(pssName, _):
	outbufs = []
	for bufname, r in rooms.iteritems():
		msgs = []
		#for k, f in r.feedcollection_in.feeds.iteritems():
		#	wOut(PSS_BUFPFX_DEBUG, [], "!!!", "getting room feed " + k + " infeed " + k + " / " + f['obj'].account.address.encode("hex") + " bufname " + bufname)
		#	wOut(PSS_BUFPFX_DEBUG, [], "!!!", "room hash " + r.hsh_room.encode("hex"))
		r.feedcollection_in.gethead(r.bzz)
		msgs = r.feedcollection_in.get()

		#buf = weechat.buffer_search("python", buf_generate_name(pssName, "room", k))
		for m in msgs:
			#wOut(PSS_BUFPFX_DEBUG, [], "!!!", "getting nick from key " + m.key.encode("hex"))
			#for k in nicks.keys():
			#	wOut(PSS_BUFPFX_DEBUG, [], "!!!", "have key " + k)

			#wOut(PSS_BUFPFX_DEBUG, [], "!!!", "parsing content " + m.content.encode("hex"))

			# use set nick if message sender is self
			# \todo eliminate, move to instant feedback on send for self
			nickuser = None
			if psses[pssName].eth.publickeybytes == m.key:
				nickuser = selfs[pssName]
			# \todo use binary key repr in nicks dict
			else:
				nickdictkey = m.key.encode("hex")
				nickuser = nicks[nickdictkey]

			msg = r.extract_message(m.src, nickuser)

			buf = weechat.buffer_search("python", bufname)
			#bufname = buf_get(pssName, "room", r.name, True)
			wOut(PSS_BUFPFX_DEBUG, [], "!!!", "writing to room buf " + bufname + " for room " + r.name)
			wOut(PSS_BUFPFX_IN, [buf], nickuser.nick, msg)


	return weechat.WEECHAT_RC_OK	


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



#############################
# BUFFER EVENT OPERATIONS
#############################

# gets the buffer matching the type and the name given
# creates if it doesn't exists
# \todo rename bufname to more precise term
def buf_get(pssName, typ, name, known):

	haveBzz = False
	# \todo integrity check of input data
	bufname = buf_generate_name(pssName, typ, name)

	wOut(PSS_BUFPFX_DEBUG, [], "!!!", "generated bufname " + bufname + " for " + pssName + " / " + typ + " / " + name)

	try:
		buf = weechat.buffer_search("python", bufname)
	# \todo re-evaluate why exception can occur here, and which one specifically
	except Exception as e:
		return ""

	if pssName in bzzs:
		haveBzz = True
	elif typ == "room":
		raise RuntimeError("gateway needed for multiuser chats over swarm")
	
	if buf == "":

		shortname = ""

		# for debug only
		pss_publickey_hex = pss.rpchex(psses[pssName].get_public_key())
		pss_overlay_hex = pss.rpchex(psses[pssName].get_overlay())

		# chat is DM between two parties
		if typ == "chat":
			ispubkey = False
			if known:
				shortname = "pss:" + name
			else:
				shortname = "pss:" + name[:8]
				ispubkey = True

			buf = weechat.buffer_new(bufname, "buf_in", pssName, "buf_close", pssName)
			weechat.buffer_set(buf, "short_name", shortname)
			weechat.buffer_set(buf, "title", name + " @ PSS '" + pssName + "' | node: " + weechat.config_get_plugin(psses[pssName].host + "_url") + ":" + weechat.config_get_plugin(psses[pssName].port + "_port") + " | key  " + pss.label(pss_publickey_hex) + " | address " + pss.label(pss_overlay_hex))
			weechat.buffer_set(buf, "hotlist", weechat.WEECHAT_HOTLIST_PRIVATE)
			weechat.buffer_set(buf, "display", "1")
			plugin = weechat.buffer_get_pointer(buf, "plugin")
			bufs[bufname] = buf
			debugstr = "have " + repr(psses[pssName].have_account()) + " + " +  repr(haveBzz)
			wOut(PSS_BUFPFX_DEBUG, [], "have", debugstr)

			if psses[pssName].have_account() and haveBzz:
				pubkey = ""
				if ispubkey:
					pubkey = name
				else:
					pubkey = remotekeys[name]
				try:
					feeds[bufname] = pss.Feed(bzzs[pssName].agent, psses[pssName].get_account(), PSS_BUFTYPE_CHAT + pss.publickey_to_address(pubkey))
					wOut(PSS_BUFPFX_DEBUG, [], "", "added feed with topic " + feeds[bufname].topic.encode("hex"))
				except ValueError as e:
					wOut(PSS_BUFPFX_ERROR, [], "???", "could not set up feed: " + str(e))

		# room is multiuser conversation
		elif typ == "room":
	
			shortname = "pss#" + name

			buf = weechat.buffer_new(bufname, "buf_in", pssName, "buf_close", pssName)
			weechat.buffer_set(buf, "short_name", shortname)
			weechat.buffer_set(buf, "title", "#" + name + " @ PSS '" + pssName + "' | node: " + weechat.config_get_plugin(psses[pssName].host + "_url") + ":" + weechat.config_get_plugin(psses[pssName].port + "_port") + " | key  " + pss.label(pss_publickey_hex) + " | address " + pss.label(pss_overlay_hex))
			weechat.buffer_set(buf, "hotlist", weechat.WEECHAT_HOTLIST_PRIVATE)
			weechat.buffer_set(buf, "nicklist", "1")
			weechat.buffer_set(buf, "display", "1")
			#weechat.nicklist_add_group(buf, "", "me", "weechat.color.nicklist_group", 1)
			#weechat.nicklist_add_nick(buf, "me", psses[pssName].name, "bar_fg", "", "bar_fg", 1)
	
			plugin = weechat.buffer_get_pointer(buf, "plugin")
			bufs[bufname] = buf
			
			if len(rooms) == 0:
				hookTimers.append(weechat.hook_timer(PSS_ROOM_PERIOD, 0, 0, "roomRead", psses[pssName].name))
			wOut(PSS_BUFPFX_DEBUG, [], "roomdbg", str(bufs[bufname]))
#			bzzRoomKey = "room"+name
#			if not bzzRoomKey in bzzs:
#				agent = pss.Agent(psses[pssName].host, 8500)
#				bzzs[bzzRoomKey] = pss.Bzz(agent)
#			rooms[bufname] = pss.Room(bzzs[bzzRoomKey], name, psses[pssName].get_account())
			rooms[bufname] = pss.Room(bzzs[pssName], name, psses[pssName].get_account())
			# \todo test load first, only init if not found
			try:
				roomhsh = rooms[bufname].get_state_hash()
				rooms[bufname].load(roomhsh, psses[pssName].get_account())
				wOut(PSS_BUFPFX_DEBUG, [], "", "loaded room with topic " + rooms[bufname].feed_out.topic.encode("hex") + " account " + rooms[bufname].feed_out.account.address.encode("hex") + " roomfeed " + rooms[bufname].feed_room.topic.encode("hex"))
				for k, p in rooms[bufname].participants.iteritems():
					nick = ""
					publickey = p.get_public_key()
					if publickey == selfs[pssName].get_public_key():
					#if p.key == selfs[pssName].key:
						nick = selfs[pssName].nick
					else:
						#if not p.key in nicks:
						if not publickey in nicks:
							acc = pss.Account()
							try:
								acc.set_public_key(publickey, p.get_address())
								nicks[p.nick] = pss.PssContact(p.nick, p.src)
								remotekeys[publickey] = p.nick
							except RuntimeError as e:
								wOut(PSS_BUFPFX_WARN, [], "", "public key does not match address")
								continue

						nick = nicks[publickey]
					buf_room_add(buf, nick)
			# \todo correct expect to disambiguate unexpected fails
			except Exception as e:
				wOut(PSS_BUFPFX_DEBUG, [], "", "fail room load: " + str(e))
				rooms[bufname].start(PSS_DEFAULT_NICK)
				wOut(PSS_BUFPFX_DEBUG, [], "", "added room with topic " + rooms[bufname].feed_out.topic.encode("hex") + " account " + rooms[bufname].feed_out.account.get_address().encode("hex") + " roomfeed " + rooms[bufname].feed_room.topic.encode("hex"))
		else:
			raise RuntimeError("invalid buffer type")

	return buf


# handle inputs to buffer that are not slash commands
# currently all input is handled as messages to send
# where the string before the first whitespace is taken as the nick of the recipient
# the recipient must have been previously added to the node
def buf_in(pssName, buf, inputdata):
	global psses

	#for k in feeds:
	#	wOut(PSS_BUFPFX_DEBUG, [buf], "bufin feed", "k " + k)


	bufname = weechat.buffer_get_string(buf, "name")
	wOut(PSS_BUFPFX_DEBUG, [], "<<<" , "input in " + bufname)

	ctx = buf_get_context(buf)

	# check if the recipient is registered
#	nick = inputdata[0:sepIndex]
#	if not nick in psses[pssName].contacts:
#		wOut(PSS_BUFPFX_ERROR, [], "???", "unknown contact '" % weechat.color("red") + nick + "'" ) 
#		return weechat.WEECHAT_RC_ERROR

	if ctx['t'] == PSS_BUFTYPE_ROOM: 
		#wOut(PSS_BUFPFX_ERROR, [buf], "!!!", "posting: " + inputdata.encode("hex"))
		rooms[bufname].send(inputdata)
		return weechat.WEECHAT_RC_OK

	for n in psses[pssName].contacts.keys():
		wOut(PSS_BUFPFX_DEBUG, [], "nickkey", repr(n))

	# send message
	if psses[pssName].send(ctx['h'], inputdata):
		wOut(PSS_BUFPFX_OUT, [buf], "you", inputdata)
	else:
		wOut(PSS_BUFPFX_ERROR, [buf], "!!!", "send fail: " + psses[pssName].error()['description'])

	# \todo make this asynchronous instead, we want command to print and return immediately in the ui
	# \todo add buffering of sub-second updates (and a timer hook to send them, this solves async too)
	if bufname in feeds:
		try:
			feedOutQueue.add(pss.FeedUpdate(pssName, "chat", ctx['h'], inputdata))
		except RuntimeError as e:
			wOut(PSS_BUFPFX_ERROR, [], "!!!", "feed add to buffer fail: " + str(e))
			
	return weechat.WEECHAT_RC_OK


# create a buffer name from given parameters
# \todo should be inverse of buf_get_context
def buf_generate_name(pssName, typ, name):
	return "pss." + pssName + "." + typ + "." + name


# when buffer is closed, node should also close down
def buf_close(pssName, buf):
	cache.close_node(pssName)
	return weechat.WEECHAT_RC_OK



# given a buffer, returns dict describing which context this buffer represents
def buf_get_context(buf):
	

	return r



# handle slash command inputs
def pss_handle(data, buf, args):
	return buf_node_in(data, buf, args)



def pss_invite(pssName, nick, room):
	#bufname = buf_generate_name(pssName, "room", nick)
	#feeds[bufname] = pss.Feed(bzzs[pssName].agent, psses[pssName].get_account(), "d" + pss.publickey_to_address(remotekeys[nick]))
	nickkey = remotekeys[nick]
	contact = nicks[nickkey]
	room.add(nick, contact)
	#wOut(PSS_BUFPFX_DEBUG, [], "", "added room feed with topic " + feeds[bufname].topic.encode("hex"))

def buf_room_add(buf, nick, groupname=""):
	#if weechat.nicklist_search_group(buf, "", "members") == "":
	#	weechat.nicklist_add_group(buf, "", "members", "weechat.color.nicklist_group", 1)
	weechat.nicklist_add_nick(buf, groupname, nick, "bar_fg", "", "bar_fg", 1)


# \todo remove unsuccessful hooks
def sock_connect(pssName, status, tlsrc, sock, error, ip):
	if status != weechat.WEECHAT_HOOK_CONNECT_OK:
		wOut(PSS_BUFPFX_ERROR, [], "???", "swarm gateway connect failed (" + str(status) + "): " + error )
		return weechat.WEECHAT_RC_ERROR

	wOut(PSS_BUFPFX_INFO, [], "!!!", "swarm gateway connected on " + pssName + ", sock " + repr(sock))
	agent = pss.Agent(psses[pssName].host, 8500, sock)
	bzzs[pssName] = pss.Bzz(agent)

	# provided the connection went ok
	# add all nicks in the plugin's memory nick map
	# that match the pubkey of the node to the node's recipient address book
	# \todo use execption instead of if/else/error
	# \todo adding the nicks from a node should be separate proedure, and maybe even split up for feeds and pss
	for c in nicks:
		# debug only
		pss_publickey_hx = psses[pssName].get_public_key().encode("hex")
		pss_overlay_hx = psses[pssName].get_overlay().encode("hex")
		if nicks[c].src == pss_publickey_hx:
			if psses[pssName].add(nicks[c].nick, nicks[c].get_public_key, nicks[c].get_address()):
				wOut(PSS_BUFPFX_INFO, [bufs[pssName]], "+++", "added '" + nicks[c].nick + "' to node '" + pssName + "' (key: " + pss.label(pss_publickey_hx) + ", addr: " + pss.label(oss_overlay_hx) + ")")
				# \ todo make this call more legible (public key to bytes method in pss pkg)
				try:
					feeds[buf_generate_name(pssName, "chat", nicks[c].nick)] = pss.Feed(bzzs[pssName].agent, psses[pssName].get_account(), PSS_BUFTYPE_CHAT + pss.publickey_to_address(psses[pssName].get_public_key()))
				except:
					wOut(PSS_BUFPFX_DEBUG, [bufs[pssName]], "", "bzz gateway for not active")
			else:
				wOut(PSS_BUFPFX_DEBUG, [bufs[pssName]], "", "nick " + c + " not added: " + psses[pssName].error()['description'])

	return weechat.WEECHAT_RC_OK



# handle node inputs	
def buf_node_in(pssName, buf, args):

	# context is only used for acvie nodes
	ctx = EventContext(buf)

	# parse cmd input 
	# \todo remove consecutive whitespace
	argv = args.split(" ")
	argc = len(argv)

	# first we handle commands that are node independent	

	# the connect command is the same for any context
	if argv[0] == "connect":

		host = "127.0.0.1"
		port = "8546"
		pssName = "" 
	
		if argc < 2:
			wOut(PSS_BUFPFX_ERROR, [], "!!!", "invalid command <TODO insert help text>")
		pssName = argv[1]

		if argc > 2:
			host = argv[2]	
		
		if argc > 3:
			port = argv[3]	

		if cache.have_node_name(pssName):	
			existingBuf = weechat.buffer_search("python", "pss.node." + pssName)
			if existingBuf != "":
				wOut(PSS_BUFPFX_DEBUG, [], "", "pss " + pssName + " already exists, changing to that buffer")
				weechat.buffer_set(bufs[pssName], "display", "1")
				return weechat.WEECHAT_RC_OK

			if host == "":
				host = weechat.config_get_plugin(pssName + "_url", host)

			if port == "":
				port = weechat.config_get_plugin(pssName + "_port", port)
	
			wOut(PSS_BUFPFX_DEBUG, [], "", "pss " + pssName + " already exists")
		else:
			
			cache.add_node(pss.Pss(pssName, host, port), pssName)
			wOut(PSS_BUFPFX_OK, [], "+++", "added pss " + pssName)


		# regardless of if we have the node already, store the connection parameters for later for this node name	
		weechat.config_set_plugin(pssName + "_url", host)
		weechat.config_set_plugin(pssName + "_port", port)

	
		# if we made it here we don't have a buffer for this node already
		# so create it and merge the node buffer with core so we can do the neat ctrl-x trick
		bufs[pssName] = weechat.buffer_new("pss.node." + pssName, "buf_node_in", pssName, "buf_close", pssName)
		weechat.buffer_set(bufs[pssName], "short_name", "pss."+ pssName)
		weechat.buffer_set(bufs[pssName], "title", "PSS '" + pssName + "' | not connected")
		weechat.buffer_merge(bufs[pssName], weechat.buffer_search_main())
		weechat.buffer_set(bufs[pssName], "display", "1")


		# now that we have the buffer up we have somewhere to write output relevant to this connection
		# we can proceed with connection in the pss instance
		wOut(
			PSS_BUFPFX_WARN,
			[bufs[pssName]],
			"0-> 0",
			"connecting to '" + pssName + "'"
		)
	
		(currentPss, _) = cache.get_node_by_name(pssName)
		if not currentPss.connect():
			wOut(PSS_BUFPFX_ERROR, [bufs[pssName]], "0-x 0", "connect to '" + pssName + "' failed: " + currentPss.error()['description'])
			return weechat.WEECHAT_RC_ERROR
		wOut(PSS_BUFPFX_OK, [bufs[pssName]], "0---0", "connected to '" + pssName + "'")

		# \todo temporary solution, swarm gateway should be set explicitly or at least we need to be able to choose port
		hookSocks.append(weechat.hook_connect("", host, 8500, 0, 0, "", "sock_connect", pssName))
		


		# start processing inputs on the websocket
		hookFds[pssName] = weechat.hook_fd(psses[pssName].get_fd(), 1, 0, 0, "msgPipeRead", pssName)
		hookTimers.append(weechat.hook_timer(PSS_FEEDBOX_PERIOD, 0, 0, "processFeedOutQueue", pssName))

		# set own nick for this node
		# \todo use configurable global default nick
		# \todo clean up messy pubkey slicing (should be binary format in pss obj)
		publickey = psses[pssName].get_public_key()
		selfs[pssName] = pss.PssContact(PSS_DEFAULT_NICK, publickey)
		selfs[pssName].set_public_key(publickey)
		wOut(PSS_BUFPFX_OK, [bufs[pssName]], pssName, "nick is " + selfs[pssName].nick)
		
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
	wOut(PSS_BUFPFX_DEBUG, [], "", "ctx: " + repr(ctx['t']) + " n " + ctx['n'] + " h " + ctx['h'])
	shiftArg = False

	# t 0 means any non-pss buffer

	if ctx['t'] == 0 and argv[0] != "connect":
		pssName = argv[0]
		argv = argv[1:]
		argc -= 1
	else:
		pssName = ctx['n']

	wOut(PSS_BUFPFX_DEBUG, [], "!!!", "after ctx " + pssName)	

	# see if we already have this node registered
	if not pssName in psses:
		wOut(PSS_BUFPFX_ERROR, [], "!!!", "unknown pss connection '" + pssName + "'")
		return weechat.WEECHAT_RC_ERROR
	currentPss = psses[pssName]



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
				currentPss.set_account_write(privkey.decode("hex"))
			except ValueError as e:
				wOut(PSS_BUFPFX_ERROR, [], "!!!", "set account fail: " + str(e))
				return weechat.WEECHAT_RC_ERROR
		else:
			wOut(PSS_BUFPFX_ERROR, [], "!!!", "unknown config key")
			return weechat.WEECHAT_RC_ERROR
					
		wOut(PSS_BUFPFX_DEBUG, [], "!!!", "set pk to " + v + " for " + pssName)

		weechat.WEECHAT_RC_OK	
	


	# add a recipient to the address books of plugin and node
	# \todo currently overwritten if same pubkey and different addr, should be possible to have both, maybe even one-shots special command with dark address where entry is deleted after message sent!!!
	elif argv[0] == "add":

		nick = ""
		pubkeyhx = ""
		overlayhx = ""

		# input sanity check
		if argc < 3:
			wOut(PSS_BUFPFX_ERROR, [bufs[pssName]], "!!!", "not enough arguments for add <TODO: help output>")
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
		if not currentPss.add(nick, pubkey, overlay):
			wOut(PSS_BUFPFX_ERROR, [bufs[pssName]], "!!!", "add contact error: " + currentPss.error()['description'])
			return weechat.WEECHAT_RC_ERROR

		# refresh the plugin memory map version of the recipient
		wOut(PSS_BUFPFX_DEBUG, [], "!!!", "added key " + pubkeyhx + " to nick " + nick)
		nicks[pubkeyhx] = currentPss.get_contact(nick)
		remotekeys[nick] = pubkeyhx

		# append recipient to file for reinstating across sessions
		storeFile.write(nick + "\t" + pubkeyhx + "\t" + overlayhx + "\t" + pss.rpchex(currentPss.get_public_key()) + "\n")

		# open the buffer if it doesn't exist
		buf_get(pssName, "chat", nick, True)	

		wOut(PSS_BUFPFX_INFO, [bufs[pssName]], "!!!", "added contact '" + nicks[pubkey].nick + "' to '" + pssName + "' (key: " + pss.label(pubkeyhx) + ", addr: " + pss.label(overlayhx) + ")")


	# send a message to a recipient
	elif argv[0] == "send" or argv[0] == "msg":

		nick = ""
		msg = ""

		if argc < 2:
			wOut(PSS_BUFPFX_ERROR, [bufs[pssName]], "!!!", "not enough arguments for send")
			return weechat.WEECHAT_RC_ERROR

		nick = argv[1]
		if argc > 2:
			msg = " ".join(argv[2:])
	
		# \todo handle hex address only	
		if not currentPss.have_nick(nick):
			wOut(PSS_BUFPFX_ERROR, [bufs[pssName]], "!!!", "invalid nick " + nick)
			return weechat.WEECHAT_RC_ERROR

		buf = buf_get(pssName, "chat", nick, True)
		# \todo remove the bufs dict, since we can use weechat method for getting it
		bufs[weechat.buffer_get_string(buf, "name")] = buf

		# if no message body we've just opened the chat window
		if msg != "":
			if not pss.is_message(msg):
				wOut(PSS_BUFPFX_DEBUG, [bufs[pssName]], "", "invalid message " + msg)
				return weechat.WEECHAT_RC_ERROR
			return buf_in(pssName, buf, msg)


	# create/join existing chat room
	elif argv[0] == "join":

		room = ""

		if argc < 2:
			wOut(PSS_BUFPFX_ERROR, [bufs[pssName]], "!!!", "not enough arguments for join")
			return weechat.WEECHAT_RC_ERROR

		room = argv[1]

		wOut(PSS_BUFPFX_DEBUG, [], "!!!", "in join " + pssName)	
		buf = buf_get(pssName, "room", room, True)


	# invite works in context of chat rooms, and translates in swarm terms to
	# adding one separate feed encoded with the invited peer's key
	# room argument can be omitted if command is issued om channel to invite to
	# note feeds are currently unencrypted
	elif argv[0] == "invite":

		nick = ""
		roomname = ""

		if argc < 2:
			wOut(PSS_BUFPFX_ERROR, [bufs[pssName]], "!!!", "not enough arguments for invite")

		# if missing channel argument get bufname command was issued in
		# and derive channel name from it if we can (fail if not)
		elif argc < 3:
			if ctx['t'] != PSS_BUFTYPE_ROOM:
				wOut(PSS_BUFPFX_ERROR, [bufs[pssName]], "!!!", "unknown channel '" + ctx['t'] + "'")
				return weechat.WEECHAT_RC_ERROR
			roomname = ctx['h']
	
		else:
			roomname = argv[2]

		nick = argv[1]

		# check if room exists
		# if it does, perform invitation
		try:
			roombufname = buf_generate_name(pssName, "room", roomname)
			room = rooms[roombufname]	
			pss_invite(pssName, nick, room)

			wOut(PSS_BUFPFX_DEBUG, [], "!!!", "added " + nick + " to " + roomname)
			# if neither the previous fail, add the nick to the buffer
			roombuf = weechat.buffer_search("python", roombufname)
			buf_room_add(roombuf, nick)

		except KeyError as e: # keyerror catches both try statements
			wOut(PSS_BUFPFX_ERROR, [buf], "!!!", "Unknown room or nick: " + str(e))


	# output node key
	elif argv[0] == "key" or argv[0] == "pubkey":
		wOut(PSS_BUFPFX_INFO, [bufs[pssName]], pssName + ".key", currentPss.get_public_key().encode("hex"))


	# output node base address
	elif argv[0] == "addr" or argv[0] == "address":
		wOut(PSS_BUFPFX_INFO, [bufs[pssName]], pssName + ".addr", currentPss.get_overlay().encode("hex"))


	# set nick for pss node
	elif argv[0] == "nick":
		try:
			if len(argv) > 1:
				nick = pss.clean_nick(argv[1])
				selfs[pssName].nick = nick
			wOut(PSS_BUFPFX_INFO, [bufs[pssName]], pssName, "nick is '" + selfs[pssName].nick + "'")
		except ValueError as e:
			wOut(PSS_BUFPFX_ERROR, [bufs[pssName]], "!!!", "Invalid nick: " + argv[1])
			
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
