import struct
import json
import sys
import copy
import codecs

from Crypto.Hash import keccak
from urllib.parse import urlencode

from .tools import now_int
from .message import Message


# this is not used for swarm feeds for the time being
# signPrefix = "\x19Ethereum Signed Message:\x0a\x20" # for 32 byte hashes

feedRootTopic = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00psschats\x00\x00\x00\x00"

# a zerohash is used as a null-pointer in linked lists of swarm content
zerohsh = ""
for i in range(32):
	zerohsh += "\x00"


## \brief Generate Swarm Feed topic
#
# Derive a new Swarm feed topic from an existing topic using XOR
#
# \param base Topic bytes to derive from
# \param prefix High-order bytes to XOR
# \param postfix Low-order bytes to XOR
def new_topic_mask(base, prefix, postfix):
	topic = ""
	for i in range(32):
		b = 0
		if i < len(base):
			b = b | ord(base[i])
		if i < len(prefix):
			b = ord(prefix[i]) | b
		l = 32-len(postfix)
		if i >= l:
			b = ord(postfix[i-l]) | b
		topic += chr(b)
	return topic


# the last topic byte is used as bitflag to allow to determine context from the topic
chattopic = new_topic_mask(zerohsh, "", "\x01")
roomtopic = new_topic_mask(zerohsh, "", "\x02")

## Exception to specify error in swarm content retrieval
class BzzRetrieveError(Exception):

	## \param hsh Swarm hash error occurred for
	# \param reason Error string
	def __init__(self, hsh, reason):
		super(BzzRetrieveError, self).__init__(reason)
		self.hsh = hsh
		
	pass


## \brief Swarm context for HTTP
#
# Bzz is a convenience wrapper for making swarm store and retrieve calls over http
class Bzz():


	def __init__(self, httpagent):
		self.agent = httpagent


	## Create new raw data chunk
	#
	# \param data binary data to post
	# \return Swarm chunk hash, binary format
	# \todo translate hex string to bytes before return
	def add(self, data):
		return self.agent.send("/bzz-raw:/", data)


	## Retrieve raw data chunk
	#
	# \param hsh Swarm hash to retrieve, binary format
	# \return Raw response data
	def get(self, hsh):
		return self.agent.get("/bzz-raw:/" + hsh + "/")


	## \brief close connection
	#
	# \todo is currently noop
	def close(self):
		pass
	


## A single Swarm Feed
#
# It can represent both a consumer and publisher feed.
#
# To create a feed to which updates may be posted, the account passed to the constructor must contain the private key for the feed account.
#
# All feeds in this application use topics that are derived from the following base topic:
#
# 0x0000000000000000000000000000000000000000707373636861747300000000
#
# \todo use bytes instead of str for topics
class Feed():


	## \param bzz Swarm transport object
	# \param account Account object containing key to use for Feed (must have private key for write access)
	# \param name Human name of feed, XORed with high-order bits of base topic to create feed topic, up to 31 bytes
	def __init__(self, bzz, account, name):
		self.tim = 0
		self.lastepoch = 25
		self.lastupdate = 0
		self.topic = ""

		self.account = account
		self.bzz = bzz
		if len(name) > 32 or len(name) == 0:
			raise ValueError("invalid name length 0 < n <= 32 {}", name)

		self.topic = new_topic_mask(feedRootTopic, name, "")


	## Get epoch and time for next update
	#
	# retrieve epoch and time next update belongs to from swarm node
	#
	# \return Tuple; (time, level), numerical
	# \todo client side should calculate this after initial state gotten from feed
	def info(self):
		q = {
			'user': '0x' + self.account.address.hex(), #codecs.encode(self.account.address, "hex")),
			'topic': '0x' + bytes(self.topic, "ascii").hex(),
			'meta': '1',
		}
		querystring = codecs.decode(urlencode(q).encode("utf-8"), "ascii")
		sendpath = "/bzz-feed:/"
		rstr = self.bzz.agent.get(sendpath, querystring)
		r = ""
		try:
			r = json.loads(rstr)
		except Exception as e:
			sys.stderr.write("ouch: '" + rstr + "'\n")
			raise ValueError("json fail: " + repr(e))
		return (r['epoch']['time'], r['epoch']['level'])
			

	## Add new update to feed
	#
	# \param data raw byte data to post as update
	# \return (unsure)
	# \todo find out what this returns
	def update(self, data):
		(tim, epoch) = self.info()
		d = compile_digest(self.topic, self.account.address, data, int(tim), int(epoch))
		s = sign_digest(self.account.privatekey, d)
		q = {
			'user': "0x" + self.account.address.hex(),
			'topic': "0x" + bytes(self.topic, "ascii").hex(),
			'signature': "0x" + s.hex(),
			'level': epoch,
			'time': tim,
		}
		querystring = codecs.decode(urlencode(q).encode("utf-8"), "ascii")
		sendpath = "/bzz-feed:/"
		r = self.bzz.agent.send(sendpath, data, querystring)
	
		self.lastupdate = tim
		self.epoch = epoch

		return r


	## Get latest feed update
	#
	# \return Update content, binary format
	def head(self):
		q = {
			'user': '0x' + self.account.address.hex(), 
			'topic': '0x' + bytes(self.topic, "ascii").hex(),
		}
		# jeez...
		querystring = urlencode(q)
		sendpath = "/bzz-feed:/"
		d = self.bzz.agent.get(sendpath, querystring)
		print("topic", self.topic, querystring)
		return d
		


## \brief Individual feed metadata for collections
#
# FeedState is a wrapper for individual feeds in a FeedCollection object
#
# It holds an index keeping track of position of last lookup
#
# It also keeps track of broken links for the purpose of later retries
#
# \todo the use of this object is slightly different in reader and sender context, should be revised to make the use identical
class FeedState:
	def __init__(self, feed):
		self.obj = feed
		self.headhsh = ""
		self.lasthsh = zerohsh
		self.lasttime = 0
		self.lastseq = 0
		self.orphans = {}
		self.active = True


	## \brief Get next update index
	#
	# Sets the last update timestamp to current time. If same timestamp as last update, serial is incremented.
	def next(self):
		tim = now_int()
		seq = 0
		if tim == self.lasttime:
			self.lastseq = (state.lastseq + 1) & 0xff
		else:
			self.lasttime = tim
			self.lastseq = 0

	## \brief Serialize update index
	#
	# \return 5 bytes; 4 byte little-endian timestamp, 1 byte serial
	def serial(self):
		return struct.pack("<I", self.lasttime) + struct.pack("B", self.lastseq)



## Convenience class for handling feed aggregation and content linking 
#
# A collection may have many feeds for reading, for which all new updates can be retrieved by one single method call
#
# The collection may also have a sender feed, through which updates may be sent. This requires an account object with a private key set.
#
# Updates handled through the feedcollection object are linked lists. The feed update points to swarm content, and the payload of the swarm content is:
#
# [00 - 31]: swarm hash of previous update
# [32 - 36]: serial number; 4 byte timestamp (seconds) + 1 byte sequence number (in increments for updates within same timestamps)
# [37 - n ]: content; arbitrary bytes
#
# The state of sender and reader feeds is the last swarm hash seen. It is stored for every retrieval or send. 
#
# Upon retrieval all new updates will be retrieved until the last seen hash is encountered, and the state is reset to the hash of the newest update.
# \todo python3 refactor; use bytes instead of string to store hashes
class FeedCollection:



	## \param name Name of collection later if senderfeed is passed, writing to this collection is enabled
	def __init__(self, name, senderfeed=None):
		self.name = name
		self.feeds = {}
		self.retrievals = []
		if senderfeed != None:
			self.senderfeed = FeedState(senderfeed)



	## \brief Get name of collection
	#
	# \return Name stirng
	# \todo not needed
	def get_name(self):
		return self.name



	## \brief Post update to room
	#
	# Makes a single update with the passed data
	#
	# The update will contain a link to the previous update
	#
	# \param data raw data to post 
	# \bug headhsh will always be empty for rooms, but will have last hash for chats. headhsh needs to be renamed to not mistake it for pointing to head position at all times
	# \todo evaluate whether bug is stale
	def write(self, data):

		senderstate = self.senderfeed
		if senderstate == None:
			raise RuntimeError("sender feed required")

		if not senderstate.obj.account.is_owner():
			raise RuntimeError("private key required")
				
		lasthsh = senderstate.lasthsh
		senderstate.next()
		writedata = lasthsh.encode("ascii") + senderstate.serial() + data
		headhsh = senderstate.obj.bzz.add(writedata)
		senderstate.lasthsh = codecs.decode(headhsh, "hex")
	
		return headhsh



	## \brief Add feed to the collection
	# 
	# This adds a feed to the collection of feeds to be polled for updates. 
	#
	# \see FeedCollection.activate
	# \param name Internal key to store feed under
	# \param feed Feed object
	def add(self, name, feed):
		if name in self.feeds:
			raise Exception("feed already exists with name '" + repr(name) + "'")

		self.feeds[name] = FeedState(feed)



	## \brief Activate feed in collection
	# 
	# After this is called, the selected feed will be polled for updates
	#
	# \param name Internal key of feed
	def activate(self, name):
		self.feeds[name].active = True



	## \brief Remove feed from collection
	# 
	# \param name Internal key of feed
	def remove(self, name):
		del self.feeds[name]



	## \brief Drain latest update buffer
	#
	# Gets all updates retrieved by last syncings
	#
	# The array of messages is an aggregate of all reader feeds, sorted by time of update 
	#
	# Removes the updates from the buffer
	#
	# \param idx Array index to start retrieval from
	# \return Array of message objects
	# \see FeedCollection.gethead
	# \todo evaulate if idx is useful
	def get(self, idx=-1):

		msgs = {}
		msgssorted = []

		if idx == -1:
			if len(self.retrievals) == 0:
				return []
			idx = len(self.retrievals)-1	
	
		feedmsgs = self.retrievals.pop(idx)

		# \todo refactor to use keys function in sorted
		for k in feedmsgs.keys():
			for s, m in feedmsgs[k].items():
				msgs[str(s) + k] = m

		for m in sorted(msgs):
			msgssorted.append(msgs[m])

		return msgssorted



	## \brief Retrieve latest updates to buffer
	#
	# Syncs all reader feeds with the latest updates and stored them in a buffer
	# 
	# The messages can be retrieved with get()
	#
	# \param bzz Swarm connection object
	# \param deactivateonfail Deactivates a feed if updates can't be retrieved for it
	# \return Tuple; number of feeds have new messages, and an array of accounts for feeds that we w not retrievable
	# \see FeedCollection.get
	# \todo make sure this completes or fully abandons retrieves before returning
	def gethead(self, bzz, deactivateonfail=True):

		# hash map eth address => hash map serial to Message 
		feedmsgs = {}
		fails = []

		for feedname in self.feeds.keys(): # feedstate in self.feeds.values():
	
			feedstate = self.feeds[feedname]
			if not feedstate.active:
				continue

			# headhsh will be empty string 
			# between completed retrieves
			# we then need to get the new head hash
			# the feed is currently pointing to
			if feedstate.headhsh == "":
				try:
					feedstate.headhsh = feedstate.obj.head()
				except:
					if deactivateonfail:
						feedstate.active = False
					fails.append(feedstate.obj.account)
					continue

			#sys.stderr.write("headhsh " + feedstate.headhsh.encode("hex") + "\n")

			if feedstate.headhsh == "":
				continue
				
			# store new messages for feed
			(msgs, brk) = self._retrieve(bzz, feedstate.obj.account, feedstate.headhsh, feedstate.lasthsh)
			feedmsgs[feedstate.obj.account.get_address()] = msgs
			if brk != None:
				sys.stderr.write("retrieve fail on hash: " + str(brk) + "\n")
				feedstate.lasthsh = brk
				feedstate.orphans[feedstate.headhsh] = feedstate.lasthsh

			# set next retrieve to terminate on
			feedstate.lasthsh = feedstate.headhsh
			feedstate.headhsh = ""
	
		self.retrievals.append(feedmsgs)
		return (len(self.retrievals)-1, fails)

	
	
	# private function for traversing linked list until target hash (or zerohash) is found 	
	# if one lookup fails, the contents retrieved up until that point is returned
	def _retrieve(self, bzz, feedaddress, curhsh, targethsh):

		# hash map serial (timestamp+seq) => Message
		msgs = {}

		# we break out of loop when we reach the previous head	
		while curhsh != targethsh and curhsh != zerohsh:
			try:
				r = bzz.get(curhsh.encode("hex"))
			except Exception as e:
				sys.stderr.write("request fail: " + repr(e) + "\n")
				return (msgs, curhsh)
				#raise BzzRetrieveError(curhsh, str(e))
			if r == "":
				return (msgs, curhsh)
				#raise BzzRetrieveError(curhsh, "empty HTTP response body")

			curhsh = r[:32]
			serial = r[32:37] # 4 bytes time + 1 byte serial
			content = r[37:]	
			msgs[serial] = Message(serial, feedaddress, content)

		return (msgs, None)



## \brief Create Swarm Feed message digest
# 
# Create a message digest to be signed for feed update
#
# \param topic Swarm Feed 32-byte topic
# \param user Account object 
# \param inputdata Binary data to create digest for
# \param tim Timestamp for update
# \param epoch Epoch for update
# \return Swarm Feed digest hash, binary format
# \see sign_digest
# \todo should take Account instead of "user" bytes
# \todo inputs should be bytes not string
def compile_digest(topic, user, inputdata, tim, epoch=1):

	# protocolversion + padding 7 bytes
	data = b'\x00\x00\x00\x00\x00\x00\x00\x00'

	# topic bytes
	data += codecs.encode(topic, "ascii")

	# user account bytes
	data += user

	# time now little endian
	# time is 7 bytes, actually
	data += struct.pack("<L", tim)
	data += b'\x00\x00\x00'

	# ... so we put the epoch on the eigth
	data += epoch.to_bytes(1, sys.byteorder)

	# add the data itself
	data += inputdata

	# fire up hasher	
	h = keccak.new(digest_bits=256)
	h.update(data)
	return h.digest()



## sign a digest with given private key to use for feed update
def sign_digest(pk, digest):
	sig = pk.ecdsa_sign_recoverable(digest, raw=True)
	s, r =  pk.ecdsa_recoverable_serialize(sig)
	s += r.to_bytes(1, sys.byteorder)
	return s



## Check if input is valid feed topic
#
# \return True; valid topic
def is_valid_topic(topic):
	return len(topic) == 32



## Check if input is a valid feed account address
# 
# \return True; valid address
def is_valid_account(user):
	return len(user) == 20



## Check if input is a valid feed digest
#
# \return True; valid digest
def is_digest(digest):
	return len(digest) == 32

