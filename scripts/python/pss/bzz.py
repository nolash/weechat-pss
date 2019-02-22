import struct
import json
import sys
import copy

from Crypto.Hash import keccak
from urllib import urlencode

from tools import now_int
from message import Message


# signPrefix = "\x19Ethereum Signed Message:\x0a\x20" # for 32 byte hashes

# application-specific topic root
# all topics used for feed updates are derived from this
feedRootTopic = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00psschats\x00\x00\x00\x00"

# a zerohash is used as a null-pointer in linked lists of swarm content
zerohsh = ""
for i in range(32):
	zerohsh += "\x00"

# exception to specify error in swarm content retrieval
class BzzRetrieveError(Exception):

	def __init__(self, hsh, reason):
		super(BzzRetrieveError, self).__init__(reason)
		self.hsh = hsh
		
	pass


# Bzz is a convenience wrapper for making swarm store and retrieve calls over http
class Bzz():


	def __init__(self, httpagent):
		self.agent = httpagent


	def add(self, data):
		return self.agent.send("/bzz-raw:/", data)


	def get(self, hsh):
		return self.agent.get("/bzz-raw:/" + hsh + "/")


	def close(self):
		pass
	


# Feed represents a single swarm feed
#
# It can represent both a consumer and publisher feed.
#
# To create a feed to which updates may be posted, the account passed to the constructor must contain the private key for the feed account.
class Feed():


	def __init__(self, bzz, account, name):
		self.tim = 0
		self.lastepoch = 25
		self.lastupdate = 0
		self.topic = ""

		self.account = account
		self.bzz = bzz
		if len(name) > 32 or len(name) == 0:
			raise ValueError("invalid name length 0 < n <= 32")

		self.topic = new_topic_mask(feedRootTopic, name, "")


	# retrieve epoch and time next update belongs to
	# \todo client side should calculate this after initial state gotten from feed
	def info(self):
		q = {
			'user': '0x' + self.account.address.encode("hex"),
			'topic': '0x' + self.topic.encode("hex"),
			'meta': '1',
		}
		querystring = urlencode(q)
		sendpath = "/bzz-feed:/"
		rstr = self.bzz.agent.get(sendpath, querystring)
		r = ""
		try:
			r = json.loads(rstr)
		except Exception as e:
			sys.stderr.write("ouch: '" + rstr + "'\n")
			raise ValueError("json fail: " + repr(e))
		return (r['epoch']['time'], r['epoch']['level'])
			

	# update the feed
	# data is raw bytes
	def update(self, data):
		(tim, epoch) = self.info()
		d = compile_digest(self.topic, self.account.address, data, int(tim), int(epoch))
		s = sign_digest(self.account.privatekey, d)
		q = {
			'user': "0x" + self.account.address.encode("hex"),
			'topic': "0x" + self.topic.encode("hex"),
			'signature': "0x" + s.encode("hex"),
			'level': epoch,
			'time': tim,
		}
		querystring = urlencode(q)
		sendpath = "/bzz-feed:/"
		r = self.bzz.agent.send(sendpath, data, querystring)
	
		self.lastupdate = tim
		self.epoch = epoch

		return r


	# get the last update of a feed
	def head(self):
		q = {
			'user': '0x' + self.account.address.encode("hex"),
			'topic': '0x' + self.topic.encode("hex"),
		}
		querystring = urlencode(q)
		sendpath = "/bzz-feed:/"
		return self.bzz.agent.get(sendpath, querystring)
		


# wrapper for individual feeds in collections
# contains index keeping track of position of last lookup
# it also keeps track of broken links
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

	# increments last time of update. if same second as last, sequence number is incremented
	def next(self):
		tim = now_int()
		seq = 0
		if tim == self.lasttime:
			self.lastseq = (state.lastseq + 1) & 0xff
		else:
			self.lasttime = tim
			self.lastseq = 0

	def serial(self):
		return struct.pack(">I", self.lasttime) + struct.pack("B", self.lastseq)



# Convenience class for handling feed aggregation and content linking 
# A collection may have many feeds for reading, for which all new updates can be retrieved by one single method call
# The collection may also have a sender feed, through which updates may be sent. This requires an account object with a private key set.
#
# Updates handled through the feedcollection object are linked lists. The feed update points to swarm content, and the payload of the swarm content is:
# [00 - 31]: swarm hash of previous update
# [32 - 36]: serial number; 4 byte timestamp (seconds) + 1 byte sequence number (in increments for updates within same timestamps)
# [37 - n ]: content; arbitrary bytes
#
# The state of sender and reader feeds is the last swarm hash seen. It is stored for every retrieval or send. 
# Upon retrieval all new updates will be retrieved until the last seen hash is encountered, and the state is reset to the hash of the newest update.
class FeedCollection:



	# if senderfeed is passed, writing to this collection is enabled
	def __init__(self, name, senderfeed=None):
		self.name = name
		self.feeds = {}
		self.retrievals = []
		if senderfeed != None:
			self.senderfeed = FeedState(senderfeed)



	# returns the name of the collection
	def get_name(self):
		return self.name



	# makes a single update with the passed data
	# the update will contain a link to the previous update
	def write(self, data):

		senderstate = self.senderfeed
		if senderstate == None:
			raise RuntimeError("sender feed required")

		if not senderstate.obj.account.is_owner():
			raise RuntimeError("private key required")
				
		# \todo this is wrong - headhsh will always be empty for rooms, but will have last hash for chats. headhsh needs to be renamed to not mistake it for pointing to head position at all times
		lasthsh = senderstate.lasthsh
		senderstate.next()
		headhsh = senderstate.obj.bzz.add(lasthsh + senderstate.serial() + data)	
		senderstate.lasthsh = headhsh.decode("hex")
	
		return headhsh



	# adds a feed to the collection
	def add(self, name, feed):
		if name in self.feeds:
			raise Exception("feed already exists with name '" + repr(name) + "'")

		self.feeds[name] = FeedState(feed)



	# removes a feed from the collection
	def remove(self, name):
		del self.feeds[name]



	# get all updates retrieved by last syncings
	# the array of messages is an aggregate of all reader feeds, sorted by time of update 
	# the call will remove the updates from the buffer
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
			for s, m in feedmsgs[k].iteritems():
				msgs[str(s) + k] = m

		for m in sorted(msgs):
			msgssorted.append(msgs[m])

		return msgssorted



	# syncs all reader feeds with the latest updates and stored them in a buffer
	# the messages can be retrieved with get()
	#
	# \todo make sure this completes or fully abandons retrieves before returning
	def gethead(self, bzz):

		# hash map eth address => hash map serial to Message 
		feedmsgs = {}

		for feedname in self.feeds.keys(): # feedstate in self.feeds.values():

			feedstate = self.feeds[feedname]
			# headhsh will be empty string 
			# between completed retrieves
			# we then need to get the new head hash
			# the feed is currently pointing to
			if feedstate.headhsh == "":
				try:
					feedstate.headhsh = feedstate.obj.head()
				except:
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
		return len(self.retrievals)-1

	
	
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



# create a message digest to be signed for feed update
# input here is raw bytes not hex
def compile_digest(topic, user, inputdata, tim, epoch=1):

	# protocolversion + padding 7 bytes
	data = "\x00\x00\x00\x00\x00\x00\x00\x00"

	# topic bytes
	data += topic

	# user account bytes
	data += user

	# time now little endian
	# time is 7 bytes, actually
	data += struct.pack("<L", tim)
	data += "\x00\x00\x00"

	# ... so we put the epoch on the eigth
	data += chr(epoch)

	# add the data itself
	data += inputdata

	# fire up hasher	
	h = keccak.new(digest_bits=256)
	h.update(data)
	return h.digest()



# sign a digest with given private key to use for feed update
def sign_digest(pk, digest):
	sig = pk.ecdsa_sign_recoverable(digest, raw=True)
	s, r =  pk.ecdsa_recoverable_serialize(sig)
	s += chr(r)
	return s



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


# check if input is valid feed topic
def is_valid_topic(topic):
	return len(topic) == 32



# check if input is a valid feed account address
def is_valid_account(user):
	return len(user) == 20



# check if input is a valid feed digest
def is_digest(digest):
	return len(digest) == 32

chattopic = new_topic_mask(zerohsh, "", "\x01")
roomtopic = new_topic_mask(zerohsh, "", "\x02")

