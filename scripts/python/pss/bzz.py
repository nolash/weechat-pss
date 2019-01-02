import struct
import json
import sys

from Crypto.Hash import keccak
from urllib import urlencode

from tools import now_int
from message import Message


signPrefix = "\x19Ethereum Signed Message:\x0a\x20" # for 32 byte hashes
feedRootTopic = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00psschats\x00\x00\x00\x01"
zerohsh = ""
for i in range(32):
	zerohsh += "00"
zerohshbytes = zerohsh.decode("hex")

class BzzRetrieveError(Exception):
	hsh = ""

	def __init__(self, hsh, reason):
		super(BzzRetrieveError, self).__init__(reason)
		self.hsh = hsh
		
	pass

# Bzz is a convenience wrapper for making swarm store and retrieve calls over http
# \todo pass agent to all methods instead of storing
class Bzz():
	agent = None

	def __init__(self, httpagent):
		self.agent = httpagent

	def add(self, data):
		return self.agent.send("/bzz-raw:/", data)

	def get(self, hsh):
		return self.agent.get("/bzz-raw:/" + hsh + "/")


# FeedUpdate encapsulates a single update to be sent on the network
class FeedUpdate:
	name = ""
	data = ""
	typ = ""
	nod = ""

	def __init__(self, nod, typ, name, data):
		self.typ = typ
		self.name = name
		self.data = data
		self.nod = nod

	

# Feed represents a single swarm feed
#
# It can represent both a consumer and publisher feed.
#
# To create a feed to which updates may be posted, the account passed to the constructor must contain the private key for the feed account.
#
# The isoutput argument sets or unsets the last bit of the feed topic, marking whether the feed is an output feed or an input feed. 
# Note that a publisher feed may still be an input feed; in this case the client is listening to another publisher.
#
# \todo pass agent to all methods instead of storing
class Feed():
	agent = None
	account = None
	tim = 0
	lastepoch = 25
	lastupdate = 0
	topic = ""


	def __init__(self, httpagent, account, name, single=True):
		self.account = account
		self.agent = httpagent
		if len(name) > 32 or len(name) == 0:
			raise ValueError("invalid name length 0 < n <= 32")
		for i in range( len(feedRootTopic)):
			if i < len(name):
				self.topic += chr(ord(feedRootTopic[i]) ^ ord(name[i]))
			else:
				self.topic += feedRootTopic[i]


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
		rstr = self.agent.get(sendpath, querystring)
		r = ""
		try:
			r = json.loads(rstr)
		except:
			sys.stderr.write("ouch: " + rstr + "\n")
			raise ValueError("json fail")
		return (r['epoch']['time'], r['epoch']['level'])
			

	# update the feed
	# data is raw bytes
	# \todo client side next epoch calc (retrieve from server is WAY too slow)
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
		r = self.agent.send(sendpath, data, querystring)
	
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
		return self.agent.get(sendpath, querystring)
			


# convenience class for handling feed aggregation (multiuser room, for instance)
class FeedCollection:
	feeds = None
	retrievals = None

	def __init__(self):
		self.feeds = {}
		self.retrievals = []

	def add(self, name, feed):
		if name in self.feeds:
			raise Exception("feed already exists")

		self.feeds[name] = {

			# feed object
			"obj": feed,

			# head of the current retrieve
			"headhsh": "",

			# head from previous update
			"lasthsh": zerohsh,
	
			# timestamp of last processed head
			"lasttime": 0,	

			"orphans": {}, # orphaned key => target key
		}


	def remove(self, name):
		del self.feeds[name]


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


	# \todo make sure this completes or fully abandons retrieves before returning
	def gethead(self, bzz):

		# hash map eth address => hash map serial to Message 
		feedmsgs = {}

		for k in self.feeds:
			sys.stderr.write("found key: " + k + "\n")

		for feed in self.feeds.values():

			# headhsh will be empty string 
			# between completed retrieves
			# we then need to get the new head hash
			# the feed is currently pointing to
			if feed['headhsh'] == "":
				try:
					feed['headhsh'] = feed['obj'].head().decode("hex")
				except:
					continue

			sys.stderr.write("headhsh " + feed['headhsh'] + "\n")

			if feed['headhsh'] == "":
				continue
				
			# store new messages for feed
			try:
				feedmsgs[feed['obj'].account.address] = self._retrieve(bzz, feed['obj'].account, feed['headhsh'], feed['lasthsh'])
			except BzzRetrieveError as e:
				sys.stderr.write("retrieve fail: " + str(e))
				feed['lasthsh'] = e.hsh
				feed['orphans'][feed['headhsh']] = feed['lasthsh']

			# set next retrieve to terminate on
			feed['lasthsh'] = feed['headhsh']
			feed['headhsh'] = ""

		self.retrievals.append(feedmsgs)
		return len(self.retrievals)-1

	
	def _retrieve(self, bzz, feedaddress, curhsh, targethsh):

		# hash map serial (timestamp+seq) => Message
		msgs = {}

		# we break out of loop when we reach the previous head	
		while curhsh != targethsh and curhsh != zerohshbytes:
			try:
				r = bzz.get(curhsh.encode("hex"))
			except Exception as e:
				sys.stderr.write("request fail: " + str(e) + "\n")
				raise BzzRetrieveError(curhsh, str(e))
			if r == "":
				raise BzzRetrieveError(curhsh, "empty HTTP response body")
			curhsh = r[:32]
			serial = r[32:36] # 4 bytes time + 1 byte serial
			content = r[36:]	
			msgs[serial] = Message(serial, feedaddress, content, r)

		return msgs

def sign_digest(pk, digest):
	sig = pk.ecdsa_sign_recoverable(digest, raw=True)
	s, r =  pk.ecdsa_recoverable_serialize(sig)
	s += chr(r)
	return s



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



def is_valid_topic(topic):
	return len(topic) == 32



def is_valid_account(user):
	return len(user) == 20



def is_digest(digest):
	return len(digest) == 32

