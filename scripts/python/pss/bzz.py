import struct
import json

from Crypto.Hash import keccak
from urllib import urlencode

from tools import now_int
from message import Message


signPrefix = "\x19Ethereum Signed Message:\x0a\x20" # for 32 byte hashes
feedRootTopic = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x02\x02awesomepsschats\x00\x01"
zerohsh = ""
for i in range(32):
	zerohsh += "00"


# \todo pass agent to all methods instead of storing
class Bzz():
	agent = None

	def __init__(self, httpagent):
		self.agent = httpagent

	def add(self, data):
		return self.agent.send("/bzz-raw:/", data)

	def get(self, hsh):
		return self.agent.get("/bzz-raw:/" + hsh + "/")



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


	# \todo implement
	def get_epoch(self):
		return 1


	
	def sync(self):
		(tim, level) = self.info()
		self.lastupdate = int(tim)
		self.lastepoch = int(level)


	def info(self):
		q = {
			'user': '0x' + self.account.address.encode("hex"),
			'topic': '0x' + self.topic.encode("hex"),
			'meta': '1',
		}
		querystring = urlencode(q)
		sendpath = "/bzz-feed:/"
		r = json.loads(self.agent.get(sendpath, querystring))
		return (r['epoch']['time'], r['epoch']['level'])
			

	# data is raw bytes
	# \todo client side next epoch calc (retrieve from server is WAY too slow)
	def update(self, data):
		(tim, epoch) = self.info()
		d = compile_digest(self.topic, self.account.address, data, int(tim), int(epoch))
		s = sign_digest(self.account.pk, d)
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


	def head(self):
		q = {
			'user': '0x' + self.account.address.encode("hex"),
			'topic': '0x' + self.topic.encode("hex"),
		}
		querystring = urlencode(q)
		sendpath = "/bzz-feed:/"
		return self.agent.get(sendpath, querystring)
			


class FeedCollection:
	feeds = {}


	def add(self, name, feed):
		if name in self.feeds:
			raise Exception("feed already exists")

		self.feeds[name] = {

			# feed object
			"obj": feed,

			# head of the current retrieve
			"headhash": "",

			# head from previous update
			"lasthash": zerohsh,
	
			# timestamp of last processed head
			"lasttime": 0,	
		}


	def remove(self, name):
		del self.feeds[name]


	# \todo make sure this completes or fully abandons retrieves before returning
	def retrieve(self, bzz):
	
		feedmsgs = {}

		for name, feed in self.feeds.iteritems():

			msgs = {}

			# headhash will be empty string 
			# between completed retrieves
			# we then need to get the new head hash
			# the feed is currently pointing to
			if feed['headhash'] == "":
				try:
					feed['headhash'] = feed['obj'].head()
				except:
					continue

			curhash = feed['headhash']
			print "headhash " + feed['headhash']

			if curhash == "":
				continue

			# we break out of loop when we reach the previous head	
			while curhash != feed['lasthash']:
				# \todo probably need bet,er error reporting here
				r = bzz.get(curhash)
				if r == "":
					# \todo what to do when the trail goes cold
					break
				curhash = r[:64]
				serial = r[64:69] # 4 bytes time + 1 byte serial
				content = r[69:]	
				msgs[serial] = Message(serial, feed['obj'].account.address, content)
			
			# store new messages for feed	 	
			feedmsgs[feed['obj'].account.address] = msgs

			# set next retrieve to terminate on
			feed['lasthsh'] = feed['headhash']
			feed['headhash'] = ""

		return feedmsgs


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

