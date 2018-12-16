import struct

from Crypto.Hash import keccak
from urllib import urlencode

from tools import now_int


signPrefix = "\x19Ethereum Signed Message:\x0a\x20" # for 32 byte hashes
feedRootTopic = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x02\x02awesomepsschats\x00\x01"


class Bzz():
	agent = None

	def __init__(self, httpagent):
		self.agent = httpagent

	def add(self, data):
		return self.agent.send("/bzz-raw:/", data)
	

class Feed():
	agent = None
	account = None
	tim = 0
	epoch = 25
	lastupdate = 0
	topic = ""


	# \todo get last update from node
	def __init__(self, httpagent, account, name, single=True):
		self.account = account
		self.agent = httpagent
		#name = name.encode("ascii")
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


	# data is raw bytes
	# \todo and epoch calculate
	def update(self, data):
		epoch = self.get_epoch()
		tim = now_int()
		d = compile_digest(self.topic, self.account.address, data, tim, epoch)
		s = sign_digest(self.account.pk, d)
		q = {
			'user': "0x" + self.account.address.encode("hex"),
			'topic': "0x" + self.topic.encode("hex"),
			'signature': "0x" + s.encode("hex"),
			'level': str(epoch),
			'time': str(tim),
		}
		querystring = urlencode(q)
		sendpath = "/bzz-feed:/"
		r = ""
		try:
			r = self.agent.send(sendpath, data, querystring)
		except Exception as e:
			raise e	
	
		self.lastupdate = tim
		self.epoch = epoch

		return r	
			


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

