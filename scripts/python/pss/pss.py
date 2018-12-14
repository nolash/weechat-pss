import websocket

from tools import is_address, is_pubkey, label
from error import *
from content import rpc_call, rpc_parse
from contact import PssContact

# topic we will be using for this messenger service
topic = "0xdeadbee2"

# object encapsulating pss node connection
# \todo move to separate package
# \todo remove direct websocket comms and get node key and addr from background process
class Pss:
	host = "127.0.0.1"
	port = "8546"
	connected = False
	inputConnected = False
	base = ""
	key = ""
	err = 0
	errstr = ""
	contacts = {}
	seq = 0
	ws = None
	name = ""
	run = False
	buf = None
	sub = ""


	def __init__(self, name, host="127.0.0.1", port="8546"):
		""" set the pss instance name and create the fifo for catching msgs from subprocess
		"""
		self.name = name
		if host != "":
			self.host = host
		if port != "":
			self.port = port
		

	# open sockets and get initial data
	def connect(self):

		self.ws = None
		try:
			self.ws = websocket.create_connection("ws://" + self.host + ":" + self.port)
		except Exception as e:
			self.err = PSS_ESOCK
			self.errstr = "could not connect to pss " + self.name + " on " + self.host + ":" + self.port + ": " + repr(e)
			return False

		# get the node adress	
		self.ws.send(rpc_call(self.seq, "baseAddr", []))
		self.seq += 1
		resp = rpc_parse(self.ws.recv())

		# verify address
		if not is_address(resp['result']):
			self.err = PSS_EREMOTEINVAL
			self.errstr = "received bogus base address " + resp['result']
			return False
		base = resp['result']
		
		# retrieve the node key	data
		self.ws.send(rpc_call(self.seq, "getPublicKey", []))
		self.seq += 1
		resp = rpc_parse(self.ws.recv())
	
		# verify key
		if not is_pubkey(resp['result']):
			self.err = PSS_EREMOTEINVAL
			self.errstr = "received bogus pubkey " + resp['result']
			return False

		key = resp['result']

		# subscribe to incoming
		self.ws.send(rpc_call(self.seq, "subscribe", ['receive', topic, False, False]))
		self.seq += 1
		resp = rpc_parse(self.ws.recv())
		self.sub = resp['result']

		# now we're in the clear
		# finish setting up object properties
		self.key = key
		self.base = base
		self.connected = True
		self.run = True
				
		return True


	
	def setBuf(self, buf):
		self.buf = buf	



	# adds recipient to node
	def add(self, nick, pubkey, address):

		# holds the newly created contact object
		contact = None

		# brief address and key for display in buffer
		addrLabel = ""
		keyLabel = ""

		# no use if we're not connected
		if self.ws == None or not self.connected:
			self.err = PSS_ESTATE
			self.errstr = "pss " + self.name + " not connected"
			return False

		# create the contact object	
		try:
			contact = PssContact(nick, pubkey, address, self.key)
		except Exception as e:
			self.err = PSS_ELOCALINVAL
			self.errstr = "invalid input for add: " + repr(e)
			return False

		# add to node and object cache
		# \todo check success	
		self.ws.send(rpc_call(self.seq, "setPeerPublicKey", [pubkey, topic, address]))
		self.ws.recv()
		self.seq += 1
		self.contacts[nick] = contact

		return True



	# send message to registered recipient
	def send(self, nick, msg):

		# recipient must already be added
		if not nick in self.contacts:
			self.err = PSS_ELOCALINVAL
			self.errstr = "no such nick " + nick
			return False

		# check if we have connection
		# \todo store outgoing messages until online on temporary network loss
		if not self.connected:
			self.err = PSS_ESOCK
			self.errstr = "not connected"
			return False

		# send the message
		self.ws.send(rpc_call(self.seq, "sendAsym", [self.contacts[nick].key, topic, "0x" + msg.encode("hex")]))
		self.seq += 1

		# give response to user
		return True


	# retrieve last error from object
	def error(self):
		errobj = {
			"code": self.err,
			"description": self.errstr
		}
		self.err = 0
		self.errstr = ""
		return errobj



	# close down connections
	def close(self):
		self.connected = False
		self.run = False
		self.ws.close()


