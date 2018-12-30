import websocket

from tools import clean_address, clean_pubkey
from error import *
from content import rpc_call, rpc_parse
from user import PssContact, Account

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
	eth = None
	err = 0
	errstr = ""
	contacts = {}
	seq = 0
	ws = None
	name = ""
	run = False
	sub = ""


	def __init__(self, name, host="127.0.0.1", port="8546"):
		""" set the pss instance name and create the fifo for catching msgs from subprocess
		"""
		self.name = name
		if host != "":
			self.host = host
		if port != "":
			self.port = port


	
	def have_account(self):
		return self.eth != None



	def set_account(self, privkeybytes):
		eth = Account(privkeybytes)
		# node pubkey is prefixed with 04
		# \todo verify that the number can't be other than 4
		if  eth.publickeybytes.encode("hex") != self.key[2:]:
			raise ValueError("private key does not match pss node public key " + self.key + " " + eth.publickeybytes.encode("hex"))
			return

		self.eth = eth
	


	def get_account(self):
		return self.eth


	# get underlying file descriptor of websocket
	def get_fd(self):
		if self.ws == None:
			return -1
		return self.ws.fileno()



	# open sockets and get initial data
	def connect(self):

		base = ""
		key = ""

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
		try:
			base = clean_address(resp['result'])
		except ValueError as e:
			self.err = PSS_EREMOTEINVAL
			self.errstr = "received bogus base address " + resp['result']
			return False
		
		# retrieve the node key	data
		self.ws.send(rpc_call(self.seq, "getPublicKey", []))
		self.seq += 1
		resp = rpc_parse(self.ws.recv())
	
		# verify key
		try: 
			key = clean_pubkey(resp['result'])
		except ValueError as e:
			self.err = PSS_EREMOTEINVAL
			self.errstr = "received bogus pubkey " + resp['result']
			return False

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


	

	# adds recipient to node
	def add(self, nick, pubkey, address):

		# holds the newly created contact object
		contact = None

		# brief address and key for display in buffer
		addrLabel = ""
		keyLabel = ""

		# no use if we're not connected
		# \todo use exception instead
		if self.ws == None or not self.connected:
			self.err = PSS_ESTATE
			self.errstr = "pss " + self.name + " not connected"
			return False

		# create the contact object	
		try:
			contact = PssContact(nick, pubkey, address, self.key)
		except ValueError as e:
			self.err = PSS_ELOCALINVAL
			self.errstr = "invalid input for add: " + repr(e)
			return False

		# add to node and object cache
		self.ws.send(rpc_call(self.seq, "setPeerPublicKey", [contact.key, topic, contact.address]))
		#self.ws.recv()
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



	# retrieve a registered contact	
	def get_contact(self, nick):
		try:
			return self.contacts[nick]
		except:	
			return None


	# check if nick is registered in node
	def have_nick(self, nick):
		return nick in self.contacts
