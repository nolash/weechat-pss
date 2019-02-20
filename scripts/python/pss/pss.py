import websocket

from tools import clean_pubkey, clean_overlay, rpchex
from error import *
from content import rpc_call, rpc_parse
from user import PssContact, Account

# topic we will be using for this messenger service
topic = "0xdeadbee2"


# object encapsulating pss node connection
# \todo remove direct websocket comms and get node key and addr from background process
# \todo remove contact store, should be handled through cache only
class Pss:
	

	def __init__(self, name, host="127.0.0.1", port="8546"):
		""" set the pss instance name and create the fifo for catching msgs from subprocess
		"""
		self.name = name
		if host != "":
			self.host = host
		if port != "":
			self.port = port

		self.contacts = {}
		self.connected = False
		self.inputConnected = False
		self.account = Account()
		self.overlay = ""
		self.err = 0
		self.errstr = ""
		self.seq = 0
		self.ws = None
		self.run = False
		self.sub = ""


	
	def have_account(self):
		return self.account != None



	def set_account_write(self, privkeybytes):
		acc = Account()
		acc.set_key(privkeybytes)
		# node pubkey is prefixed with 04
		# \todo verify that the number can't be other than 4
		currentpubkey = self.account.get_public_key()
		if len(currentpubkey) > 0 and acc.get_public_key() != self.account.get_public_key():
			raise ValueError("private key does not match pss node public key " + rpchex(acc.get_public_key()) + " != " + rpchex(self.account.get_public_key()))

		self.account.set_key(privkeybytes)



	def get_account(self):
		return self.account



	# get underlying file descriptor of websocket
	def get_fd(self):
		if self.ws == None:
			return -1
		return self.ws.fileno()



	# open sockets and get initial data
	def connect(self):

		overlay = ""
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
			overlay = clean_overlay(resp['result']).decode("hex")
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
			key = clean_pubkey(resp['result']).decode("hex")
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
		self.account.set_public_key(key)
		self.overlay = overlay
		self.connected = True
		self.run = True

		return True


	def get_name(self):
		return self.name


	def get_host(self):
		return self.host	

	
	def get_port(self):
		return self.port

	
	def get_public_key(self):
		return self.account.publickeybytes



	def get_overlay(self):
		return self.overlay

	

	# adds recipient to node
	def add(self, nick, pubkey, overlay):

		# holds the newly created contact object
		contact = None

		# 
		# no use if we're not connected
		# \todo use exception instead
		if self.ws == None or not self.connected:
			raise IOError("not connected")

		# create the contact object	
		contact = PssContact(nick, self.account.get_public_key())
		contact.set_public_key(pubkey)
		contact.set_overlay(overlay)

		# add to node and object cache
		pubkeyhx = rpchex(contact.get_public_key())
		overlayhx = rpchex(contact.get_overlay())
		self.ws.send(rpc_call(self.seq, "setPeerPublicKey", [pubkeyhx, topic, overlayhx]))
		#self.ws.recv()
		self.seq += 1
		self.contacts[nick] = contact

		return contact



	# send message to registered recipient
	def send(self, contact, msg):

		# check if we have connection
		# \todo store outgoing messages until online on temporary network loss
		if not self.connected:
			raise IOError("not connected")

		# send the message
		self.ws.send(rpc_call(self.seq, "sendAsym", [rpchex(contact.get_public_key()), topic, "0x" + msg.encode("hex")]))
		self.seq += 1


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




