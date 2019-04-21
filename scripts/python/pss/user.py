import json
import secp256k1
from Crypto.Hash import keccak

from .tools import clean_pubkey, clean_address, clean_nick


## \brief Ethereum account object
#
# If private key is set, public key and address is derived from it.
#
# If public key is explicitly set, address is derived from it.
#
# Address can also be explicitly set.
class Account:


	def __init__(self):
		self.privatekey = None
		self.publickeybytes = "" 
		self.address = None


	# \todo check address
	def set_address(self, address):
		self._clear_key()
		self.address = address


	def set_public_key(self, pubkey, address=None):
		self._clear_key()
		self.publickeybytes = pubkey
		self.address = publickey_to_address(pubkey)
		if address != None and self.address != address:
			raise RuntimeError("pubkey address and control address do not match: " + repr(self.address).encode("hex") + " != " + repr(address))
	
	
	def set_key(self, keybytes):
		self._clear_key()
		self.privatekey = secp256k1.PrivateKey(keybytes)
		self.publickeybytes = self.privatekey.pubkey.serialize(False)
		self.address = publickey_to_address(self.publickeybytes)


	def _clear_key(self):
		self.privatekey = None
		self.publickeybytes = ""
		self.address = None


	def is_owner(self):
		return self.privatekey != None
			

	def get_public_key(self):
		return self.publickeybytes


	def get_address(self):
		return self.address



class Location():
	
	def __init__(self, overlay=b'', publickey=None):
		self.overlay = overlay
		self.publickey = publickey	


## \brief pss context for Account
#
# \todo extend account
# \todo rename to Contact
class PssContact(Account):


	# key is the contact's public key in HEX
	# addr is the account of the contact in HEX
	# src is the public key of the pss node used when adding the contact
	def __init__(self, nick, src):
		Account.__init__(self)

		self.nick = nick
		self.src = src
		self.location = None


	# \todo proper nested json serialize
	def serialize(self):
		return	"\"key\":\"" + self.key + "\""



	# \todo implement	
	def encrypt_to(self, s):
		return s


	
	def set_from_account(self, account):
		self.publickeybytes = account.get_public_key()
		self.address = account.get_address()



	def set_location(self, location):
		if location.__class__.__name__ != "Location":
			raise ValueError("Must be Location object")
		self.location = location


	
	def get_src(self):
		return self.src



	def get_location(self):
		return self.location



	def get_nick(self):
		return self.nick



def publickey_to_address(keybytes):
	h = keccak.new(digest_bits=256)
	h.update(keybytes[1:])
	return h.digest()[12:]
	
