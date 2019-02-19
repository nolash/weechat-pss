import json
import secp256k1
from Crypto.Hash import keccak

from tools import clean_pubkey, clean_address, clean_nick

# object representing a single recipient
# \todo extend account
class PssContact:


	# key is the contact's public key in HEX
	# addr is the account of the contact in HEX
	# src is the public key of the pss node used when adding the contact
	def __init__(self, nick, account, src):

		validnick = ""
		validkey = ""
		validaddr = ""

		validnick = clean_nick(nick)
		validkey = clean_pubkey(key)
		if len(addr) > 0:
			validaddr = clean_address(addr)

		self.nick = validnick
		self.key = "0x" + validkey
		self.address = "0x" + validaddr
		self.src = src


	# \todo proper nested json serialize
	def serialize(self):
		return	"\"key\":\"" + self.key + "\""


	# \todo implement	
	def encrypt_to(self, s):
		return s


	def get_public_key(self):
		return self.account.publickeybytes


	def get_address(self):
		return self.account.address



# holds ethereum account
# \todo move out of pss to enable sync comms even though crypto modules doesn't exist
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
		self.publickeybytes = pubkey[1:]
		self.address = publickey_to_account(pubkey[1:])
		if address != None and self.address != address:
			raise RuntimeError("pubkey address and control address do not match")
	
	
	def set_key(self, keybytes):
		self._clear_key()
		self.privatekey = secp256k1.PrivateKey(keybytes)
		self.publickeybytes = self.privatekey.pubkey.serialize(False)
		self.address = publickey_to_account(self.publickeybytes)


	def _clear_key(self):
		self.privatekey = None
		self.publickeybytes = ""
		self.address = None


	def is_owner(self):
		return self.privatekey != None
			


def publickey_to_account(keybytes):
	h = keccak.new(digest_bits=256)
	h.update(keybytes[1:])
	return h.digest()[12:]
	
