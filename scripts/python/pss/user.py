import json
import secp256k1
from Crypto.Hash import keccak

from tools import clean_pubkey, clean_address, clean_nick

# object representing a single recipient
# \todo move to separate package
class PssContact:
	nick = ""
	key = ""
	address = ""
	src = ""

	def __init__(self, nick, key, addr, src):

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


# holds ethereum account
# \todo move out of pss to enable sync comms even though crypto modules doesn't exist
class Account:
	privatekey = None
	publickeybytes = "" 
	address = None

	# \todo check address
	def set_address(self, address):
		self._clear_key()
		self.address = address
		
	def set_key(self, keybytes):
		self._clear_key()
		self.privatekey = secp256k1.PrivateKey(keybytes)
		self.publickeybytes = self.privatekey.pubkey.serialize(False)[1:]
		self.address = publickey_to_account(self.publickeybytes)

	def _clear_key(self):
		self.privkatekey = None
		self.publickeybytes = ""
		self.address = None


def publickey_to_account(keybytes):
	h = keccak.new(digest_bits=256)
	h.update(keybytes)
	return h.digest()[12:]
	
