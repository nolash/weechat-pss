from tools import *
from error import *

# object representing a single recipient
# \todo move to separate package
class PssContact:
	nick = ""
	key = ""
	address = ""
	src = ""

	def __init__(self, nick, key, addr, src):
		if not is_pubkey(key):
			raise Exception("invalid key " + key)

		if not is_address(addr):
			raise Exception("invalid address " + addr)

		self.nick = nick
		self.key = key
		self.address = addr
		self.src = src
