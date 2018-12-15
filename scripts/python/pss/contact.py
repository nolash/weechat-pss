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
