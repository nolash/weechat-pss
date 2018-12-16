import re

# \todo make unicode aware
regexValidNick = re.compile("^[\w\d_]$")



# check validity of private key
# length and valid hex check
# \todo add unit test 
def clean_privkey(key):
	keyhex = clean_hex(key)

	if len(keyhex) != 64:
		raise ValueError("wrong privkey size")

	return keyhex



# check validity of address 
# length and valid hex check
# \todo add unit test 
def clean_address(addr):
	addrhex = clean_hex(addr)
		
	if len(addrhex) > 64:
		raise ValueError("address too long")
	
	return addrhex



# check validity of key format
# length and valid hex check
# \todo add unit test 
def clean_pubkey(pubkey):
	keyhex = clean_hex(pubkey)

	if len(keyhex) != 130:
		raise ValueError("wrong key length (" + str(len(keyhex)) + ")")

	return keyhex



# check if nick can be used
def clean_nick(s):
	validnick = ""
	try:
		validnick = regexValidNick.search(s)
	except Exception as e:
		raise ValueError("provided nick is not a string")

	if validnick == "":
		raise ValueError("invalid characters in nick")

	return s.encode("ascii")	
	
	


# current only converts from unicode to ascii
# though what else may we need I wonder?
# will return an ascii hex string without 0x prefix
# throws exception on failure
# \todo add unit test
def clean_hex(hx):
	decodedHex = repr(hx)

	if decodedHex[:2] == "u'":
		decodedHex = decodedHex[2:-1]
	elif decodedHex[0] == "'":
		decodedHex = decodedHex[1:-1]

	if len(decodedHex) < 2:
		raise ValueError("invalid hex '" + decodedHex + "'")

	if decodedHex[:2] == "\x30\x78":
		decodedHex = decodedHex[2:]

	if len(decodedHex) > 0:
		try:
			decodedHex.decode("hex")
		except Exception as e:
			raise ValueError("invalid hex '" + decodedHex + "': " + str(e))

	return decodedHex



# hex excerpt for display
# shows by default 4 bytes
# \todo add unit test
def label(hx, l=8):
	if l == 0:
		return ""
	l += 2	

	decodedHex = clean_hex(hx)

	if len(decodedHex) < l:
		l = len(hx)

	return decodedHex[:l] 
