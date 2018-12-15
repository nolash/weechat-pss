# check validity of address 
# \todo implement
def is_address(addr):
	return True		



# check validity of key format
# \todo implement
def is_pubkey(pubkey):
	return True		



# hex excerpt for display
def label(hx, l=8):
	if l == 0:
		return "0x"
	l += 2	

	decodedHex = repr(hx)
	if decodedHex[:2] == "u'":
		decodedHex = decodedHex[2:-1]

	try:
		if decodedHex[:2] != "0x":
			raise Exception("invalid hex string")
	except:
		raise Exception("invalid hex string")

	if len(decodedHex) < l:
		l = len(hx)

	return decodedHex[2:l] 
