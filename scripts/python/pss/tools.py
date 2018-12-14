# check validity of address 
# \todo implement
# \todo move to util package
def is_address(addr):
	return True		



# check validity of key format
# \todo implement
# \todo move to util package
def is_pubkey(pubkey):
	return True		



# hex excerpt for display
# \todo move to util package
def label(hx):
	l = 10
	p = ""
	try:
		if hx[0:2] != "0x":
			raise Exception("invalid hex string")
	except:
		raise Exception("invalid hex string")

	if len(hx) < 10:
		l = len(hx)
	elif(hx) > 10:
		p = "..."

	return hx[0:l] + p


