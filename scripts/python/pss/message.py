import re

rMsg = re.compile("\S")

def is_message(msg):
	return rMsg.search(msg) != None
