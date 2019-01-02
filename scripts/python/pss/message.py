import re

rMsg = re.compile("\S")


class Message:
	timestamp = 0
	key = ""
	user = ""
	content = ""
	src = ""

	
	def __init__(self, timestamp, acc, content, src):
		self.timestamp = timestamp
		self.key = acc.publickeybytes
		self.user = acc.address
		self.content = content
		self.src = src


def is_message(content):
	return rMsg.search(content) != None
