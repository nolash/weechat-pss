import re

rMsg = re.compile("\S")


class Message:
	timestamp = 0
	user = ""
	content = ""

	
	def __init__(self, timestamp, user, content):
		self.timestamp = timestamp
		self.user = user
		self.content = content


def is_message(content):
	return rMsg.search(content) != None
