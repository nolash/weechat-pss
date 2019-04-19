import re
import struct

rMsg = re.compile("\S")

## Base type for all user-generated message updates
class Message:
	
	def __init__(self, serial, acc, content):
		if len(serial) != 5:
			raise ValueError("wrong serial length")

		self.timestamp = struct.unpack(">I", serial[0:4])
		self.seq = struct.unpack("B", serial[len(serial)-1])
		self.key = acc.publickeybytes
		self.user = acc.address
		self.content = content


	def serialize(self):
		serial = struct.pack(">I", self.timestamp)
		serial += struct.pack("B", self.seq)
		serial += content
		return serial


def is_message(content):
	return rMsg.search(content) != None
