#!/usr/bin/python2

import unittest
import pss
import random
import json

# \todo one source of keys across test files

class TestSerialize(unittest.TestCase):
	pubkey = []
	addr = []
	nodekey = []

	def setUp(self):
		for i in range(3):
			random.seed(42+i)
			addr = ""
			nodekey = ""
			pubkey = ""
			for j in range(32):
				addr += "{:02x}".format(random.randint(0, 255))
				nodekey += "{:02x}".format(random.randint(0, 255))
			for j in range(64):
				pubkey += "{:02x}".format(random.randint(0, 255))
			self.addr.append(addr)
			self.nodekey.append(nodekey)
			self.pubkey.append("04"+pubkey)
			pass


	def tearDown(self):	
		self.addr = []
		self.nodekey = []
		pass


	@unittest.skip("modular serialization not implemented, reinstate when it is")
	def test_contact(self):
		c = pss.PssContact("foo", self.pubkey[0], self.addr[0], self.nodekey[0])

		s = c.serialize()
		try:
			roomobj = json.loads(s)
		except ValueError as e:
			self.fail("json deserialize error: " + (str(e)))


	def test_room(self):
		r = pss.Room("foo")
		for i in range(len(self.pubkey)):
			r.add(str(i), pss.Participant(str(i), self.pubkey[i], self.addr[i], self.nodekey[i]))

		s = r.serialize()
		try:
			roomobj = json.loads(s)
		except ValueError as e:
			self.fail("json deserialize error: " + (str(e)))


if __name__ == "__main__":
	unittest.main()
