#!/usr/bin/python2

import unittest
import pss
import random
import json
import socket

from pss.room import Participant

# \todo one source of keys across test files

class TestSerialize(unittest.TestCase):
	pubkey = []
	addr = []
	nodekey = []
	bzz = None
	agent = None
	sock = None

	def setUp(self):

		self.sock = socket.create_connection(("127.0.0.1", "8500"), 20)
		self.agent = pss.Agent("127.0.0.1", 8500, self.sock.fileno())
		self.bzz = pss.Bzz(self.agent)

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
		acc = pss.Account()
		print len(self.pubkey[0])
		acc.set_public_key(self.pubkey[0].decode("hex"))
		r = pss.Room(self.bzz, "root", acc)
		#r.start("bar", "foo")
		for i in range(len(self.pubkey)):
			r.participants[str(i)] = Participant(str(i), self.pubkey[i], self.addr[i], self.nodekey[i])

		s = r.serialize()
		try:
			roomobj = json.loads(s)
		except ValueError as e:
			self.fail("json deserialize error: " + (str(e)))


if __name__ == "__main__":
	unittest.main()
