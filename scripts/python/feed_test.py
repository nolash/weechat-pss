#!/usr/bin/python2

import unittest
import pss
import socket
import sys
import random
import copy
import struct

privkey = "2ea3f401733d3ecc1e18b305245adc98f3ffc4c6e46bf42f37001fb18b5a70ac"
pubkey = "b72985aa2104e41c1a2d40340c2b71a8d641bb6ac0f9fd7dc2dbbd48c0eaf172baa41456d252532db97704ea4949e1f42f66fd57de00f8f1f4514a2889f42df6"
seedval = 42

# \todo put in single test setup
zerohsh = ""
for i in range(32):
	zerohsh += "00"


class TestFeedRebuild(unittest.TestCase):
	bzz = None
	sock = None
	agent = None
	accounts = []
	feeds = []
	seedval = 42
	privkeys = []


	def setUp(self):
		global seedval

		sys.stderr.write("setup\n")
		self.sock = socket.create_connection(("127.0.0.1", "8500"), 20)
		self.agent = pss.Agent("127.0.0.1", 8500, self.sock.fileno())
		self.bzz = pss.Bzz(self.agent)
	
		random.seed(pss.now_int()+seedval)
		self.privkeys = []

		for i in range(10):
			hx = ""
			for j in range(32):
				hx += "{:02x}".format(random.randint(0, 255))
			print "#" + str(i) + " is using " + hx
			self.privkeys.append(hx)
			acc = pss.Account()
			acc.set_key(pss.clean_privkey(self.privkeys[i]).decode("hex"))
			self.accounts.append(acc)
			sys.stderr.write("added random (seed " + str(seedval) + " key " + self.privkeys[i] + " account " + self.accounts[i].address.encode("hex") + "\n")

		seedval += 1

	@unittest.skip("yes")	
	def test_single_feed(self):
		self.feeds.append(pss.Feed(self.agent, self.accounts[0], "one", True))
		self.feeds[0].sync()

		hshfirst = self.bzz.add(zerohsh + "inky")
		self.feeds[0].update(hshfirst)

		hshsecond = self.bzz.add(hshfirst + "pinky")
		self.feeds[0].update(hshsecond)

		hshthird = self.bzz.add(hshsecond + "blinky")
		self.feeds[0].update(hshthird)

		r = self.feeds[0].head()
		self.assertEqual(r, hshthird)

		r = self.bzz.get(hshthird)
		self.assertEqual(r[:64], hshsecond)
		self.assertEqual(r[64:], "blinky")
		
		r = self.bzz.get(r[:64])
		self.assertEqual(r[:64], hshfirst)
		self.assertEqual(r[64:], "pinky")

		r = self.bzz.get(r[:64])
		self.assertEqual(r[:64], zerohsh)
		self.assertEqual(r[64:], "inky")

	def test_feed_collection_ok(self):
		for i in range(2):
			self.feeds.append(pss.Feed(self.agent, self.accounts[i], "one", True))

		tim = pss.now_int()
		outfeeds = []
		for i in range(len(self.feeds)):
			lasthsh = copy.copy(zerohsh)
			addr = self.feeds[i].account.address
			acc = pss.Account()
			acc.set_address(addr)
			outfeeds.append(pss.Feed(self.agent, acc, "one", True))
			print "set addr " +  str(i) + " " + addr
			for j in range(3):
				lasthsh = self.bzz.add(lasthsh + struct.pack(">I", tim) + chr(j) + hex((i*3)+j))
				self.feeds[i].update(lasthsh)
	
		coll = pss.FeedCollection()
		coll.add("foo", outfeeds[0])
		coll.add("bar", outfeeds[1])
		msgs = coll.retrieve(self.bzz)

		for k, v in msgs.iteritems():
			print "msgs for " + k.encode("hex")
			i = 0
			for m in v:
				print "#" + str(i) + " " + v[m].timestamp.encode("hex") + ": " + v[m].content
				i += 1

	def tearDown(self):
		sys.stderr.write("teardown\n")
		self.sock.close()


if __name__ == "__main__":
	unittest.main()
