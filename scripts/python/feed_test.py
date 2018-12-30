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
seedval = 13

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
	privkeys = []
	coll = None


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

		self.coll = pss.FeedCollection()


	#@unittest.skip("showing class skipping")
	def test_single_feed(self):
		self.feeds.append(pss.Feed(self.agent, self.accounts[0], "one", True))

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


	#@unittest.skip("showing class skipping")
	def test_feed_collection_ok(self):
		for i in range(2):
			self.feeds.append(pss.Feed(self.agent, self.accounts[i], "one", True))
		tim = pss.now_int()
		timebytes = struct.pack(">I", tim)
		outfeeds = []
		for i in range(len(self.feeds)):
			lasthsh = copy.copy(zerohsh)
			addr = self.feeds[i].account.address
			acc = pss.Account()
			acc.set_address(addr)
			outfeeds.append(pss.Feed(self.agent, acc, "one", True))
			print "set addr " +  str(i) + " " + addr
			for j in range(3):
				lasthsh = self.bzz.add(lasthsh + timebytes  + chr(j) + hex((i*3)+j))
				self.feeds[i].update(lasthsh)

		self.coll.add("foo", outfeeds[0])
		self.coll.add("bar", outfeeds[1])
		ridx = self.coll.gethead(self.bzz)
		msgs = self.coll.retrievals.pop(ridx)

		i = 0
		for n in ["foo", "bar"]:
			k = self.coll.feeds[n]['obj'].account.address
			v = msgs[k]
			self.assertEqual(v[timebytes + "\x00"].content, "0x" + str(i*3))
			self.assertEqual(v[timebytes + "\x00"].user, k)
			self.assertEqual(v[timebytes + "\x01"].content, "0x" + str((i*3)+1))
			self.assertEqual(v[timebytes + "\x01"].user, k)
			self.assertEqual(v[timebytes + "\x02"].content, "0x" + str((i*3)+2))
			self.assertEqual(v[timebytes + "\x02"].user, k)	
			i += 1

	
	#@unittest.skip("showing class skipping")
	def test_feed_collection_sort(self):
		for i in range(2):
			self.feeds.append(pss.Feed(self.agent, self.accounts[i], "one", True))
		tim = pss.now_int()
		timebytes = struct.pack(">I", tim)
		outfeeds = []
		for i in range(len(self.feeds)):
			lasthsh = copy.copy(zerohsh)
			addr = self.feeds[i].account.address
			acc = pss.Account()
			acc.set_address(addr)
			outfeeds.append(pss.Feed(self.agent, acc, "one", True))
			print "set addr " +  str(i) + " " + addr
			for j in range(3):
				lasthsh = self.bzz.add(lasthsh + timebytes  + chr(j) + hex((i*3)+j))
				self.feeds[i].update(lasthsh)

		self.coll.add("foo", outfeeds[0])
		self.coll.add("bar", outfeeds[1])
		self.coll.gethead(self.bzz)
		msgs = self.coll.get()

		# \todo more elegance, please
		if msgs[0].content == "0x0":
			self.assertEqual(msgs[1].content, "0x3")
			self.assertEqual(msgs[2].content, "0x1")
			self.assertEqual(msgs[3].content, "0x4")
		if msgs[0].content == "0x3":
			self.assertEqual(msgs[1].content, "0x0")
			self.assertEqual(msgs[2].content, "0x4")
			self.assertEqual(msgs[3].content, "0x1")


	#@unittest.skip("showing class skipping")
	def test_feed_collection_single_gap(self):
		feed = pss.Feed(self.agent, self.accounts[0], "one", True)

		tim = pss.now_int()
		timebytes = struct.pack(">I", tim)
		bogushsh = ""
		for i in range(32):
			bogushsh += "01"
		lasthsh = copy.copy(bogushsh)


		addr = feed.account.address
		acc = pss.Account()
		acc.set_address(addr)
		outfeed = pss.Feed(self.agent, acc, "one", True)
		print "set addr " +  str(i) + " " + addr
		for j in range(3):
			lasthsh = self.bzz.add(lasthsh + timebytes  + chr(j) + hex((i*3)+j))
			feed.update(lasthsh)
	
		self.coll.add("foo", outfeed)
		# \todo this is not theoretically safe on a busy node, as things may change between, but in controlled test should be ok
		headhsh = feed.head()
		ridx = self.coll.gethead(self.bzz)
		self.coll.retrievals.pop(ridx)
		#ridx = self.coll.gethead(self.bzz)
		#msgs = self.coll.retrievals.pop(ridx)

		try:
			self.assertEqual(self.coll.feeds['foo']['orphans'][headhsh], bogushsh)
		except Exception as e:
			self.fail("dict key in test assert fail: " + str(e))

	
	def test_feed_room(self):
		nicks = []
		r = pss.Room("foo", self.agent)
		for i in range(len(self.accounts)):
			addrhx = self.accounts[i].address.encode("hex")
			nicks.append(addrhx[:16])
			pubkeyhx = "04"+self.accounts[i].publickeybytes.encode("hex")
			p = pss.Participant(nicks[i], pubkeyhx, addrhx, "04"+pubkey)
			r.add(nicks[i], p)
		
		for k, v in r.feedcollection.feeds.iteritems():
			print "have feed " + k + " topic: " + v['obj'].topic


	def tearDown(self):
		self.feeds = []
		colls = []
		for k, v in self.coll.feeds.iteritems():
			colls.append(k)
		for k in colls:
			self.coll.remove(k)
		sys.stderr.write("teardown\n")
		self.sock.close()


if __name__ == "__main__":
	unittest.main()
