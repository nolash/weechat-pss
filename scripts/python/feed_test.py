#!/usr/bin/python2

import unittest
import pss
import socket
import sys
import random
import copy
import struct
import json

from pss.bzz import feedRootTopic, FeedCollection
from pss.room import Participant
from pss.tools import clean_pubkey, now_int

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
	accounts = None
	feeds = None
	privkeys = None
	coll = None


	def setUp(self):
		global seedval

		self.accounts = []
		self.feeds = []
		self.privkeys = []

		sys.stderr.write("setup\n")
		self.sock = socket.create_connection(("127.0.0.1", "8500"), 20)
		self.agent = pss.Agent("127.0.0.1", 8500, self.sock.fileno())
		self.bzz = pss.Bzz(self.agent)
	
		random.seed(pss.now_int()+seedval)

		for i in range(10):
			hx = ""
			for j in range(32):
				hx += "{:02x}".format(random.randint(0, 255))
			print "#" + str(i) + " is using " + hx
			self.privkeys.append(hx)
			acc = pss.Account()
			acc.set_key(pss.clean_privkey(self.privkeys[i]).decode("hex"))
			self.accounts.append(acc)
			sys.stderr.write("added random (seed " + str(seedval) + " key " + self.privkeys[i] + " account " + self.accounts[i].address.encode("hex") + " pubkey " + self.accounts[i].publickeybytes.encode("hex") + "\n")

		seedval += 1

		self.coll = FeedCollection()


	#@unittest.skip("showing class skipping")
	def test_single_feed(self):
		global zerohsh

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
		print r
		self.assertEqual(r[:64], hshfirst)
		self.assertEqual(r[64:], "pinky")

		r = self.bzz.get(r[:64])
		print r
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


	#@unittest.skip("collection single gap")
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


	# test that room topics are correctly generated
	#@unittest.skip("room name")	
	def test_feed_room_name(self):
		roomname = "foo"
		nick = "bar"
		self.feeds.append(pss.Feed(self.agent, self.accounts[0], roomname, False))
		r = pss.Room(self.bzz, self.feeds[0])
		r.start(nick, roomname)
		addrhx = self.accounts[0].address.encode("hex")
		pubkeyhx = "04"+self.accounts[0].publickeybytes.encode("hex")
		p = Participant(nick, pubkeyhx, addrhx, "04"+pubkey)

		resulttopic = r.feedcollection_in.feeds[p.nick]['obj'].topic
		self.assertEqual(resulttopic[0:len(roomname)], roomname)
		self.assertEqual(resulttopic[20:], feedRootTopic[20:])
		
		

	# test that we can instantiate a room from saved state
	##@unittest.skip("feed room load save")	
	def test_feed_room(self):

		# room ctrl feed
		self.feeds.append(pss.Feed(self.agent, self.accounts[0], "abc", False))

		nicks = [self.accounts[0].address.encode("hex")]
		r = pss.Room(self.bzz, self.feeds[0])
		r.start("foo", "abc")
		for i in range(1, len(self.accounts)):
			addrhx = self.accounts[i].address.encode("hex")
			nicks.append(str(i))
			pubkeyhx = "04"+self.accounts[i].publickeybytes.encode("hex")
			p = Participant(nicks[i], pubkeyhx, addrhx, "04"+pubkey)
			r.add(nicks[i], p)
	
		# get the serialized representation of room	
		serializedroom = r.serialize()

		# save the room 
		savedhsh = r.save()
	
		# retrieve the pubkey from the saved room format	
		# and create account with retrieved public key
		# \todo more intuitive feed injection on load
		unserializedroom = json.loads(serializedroom)
		acc = pss.Account()
		cleanpub = clean_pubkey(unserializedroom['pubkey'])
		acc.set_public_key(cleanpub.decode("hex"))
		return

		# create feed with account from newly (re)created account
		recreatedownerfeed = pss.Feed(self.agent, acc, unserializedroom['name'], False)

		# instantiate room with feed recreated from saved state
		rr = pss.Room(self.bzz, recreatedownerfeed)
		rr.load(r.hsh, self.accounts[0])

		# check that for all"cleanpub: " +  in-feeds (read peer's updates) the feed user field is the address of the peer
		matchesleft = len(self.accounts)
		for f in rr.feedcollection_in.feeds.values():
			matched = False
			for a in self.accounts:

				if f['obj'].account.address == a.address:
					matched = True
					matchesleft -= 1
			if not matched:
				print "key '" + f['obj'].account.publickeybytes.encode("hex") + "'"
				self.fail("found unknown address " + f['obj'].account.address.encode("hex"))
		if matchesleft != 0:
			self.fail("have " + str(matchesleft) + " unmatched addresses")


		# for the outfeed, check that we are owner
		self.assertTrue(rr.feed_out.account.is_owner())


	# \todo add extract_message test (without fetch)
	##@unittest.skip("room send")	
	def test_extract(self):
		hx = ""
		data = ""
		now = 0
		r = None

		now = now_int()

		for i in range(32):
			hx += chr(random.randint(0, 255))

		data = hx
		data += struct.pack(">I", now)
		data += "\x00"

		for i in range(32):
			data += chr(random.randint(0, 255))
		data += "\x00\x00\x00"

		r = pss.Room(None, pss.Feed(None, None, "nothing"))

		r_hx, r_now, r_serial = r.extract_meta(data)
		self.assertEqual(hx, r_hx)
		self.assertEqual(now, r_now)
		self.assertEqual("\x00", r_serial)
		

	# \todo add test for initial feed update on start		


	# test that we can create update and that the saved update contains the expected data
	##@unittest.skip("room send")	
	def test_feed_room_send(self):

		msg = "heyho"
		roomname = hex(now_int())

		# room ctrl feed
		self.feeds.append(pss.Feed(self.agent, self.accounts[0], roomname, False))

		nicks = ["0"]
		r = pss.Room(self.bzz, self.feeds[0])
		r.start("0", roomname)
		for i in range(1, len(self.accounts)):
			addrhx = self.accounts[i].address.encode("hex")
			nicks.append(str(i))
			pubkeyhx = "04"+self.accounts[i].publickeybytes.encode("hex")
			p = Participant(nicks[i], pubkeyhx, addrhx, "04"+pubkey)
			r.add(nicks[i], p)

		hsh = r.send(msg)

		body = self.bzz.get(hsh)
		self.assertEqual(body[37:69], r.hsh_room)
	
		roomparticipants = json.loads(self.bzz.get(r.hsh_room.encode("hex")))
		crsr = 69
		participantcount = len(roomparticipants['participants'])
		datathreshold = 69 + (participantcount*3)
		for i in range(participantcount):
			lenbytes = body[crsr:crsr+3]
			print lenbytes.encode("hex")
			offset = struct.unpack("<I", lenbytes + "\x00")[0]
			self.assertEqual(offset, i*len(msg))
			self.assertEqual(body[datathreshold+offset:datathreshold+offset+len(msg)], msg)
			body = self.bzz.get(hsh)
			ciphermsg = r.extract_message(body, r.participants[nicks[i]])
			self.assertEqual(ciphermsg, msg)
			crsr += 3

		self.assertEqual(len(body), datathreshold + (participantcount*len(msg)))
			

	
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
