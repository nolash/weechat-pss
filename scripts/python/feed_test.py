#!/usr/bin/python2

import unittest
import pss
import socket
import sys
import random
import struct
import json

from pss.bzz import feedRootTopic, FeedCollection, zerohsh, new_topic_mask
from pss.room import Participant
from pss.tools import clean_pubkey, now_int

privkey = "2ea3f401733d3ecc1e18b305245adc98f3ffc4c6e46bf42f37001fb18b5a70ac"
pubkey = "04b72985aa2104e41c1a2d40340c2b71a8d641bb6ac0f9fd7dc2dbbd48c0eaf172baa41456d252532db97704ea4949e1f42f66fd57de00f8f1f4514a2889f42df6"
seedval = 13

class TestFeedRebuild(unittest.TestCase):


	def setUp(self):
		global seedval

		self.accounts = []
		self.feeds = []
		self.privkeys = []

		self.sock = socket.create_connection(("127.0.0.1", "8500"), 20)
		self.agent = pss.Agent("127.0.0.1", 8500, self.sock.fileno())
		self.sock.settimeout(10.0)
		self.bzz = pss.Bzz(self.agent)
	
		random.seed(pss.now_int()+seedval)

		# create 10 random private keys and create accounts with them
		for i in range(10):
			hx = ""
			for j in range(32):
				hx += "{:02x}".format(random.randint(0, 255))
			self.privkeys.append(hx)
			acc = pss.Account()
			acc.set_key(pss.clean_privkey(self.privkeys[i]).decode("hex"))
			self.accounts.append(acc)

		seedval += 1

		self.coll = FeedCollection("test")


	# create a linked list of three elements, retrieve in order and compare hashes
	#@unittest.skip("skipping test_single_feed")
	def test_single_feed(self):

		self.feeds.append(pss.Feed(self.bzz, self.accounts[0], "one"))

		hshfirst = self.bzz.add(zerohsh + "inky")
		self.feeds[0].update(hshfirst)

		hshsecond = self.bzz.add(hshfirst.decode("hex") + "pinky")
		self.feeds[0].update(hshsecond)

		hshthird = self.bzz.add(hshsecond.decode("hex") + "blinky")
		self.feeds[0].update(hshthird)

		r = self.feeds[0].head()
		self.assertEqual(r, hshthird)

		r = self.bzz.get(hshthird)
		self.assertEqual(r[:32], hshsecond.decode("hex"))
		self.assertEqual(r[32:], "blinky")
		
		r = self.bzz.get(r[:32].encode("hex"))
		self.assertEqual(r[:32], hshfirst.decode("hex"))
		self.assertEqual(r[32:], "pinky")

		r = self.bzz.get(r[:32].encode("hex"))
		self.assertEqual(r[:32], zerohsh)
		self.assertEqual(r[32:], "inky")


	# create a collection of two feeds. 
	# test that updates are available in the collection after gethead()
	#@unittest.skip("skipping test_feed_collection_ok")
	def test_feed_collection_ok(self):

		for i in range(2):
			self.feeds.append(pss.Feed(self.bzz, self.accounts[i], "one"))

		tim = pss.now_int()
		timebytes = struct.pack(">I", tim)

		# holds feeds to read from
		outfeeds = []

		for i in range(len(self.feeds)):

			# first hash in linked list is zerohash
			lasthsh = zerohsh

			# create new feed with address only (no private key) for read
			addr = self.feeds[i].account.get_address()
			acc = pss.Account()
			acc.set_address(addr)
			outfeeds.append(pss.Feed(self.bzz, acc, "one"))

			#print "set addr " +  str(i) + " " + addr.encode("hex")

			# create 3 updates
			# an update is 
			# * previous hash (zerohash if first update)
			# * time of update
			# * sequence of update within timestamp (one byte)
			# * data (in this case incrementing counter in hex)
			for j in range(3):
				hsh = self.bzz.add(lasthsh + timebytes  + chr(j) + hex((i*3)+j))
				hshbytes = hsh.decode("hex")
				lasthsh = hshbytes
				self.feeds[i].update(hshbytes)

		# put the read feeds into the collection
		self.coll.add("foo", outfeeds[0])
		self.coll.add("bar", outfeeds[1])

		# get the latest updates using the collection
		# it iterates all feeds, gets the latest update
		# and follows the linked hashes to retrieve all content
		(ridx, fails) = self.coll.gethead(self.bzz)
		self.assertEqual(len(fails), 0)

		# one element in retrievals array contains all updates
		# retrieved in one "gethead" call
		msgs = self.coll.retrievals.pop(ridx)

		# compare the results
		i = 0
		for n in ["foo", "bar"]:
			k = self.coll.feeds[n].obj.account.get_address()

			# feed updates are indexed on user address, then time and index
			v = msgs[k]
			self.assertEqual(v[timebytes + "\x00"].content, "0x" + str(i*3))
			self.assertEqual(v[timebytes + "\x00"].user, k)
			self.assertEqual(v[timebytes + "\x01"].content, "0x" + str((i*3)+1))
			self.assertEqual(v[timebytes + "\x01"].user, k)
			self.assertEqual(v[timebytes + "\x02"].content, "0x" + str((i*3)+2))
			self.assertEqual(v[timebytes + "\x02"].user, k)	
			i += 1


	# create a feed collection
	# and test that the get() method returns chronologically sorted entries	
	#@unittest.skip("collection sort")
	def test_feed_collection_sort(self):

		# same setup as previous test
		for i in range(2):
			self.feeds.append(pss.Feed(self.bzz, self.accounts[i], "one"))

		tim = pss.now_int()
		timebytes = struct.pack(">I", tim)

		outfeeds = []
		for i in range(len(self.feeds)):
			lasthsh = zerohsh
			addr = self.feeds[i].account.get_address()
			acc = pss.Account()
			acc.set_address(addr)
			outfeeds.append(pss.Feed(self.bzz, acc, "one"))
			for j in range(3):
				hsh = self.bzz.add(lasthsh + timebytes  + chr(j) + hex((i*3)+j))
				byteshsh = hsh.decode("hex")
				lasthsh = byteshsh
				self.feeds[i].update(byteshsh)

		self.coll.add("foo", outfeeds[0])
		self.coll.add("bar", outfeeds[1])
		(_, fails) = self.coll.gethead(self.bzz)
		self.assertEqual(len(fails), 0)
		
		msgs = self.coll.get()

		# depending on which feed comes first alphabetically
		# the messages should be ordered first by address 
		# then by time+serial
		if msgs[0].content == "0x0":
			self.assertEqual(msgs[1].content, "0x3")
			self.assertEqual(msgs[2].content, "0x1")
			self.assertEqual(msgs[3].content, "0x4")
			self.assertEqual(msgs[4].content, "0x2")
			self.assertEqual(msgs[5].content, "0x5")
		if msgs[0].content == "0x3":
			self.assertEqual(msgs[1].content, "0x0")
			self.assertEqual(msgs[2].content, "0x4")
			self.assertEqual(msgs[3].content, "0x1")
			self.assertEqual(msgs[4].content, "0x5")
			self.assertEqual(msgs[5].content, "0x2")


	# test that broken links (swarm content hashes that do not resolve)
	# and content until break
	# are correctly recorded in the collection object
	#@unittest.skip("collection single gap")
	def test_feed_collection_single_gap(self):

		feed = pss.Feed(self.bzz, self.accounts[0], "one")

		tim = pss.now_int()
		timebytes = struct.pack(">I", tim)

		# create a (most probably) non-existent hash
		# this will constitute a dead end on retrieval
		bogushsh = ""
		for i in range(32):
			bogushsh += "01"
		lasthsh = bogushsh.decode("hex")

		# set up similar as previous collection tests, but only one feed
		addr = feed.account.get_address()
		acc = pss.Account()
		acc.set_address(addr)
		outfeed = pss.Feed(self.bzz, acc, "one")
		for j in range(3):
			hsh = self.bzz.add(lasthsh + timebytes  + chr(j) + hex(j))
			hshbytes = hsh.decode("hex")
			lasthsh = hshbytes
			feed.update(hshbytes)
	
		self.coll.add("foo", outfeed)

		# retrieve the updates in the collection
		# we also retrieve the hash of the latest update
		# as this is the key for the resulting dead end entry
		# \todo this is not theoretically safe on a busy node, as things may change between, but in controlled test should be ok
		headhsh = feed.head()
		(ridx, fails) = self.coll.gethead(self.bzz)
		self.assertEqual(len(fails), 0)
		upd = self.coll.retrievals.pop(ridx)

		try:
			self.assertEqual(self.coll.feeds['foo'].orphans[headhsh], bogushsh.decode("hex"))
		except Exception as e:
			self.fail("dict key in test assert fail: " + str(e))

		# check that we still got all the updates that we could	
		k = self.coll.feeds['foo'].obj.account.get_address()
		msgs = upd[k]
		self.assertEqual(msgs[timebytes + "\x00"].content, "0x0")
		self.assertEqual(msgs[timebytes + "\x01"].content, "0x1")
		self.assertEqual(msgs[timebytes + "\x02"].content, "0x2")



	# test that room topics are correctly generated
	#@unittest.skip("room name")	
	def test_feed_room_name(self):

		# start room 
		roomname = "foo"
		nick = "bar"
		r = pss.Room(self.bzz, roomname, self.accounts[0])
		r.start(nick)

		# create participant object to ensure correct representation of nick
		p = Participant(nick, pubkey)
		p.set_public_key(self.accounts[0].get_public_key())

		resulttopic = r.feedcollection.feeds[p.nick].obj.topic

		# the name will be xor'd to the leftmost bits in the topic byte array
		# it will still be intact as a substring
		self.assertEqual(resulttopic[0:len(roomname)], roomname)

		# the last 12 bytes should be identical to the root topic
		self.assertEqual(resulttopic[20:], new_topic_mask(feedRootTopic, "", "\x06")[20:])
		
		

	# test that we can instantiate a room from saved state
	#@unittest.skip("feed room load save")	
	def test_feed_room(self):

		nicks = [self.accounts[0].get_address().encode("hex")]
		r = pss.Room(self.bzz, "abc", self.accounts[0])
		r.start("foo")
		for i in range(1, len(self.accounts)):
			nicks.append(str(i))
			p = Participant(nicks[i], pubkey)
			p.set_public_key(self.accounts[i].get_public_key())	
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
		recreatedownerfeed = pss.Feed(self.bzz, acc, unserializedroom['name'])

		# instantiate room with feed recreated from saved state
		rr = pss.Room(self.bzz, recreatedownerfeed)
		rr.load(r.hsh, self.accounts[0])

		# check that for all"cleanpub: " +  in-feeds (read peer's updates) the feed user field is the address of the peer
		matchesleft = len(self.accounts)
		for f in rr.feedcollection_in.feeds.values():
			matched = False
			for a in self.accounts:

				if f['obj'].account.get_address() == a.get_address():
					matched = True
					matchesleft -= 1
			if not matched:
				self.fail("found unknown address " + f['obj'].account.get_address().encode("hex"))
		if matchesleft != 0:
			self.fail("have " + str(matchesleft) + " unmatched addresses")


		# for the outfeed, check that we are owner
		self.assertTrue(rr.feed_out.account.is_owner())


	# \todo add extract_message test (without fetch)
	#@unittest.skip("room send")	
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

		r = pss.Room(self.bzz, "nothing", None) 

		r_hx, r_now, r_serial = r.extract_meta(data)
		self.assertEqual(hx, r_hx)
		self.assertEqual(now, r_now)
		self.assertEqual("\x00", r_serial)
		

	# \todo add test for initial feed update on start		


	# test that we can create update and that the saved update contains the expected data
	# \todo rewrite using feedcollections.write()
	#@unittest.skip("room send")	
	def test_feed_room_send(self):

		msg = "heyho"
		roomname = hex(now_int())

		nicks = ["0"]
		r = pss.Room(self.bzz, roomname, self.accounts[0])
		r.start("0")
		for i in range(1, len(self.accounts)):
			nicks.append(str(i))
			p = Participant(nicks[i], pubkey)
			p.set_public_key(self.accounts[i].get_public_key())
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
			offset = struct.unpack("<I", lenbytes + "\x00")[0]
			self.assertEqual(offset, i*len(msg))
			self.assertEqual(body[datathreshold+offset:datathreshold+offset+len(msg)], msg)
			body = self.bzz.get(hsh)
			ciphermsg = r.extract_message(body[37:], r.participants[nicks[i]])
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
		self.sock.close()


if __name__ == "__main__":
	unittest.main()
