#!/usr/bin/python2

import unittest
import pss
import socket
import sys

privkey = "2ea3f401733d3ecc1e18b305245adc98f3ffc4c6e46bf42f37001fb18b5a70ac"
pubkey = "b72985aa2104e41c1a2d40340c2b71a8d641bb6ac0f9fd7dc2dbbd48c0eaf172baa41456d252532db97704ea4949e1f42f66fd57de00f8f1f4514a2889f42df6"
account = "45dcf678e39c6e5e89ad25c7a0659a78c5584d99"

zerohsh = ""
for i in range(32):
	zerohsh += "00"

class TestFeedRebuild(unittest.TestCase):
	bzz = None
	sock = None
	agent = None
	account = None
	feeds = {}


	def setUp(self):
		sys.stderr.write("setup\n")
		self.account = pss.Eth(pss.clean_privkey(privkey).decode("hex"))
		self.sock = socket.create_connection(("127.0.0.1", "8500"), 20)
		self.agent = pss.Agent("127.0.0.1", 8500, self.sock.fileno())
		self.bzz = pss.Bzz(self.agent)

	
	def test_single_feed(self):
		self.feeds["foo"] = pss.Feed(self.agent, self.account, "one", True)
		self.feeds["foo"].sync()

		hshfirst = self.bzz.add(zerohsh + "inky")
		self.feeds["foo"].update(hshfirst)

		hshsecond = self.bzz.add(hshfirst + "pinky")
		self.feeds["foo"].update(hshsecond)

		hshthird = self.bzz.add(hshsecond + "blinky")
		self.feeds["foo"].update(hshthird)

		r = self.feeds["foo"].head()
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

	def test_two_feeds_same_period(self):
		pass

	def tearDown(self):
		sys.stderr.write("teardown\n")
		self.sock.close()


if __name__ == "__main__":
	unittest.main()
