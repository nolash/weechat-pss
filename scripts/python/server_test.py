#!/usr/bin/python3

import unittest
import time
import api
import socket
import select
import struct
import threading
import json
import os
import codecs
from pss import decodehex, rpc_call

privkey = "2ea3f401733d3ecc1e18b305245adc98f3ffc4c6e46bf42f37001fb18b5a70ac"
pubkey = "04b72985aa2104e41c1a2d40340c2b71a8d641bb6ac0f9fd7dc2dbbd48c0eaf172baa41456d252532db97704ea4949e1f42f66fd57de00f8f1f4514a2889f42df6"
to_pubkey = "0462eb15eb2b940742eda35065f7b38f3ebe17328bf905cac6f7a0af0f323834d2362c0699a18592b2077f6c98d6bfce38773ffcc0ed3361db4db0ae085b9c866a"
loc_pubkey = "0408e4c47b5f5e18e4d4e5f5fbbbee7b0d90147ed50a85ef81bacb98935ac47a1aa72ac853d456a43872cfc731e7ffff9884237afd7fde74270d486cb038724017"

class TestServer(unittest.TestCase):


	def setUp(self):
		self.obj = api.ApiServer(os.path.realpath("."), "foo")
		self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		self.fileno = self.sock.fileno()
		self.obj.start()
		time.sleep(0.25) # wait for sockets to be opened
		self.obj.connect(self.sock)
		self.sock.settimeout(0.25)
		select.select([self.fileno], [], [], 0.25)
		expectreceive = 7+65+32
		datarecv = self.sock.recv(expectreceive)
		if len(datarecv) != expectreceive:
			self.tearDown()
			raise ValueError("short read identity ({})".format(len(datarecv)))
		data = datarecv[7:]
		self.publickey_location = data[:65]
		self.overlay = datarecv[65:97]
				

	def tearDown(self):
		self.sock.close()
		self.obj.stop()


	@unittest.skip("skip test_room")
	def test_identity(self):
		print(self.overlay)
		self.assertEqual(pubkey, self.publickey_location.hex())

	
	@unittest.skip("skip test_room")
	# \todo verify json payload correct
	def test_pss_in(self):
		s_in, s_out = os.pipe()
		testmsg = {
			"json-rpc": "2.0",
			"id": 0,
			"params": {
				"result": {
					"Asymmetric": False,
					"Key": "0x" + to_pubkey,
					"Msg": "abc",
				}
			}
		}
		th = threading.Thread(None, self.obj.pss_in, "test_pss_in", [s_in])
		th.start()
		time.sleep(0.1)
		select.select([], [s_out], [])
		os.write(s_out, bytes(json.dumps(testmsg), "ascii"))
		dataexpect = b'\x20\x00\x02\x00\x00\x00\x44'
		pubkeybytes = codecs.decode(to_pubkey, "hex")
		dataexpect += pubkeybytes
		dataexpect += b'abc'
		select.select([self.fileno], [], [])
		datarecv = self.sock.recv(1024)
		self.obj.stop()
		th.join()
		os.close(s_in)
		os.close(s_out)
		self.assertEqual(dataexpect, datarecv)


	@unittest.skip("skip test_room")
	def test_room(self):

		# add private key
		select.select([], [self.fileno], [])
		datasend = b"\x00\x01\x00\x00\x00\x00\x20"
		datasend += decodehex(privkey)
		dataexpect = b"\x20\x01\x00\x00\x00\x00\x00"
		self.sock.send(datasend)
		select.select([self.fileno], [], [])
		datarecv = self.sock.recv(1024)
		self.assertEqual(dataexpect, datarecv)

		# join room (no public key = do not add peer to room)
		select.select([], [self.fileno], [])
		datasend = b"\x00\x02\x81\x00\x00\x00\x06\x05pinkz"
		dataexpect = b"\x20\x02\x81\x00\x00\x00\x00"
		self.sock.send(datasend)
		select.select([self.fileno], [], [])
		datarecv = self.sock.recv(1024)
		self.assertEqual(dataexpect, datarecv)

		# join room (no public key = do not add peer to room)
		select.select([], [self.fileno], [])
		datasend = b"\x00\x02\x81\x00\x00\x00\x4a\x05pinkz"
		datasend += decodehex(to_pubkey)
		datasend += b"meh"	
		dataexpect = b"\x20\x02\x81\x00\x00\x00\x00"
		self.sock.send(datasend)
		select.select([self.fileno], [], [])
		datarecv = self.sock.recv(1024)
		self.assertEqual(dataexpect, datarecv)

		# send to room
		select.select([], [self.fileno], [])
		datasend = b"\x00\x02\x82\x00\x00\x00\x09\x05pinkzfoo"
		dataexpect = b"\x20\x02\x82\x00\x00\x00\x00"
		self.sock.send(datasend)
		select.select([self.fileno], [], [])
		datarecv = self.sock.recv(1024)
		self.assertEqual(dataexpect, datarecv)


		time.sleep(10.0)


	#@unittest.skip("skip test_contact_single")
	def test_contact_single(self):

		# add private key
		select.select([], [self.fileno], [])
		datasend = b"\x00\x01\x00\x00\x00\x00\x20"
		datasend += decodehex(privkey)
		dataexpect = b"\x20\x01\x00\x00\x00\x00\x00"
		self.sock.send(datasend)
		select.select([self.fileno], [], [])
		datarecv = self.sock.recv(1024)
		self.assertEqual(dataexpect, datarecv)

		# add peer
		select.select([], [self.fileno], [])
		datasend = b"\x00\x02\x01"
		bytedata = decodehex(to_pubkey)
		bytedata += b'inky'
		(datalengthserialized) = struct.pack(">I", len(bytedata))
		datasend += datalengthserialized
		datasend += bytedata
		dataexpect = b"\x20\x02\x01\x00\x00\x00\x00"
		self.sock.send(datasend)
		select.select([self.fileno], [], [])
		datarecv = self.sock.recv(1024)
		self.assertEqual(dataexpect, datarecv)
		self.assertEqual(0x20, datarecv[0] & 0xe0)

		# tag peer location
		select.select([], [self.fileno], [])
		datasend = b"\x00\x03\x08\x00\x00\x00\x86"
		datasend += decodehex(to_pubkey)
		datasend += decodehex(loc_pubkey)
		datasend += b"\x01\x02\x03\x04"
		dataexpect = b"\x20\x03\x08\x00\x00\x00\x00"
		self.sock.send(datasend)
		select.select([self.fileno], [], [])
		datarecv = self.sock.recv(1024)
		self.assertEqual(dataexpect, datarecv)

		# check data
		select.select([], [self.fileno], [])
		datasend = b"\x00\x04\x60\x00\x00\x00\x04inky"
		dataexpect = b"\x20\x04\x60\x00\x00\x00\x86"
		dataexpect += decodehex(to_pubkey)
		dataexpect += decodehex(loc_pubkey)
		dataexpect += b'\x01\x02\x03\x04'
		self.sock.send(datasend)
		select.select([self.fileno], [], [])
		datarecv = self.sock.recv(1024)
		self.assertEqual(dataexpect, datarecv)

		# send a message, expect success
		select.select([], [self.fileno], [])
		datasend = b"\x00\x02\x02"
		#datasend += struct.pack(">I", 65+3)
		datasend += struct.pack(">I", 8)
		#datasend += decodehex(to_pubkey)
		msg = b'inky'
		datasend += bytes([len(msg) & 0xff])
		datasend += msg
		datasend += b'foo'
		dataexpect = b"\x20\x02\x02\x00\x00\x00\x00"
		self.sock.send(datasend)
		select.select([self.fileno], [], [])
		datarecv = self.sock.recv(1024)
		self.assertEqual(dataexpect, datarecv)

		# tag peer location
		select.select([], [self.fileno], [])
		datasend = b"\x00\x04\x08\x00\x00\x00\x82"
		datasend += decodehex(to_pubkey)
		datasend += decodehex(loc_pubkey)
		dataexpect = b"\x20\x04\x08\x00\x00\x00\x00"
		self.sock.send(datasend)
		select.select([self.fileno], [], [])
		datarecv = self.sock.recv(1024)
		self.assertEqual(dataexpect, datarecv)

		time.sleep(3.0)


if __name__ == "__main__":
	unittest.main()
