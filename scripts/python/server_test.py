#!/usr/bin/python3

import unittest
import time
import api
import socket
import select
import struct
from pss import decodehex

privkey = "2ea3f401733d3ecc1e18b305245adc98f3ffc4c6e46bf42f37001fb18b5a70ac"
pubkey = "04b72985aa2104e41c1a2d40340c2b71a8d641bb6ac0f9fd7dc2dbbd48c0eaf172baa41456d252532db97704ea4949e1f42f66fd57de00f8f1f4514a2889f42df6"
to_pubkey = "0462eb15eb2b940742eda35065f7b38f3ebe17328bf905cac6f7a0af0f323834d2362c0699a18592b2077f6c98d6bfce38773ffcc0ed3361db4db0ae085b9c866a"

class TestServer(unittest.TestCase):


	def setUp(self):
		self.obj = api.ApiServer("foo")
		self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		self.fileno = self.sock.fileno()
		time.sleep(1.0)


	def tearDown(self):
		self.sock.close()
		self.obj.stop()


	@unittest.skip("skip test_room")
	def test_room(self):
		self.obj.connect(self.sock)
		print("sending on addr:{} sock:{}\n".format(self.obj.sockaddr, self.sock))

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
		datasend = b"\x00\x02\x81\x00\x00\x00\x06\x05pinky"
		dataexpect = b"\x20\x02\x81\x00\x00\x00\x00"
		self.sock.send(datasend)
		select.select([self.fileno], [], [])
		datarecv = self.sock.recv(1024)
		self.assertEqual(dataexpect, datarecv)

		# join room (no public key = do not add peer to room)
		select.select([], [self.fileno], [])
		datasend = b"\x00\x02\x81\x00\x00\x00\x4a\x05pinky"
		datasend += decodehex(to_pubkey)
		datasend += b"meh"	
		dataexpect = b"\x20\x02\x81\x00\x00\x00\x00"
		self.sock.send(datasend)
		select.select([self.fileno], [], [])
		datarecv = self.sock.recv(1024)
		self.assertEqual(dataexpect, datarecv)


	#@unittest.skip("skip test_contact_single")
	def test_contact_single(self):
		self.obj.connect(self.sock)
		print("sending on addr:{} sock:{}\n".format(self.obj.sockaddr, self.sock))

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
		datasend = b"\x00\x08\x01"
		bytedata = decodehex(to_pubkey)
		#bytedata += b'\x04\x01\x02\x03\x04inky'
		bytedata += b'inky'
		(datalengthserialized) = struct.pack(">I", len(bytedata))
		datasend += datalengthserialized
		datasend += bytedata
		dataexpect = b"\x20\x08\x01\x00\x00\x00\x00"
		self.sock.send(datasend)
		select.select([self.fileno], [], [])
		datarecv = self.sock.recv(1024)
		self.assertEqual(dataexpect, datarecv)
		self.assertEqual(0x20, datarecv[0] & 0xe0)

		# send a message, expect success
		select.select([], [self.fileno], [])
		datasend = b"\x00\x02\x02"
		datasend += struct.pack(">I", 65+3)
		datasend += decodehex(to_pubkey)
		datasend += b'foo'
		dataexpect = b"\x20\x02\x02\x00\x00\x00\x00"
		self.sock.send(datasend)
		select.select([self.fileno], [], [])
		datarecv = self.sock.recv(1024)
		self.assertEqual(dataexpect, datarecv)

		time.sleep(1.0)


if __name__ == "__main__":
	unittest.main()
