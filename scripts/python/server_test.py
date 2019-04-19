#!/usr/bin/python3

import unittest
import time
import api
import socket
import select

class TestServer(unittest.TestCase):


	def setUp(self):
		self.obj = api.ApiServer()
		self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		self.fileno = self.sock.fileno()
		time.sleep(1.0)


	def tearDown(self):
		self.sock.close()
		self.obj.stop()


	def test_basic(self):
		self.obj.connect(self.sock)
		print("sending on addr:{} sock:{}\n".format(self.obj.sockaddr, self.sock))

		# basic check for echo
		select.select([], [self.fileno], [])
		datasend = b"\x00\x08\x01\x00\x00\x00\x03\x66\x6f\x6f"
		self.sock.send(datasend)
		select.select([self.fileno], [], [])
		datarecv = self.sock.recv(1024)
		self.assertEqual(datasend[1:], datarecv[1:])
		self.assertEqual(datasend[0], datarecv[0] & 0x1f)
		self.assertEqual(0x20, datarecv[0] & 0xe0)

		# check that the error (erroneously) sent does not come back
		select.select([], [self.fileno], [])
		datasend = b"\x70\x00\x42\x00\x00\x00\x04\x62\x61\x72\x20"
		self.sock.send(datasend)
		select.select([self.fileno], [], [])
		datarecv = self.sock.recv(1024)
		self.assertEqual(datasend[1:], datarecv[1:])
		self.assertEqual(datasend[0] & 0x3f, datarecv[0])
		self.assertEqual(0x20, datarecv[0] & 0xe0)

		# check correct treatment of high order byte in id
		select.select([], [self.fileno], [])
		datasend = b"\x10\x01\x88\x00\x00\x00\x05\x78\x79\x7a\x7a\x79"
		self.sock.send(datasend)
		select.select([self.fileno], [], [])
		datarecv = self.sock.recv(1024)
		self.assertEqual(datasend[1:], datarecv[1:])
		self.assertEqual(datasend[0], datarecv[0] & 0x1f)
		self.assertEqual(0x20, datarecv[0] & 0xe0)

		time.sleep(1.0)


if __name__ == "__main__":
	unittest.main()
