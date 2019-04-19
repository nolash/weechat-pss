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
		select.select([], [self.fileno], [])
		self.sock.send(b"\x00\x08\x01\x00\x00\x00\x03\x66\x6f\x6f")
		select.select([], [self.fileno], [])
		self.sock.send(b"\x30\x00\x42\x00\x00\x00\x04\x62\x61\x72\x20")
		select.select([], [self.fileno], [])
		self.sock.send(b"\x10\x01\x88\x00\x00\x00\x05\x78\x79\x7a\x7a\x79")
		time.sleep(1.0)


if __name__ == "__main__":
	unittest.main()
