#!/usr/bin/python3

import threading
import socket
import select
import uuid
import time
import os
import struct
import sys
import pss

_flag_ctx_peer = 1 << 0
_flag_ctx_comm = 1 << 1
_flag_ctx_content = 1 << 2
_flag_ctx_tag = 1 << 3
_flag_ctx_bank = 1 << 6
_flag_ctx_multi = 1 << 7


class ApiItem:

	def __init__(self, itemid):
		self.id = itemid
		self.err = 0
		self.data = b''


class ApiParser:


	def __init__(self):
		self.item = None


	def put(self, data):
		if len(data) == 0:
			return (None, None)
		if self.item == None:
			itemid = (data[0] & 31) << 7
			itemid += data[1]
			#err = data[0] >> 5
			self.item = ApiItem(itemid)
			self.remaining = struct.unpack(">I", data[3:7])[0]
			print("got id {} len {}\n".format(itemid, self.remaining))
			self.item.data += data[:7]
			data = data[7:]

		cap = len(data)
		if cap > self.remaining:
			cap = self.remaining
		self.item.data += data[:cap]
		self.remaining -= cap
		if self.remaining == 0:
			item = self.item
			self.item = None 
			return (item, data[cap:])
		return (None, None)


class ApiServer: 


	def __init__(self):
		self.agent = pss.Agent("127.0.0.1", 8500)
		self.bzz = pss.Bzz(self.agent)
		self.queue_i = pss.Queue(4095)
		self.queue_o = pss.Queue(4095)
		self.lock_i = threading.Lock() 
		self.lock_o = threading.Lock()
		self.lock_main = threading.Lock()
		self.running = True
		self.thread_process = threading.Thread(None, self.process, "process")
		self.thread_process.start()
		self.sockaddr = "tmp_{:}.sock".format(uuid.uuid4())
		self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		self.sock.bind(self.sockaddr)
		self.thread_handle = threading.Thread(None, self.handle_in, "handle")
		self.thread_handle.start()


	def __del__(self):
		print("closing")
		self.lock_main.acquire()
		self.agent.close()
		self.lock_main.release()


	def process(self):
		while True:
			self.lock_i.acquire()
			item = self.queue_i.get()
			self.lock_i.release()
			if item != None: 
				data = item.data
				sys.stdout.write("data {}".format(data[7:]))
				if _flag_ctx_peer & data[2] > 0:
					sys.stdout.write("|peer")
				elif _flag_ctx_comm & data[2] > 0:
					sys.stdout.write("|comm")
				elif _flag_ctx_content & data[2] > 0:
					sys.stdout.write("|content")
				elif _flag_ctx_tag & data[2] > 0:
					sys.stdout.write("|tag")
				if _flag_ctx_bank & data[2] > 0:
					sys.stdout.write("|bank")
				if _flag_ctx_multi & data[2] > 0:
					sys.stdout.write("|multi")
				print()
				#print("ok: {}".format(self.bzz.add(data)))
			elif not self.running:
				return
			time.sleep(0.1)
		
	
	def handle_in(self):
		#print("start listen {}\n".format(self.sock))
		self.sock.listen(0)
		(c, addr) = self.sock.accept()
		c.settimeout(0.1)
		#print("got incoming addr:{} sock:{}\n".format(addr, c))
		parser = ApiParser()
		while self.running:
			data = ""
			try:
				select.select([c.fileno()], [], [], 0.1)
				data = c.recv(1024)
			except:
				print("sock timeout\n")
				continue
			print("in: {}".format(data))
			(complete, leftovers) = parser.put(data)
			while leftovers != None:
				self.lock_i.acquire()
				self.queue_i.add(complete)
				self.lock_i.release()
				print("complete {}".format(complete))
				(complete, leftovers) = parser.put(leftovers)
		c.close()
		self.sock.close()
		os.unlink(self.sockaddr)


	def connect(self, c):
		self.lock_main.acquire()
		c.connect(self.sockaddr)
		self.lock_main.release()


	def stop(self):
		self.lock_main.acquire()
		self.running = False
		self.lock_main.release()
		self.thread_handle.join()
		self.thread_process.join()

