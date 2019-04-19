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
			itemid = (data[0] & 31) << 8
			itemid += data[1]
			#err = data[0] >> 5
			self.item = ApiItem(itemid)
			self.remaining = struct.unpack(">I", data[3:7])[0]
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
		self.queue_i = pss.Queue((1<<13)-1)
		self.queue_o = pss.Queue((1<<13)-1)
		self.lock_i = threading.Lock() 
		self.lock_o = threading.Lock()
		self.lock_main = threading.Lock()
		self.running = True
		self.thread_process = threading.Thread(None, self.process, "process")
		self.thread_process.start()
		self.sockaddr = "tmp_{:}.sock".format(uuid.uuid4())
		self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		self.sock.bind(self.sockaddr)
		self.thread_in = threading.Thread(None, self.handle_in, "handle_in")
		self.thread_in.start()

	def __del__(self):
		self.lock_main.acquire()
		self.agent.close()
		self.lock_main.release()


	def handle_out(self, sock):
		while True:
			self.lock_o.acquire()
			item = self.queue_o.get()
			self.lock_o.release()
			if item != None:
				select.select([], [sock.fileno()], [])
				sock.send(item.data)
			elif not self.running:
				return
			time.sleep(0.1)	
		pass


	def process(self):
		while True:
			self.lock_i.acquire()
			item = self.queue_i.get()
			self.lock_i.release()
			if item != None: 
				data = item.data
				typ = ""
				bank = False
				multi = False
				sys.stdout.write("data {}".format(data[7:]))
				if _flag_ctx_peer & data[2] > 0:
					typ = "peer"
				elif _flag_ctx_comm & data[2] > 0:
					typ = "comm"
				elif _flag_ctx_content & data[2] > 0:
					typ = "content"
				elif _flag_ctx_tag & data[2] > 0:
					typ = "tag"	
				if _flag_ctx_bank & data[2] > 0:
					bank = True	
				if _flag_ctx_multi & data[2] > 0:
					multi = True
				# short circuit
				h = self.newheader(item.id, 1, typ, item.data, bank, multi)
				outitem = ApiItem(item.id)
				print("hhdd", hex(h[0]), hex(h[1]), hex(h[2]))
				h += item.data[7:]
				outitem.data =  h
				self.lock_o.acquire()
				self.queue_o.add(outitem)
				self.lock_o.release()
			elif not self.running:
				return
			time.sleep(0.1)


	def newheader(self, seq, err, typ, data, bank=False, multi=False):
		h = bytearray(7)
		h[0] = err << 5
		h[0] |= (seq >> 8) & 0x1f 
		print("hh", h[0])
		h[1] = seq & 0xff
		if typ == "comm":
			h[2] = _flag_ctx_comm
		elif typ == "peer":
			h[2] = _flag_ctx_peer
		elif typ == "tag":
			h[2] = _flag_ctx_tag
		elif typ == "content":
			h[2] = _flag_ctx_content
		if bank:
			h[2] |= 0x40
		if multi:
			h[2] |= 0x80
		(lenbytes) = struct.pack(">I", len(data)-7)
		i = 3
		for l in lenbytes:
			h[i] = l
			i+=1
		return h
	
	
	def handle_in(self):
		self.sock.listen(0)
		(c, addr) = self.sock.accept()
		c.settimeout(0.1)
		self.thread_out = threading.Thread(None, self.handle_out, "handle_out", [c])
		self.thread_out.start()
		parser = ApiParser()
		while self.running:
			data = ""
			try:
				select.select([c.fileno()], [], [], 0.1)
				data = c.recv(1024)
			except:
				print("sock timeout\n")
				continue
			(complete, leftovers) = parser.put(data)
			while leftovers != None:
				self.lock_i.acquire()
				self.queue_i.add(complete)
				self.lock_i.release()
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
		self.thread_in.join()
		self.thread_out.join()
		self.thread_process.join()

