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
import uuid

_flag_ctx_peer = 1 << 0
_flag_ctx_comm = 1 << 1
_flag_ctx_content = 1 << 2
_flag_ctx_tag = 1 << 3
_flag_ctx_bank = 1 << 6
_flag_ctx_multi = 1 << 7

_flag_error_format = 0x02
_flag_error_exist = 0x04

class ApiItem:

	def __init__(self, itemid):
		self.id = itemid
		self.err = 0
		self.data = b''
		self.datalength = 0


class ApiParser:


	def __init__(self):
		self.item = None


	def put(self, data):
		if len(data) == 0:
			return (None, None)
		if self.item == None:
			itemid = (data[0] & 31) << 8
			itemid += data[1]
			self.item = ApiItem(itemid)
			self.remaining = struct.unpack(">I", data[3:7])[0]
			self.item.data += data[:7]
			datalength = struct.unpack(">I", data[3:7])
			self.item.datalength = datalength[0]
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


	def __init__(self, name, host="127.0.0.1", wsport="8546", bzzport="8500"):

		self.lock_i = threading.Lock() 
		self.lock_o = threading.Lock()
		self.lock_main = threading.Lock()
		self.agent = None
		self.pss = None

		if name == "":
			self.name = str(uuid.uuid4())
		else:
			self.name = name

		self.pss = pss.Pss(name, host, wsport)
		if not self.pss.connect():
			raise Exception(self.pss.errstr)
		self.agent = pss.Agent(host, bzzport)
		self.bzz = pss.Bzz(self.agent)
		self.queue_i = pss.Queue((1<<13)-1)
		self.queue_o = pss.Queue((1<<13)-1)
		self.running = True
		self.thread_process = threading.Thread(None, self.process, "process")
		self.thread_process.start()
		self.sockaddr = "tmp_{:}.sock".format(uuid.uuid4())
		self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		self.sock.bind(self.sockaddr)
		self.thread_in = threading.Thread(None, self.handle_in, "handle_in")
		self.thread_in.start()

		# cached objects
		self.contacts = []
		self.chats = {}
		self.rooms = {}

		# cache lookup indices
		self.idx_publickey_contact = {}
		self.idx_publickey_pss = {}
		self.idx_nick_contact = {}
		self.idx_src_contacts = {}
		self.idx_room_contacts = {}
		self.idx_contacts_rooms = {}


	def __del__(self):
		self.lock_main.acquire()
		if self.agent != None:
			self.agent.close()
		if self.pss != None:
			self.pss.close()
		self.lock_main.release()


	def connect(self, c):
		self.lock_main.acquire()
		c.connect(self.sockaddr)
		self.lock_main.release()


	## loop sending output queue entries to socket
	#
	# \todo partial send handling
	def handle_out(self, sock):
		while True:
			self.lock_o.acquire()
			item = self.queue_o.get()
			self.lock_o.release()
			if item != None:
				select.select([], [sock.fileno()], [])
				c = sock.send(item.data)
				if c == 0:
					print("fail send", c, item.data)
					self.lock_o.acquire()
					self.queue_o.add(item)
					self.lock_o.release()
			elif not self.running:
				return
			time.sleep(0.1)	
		pass


	## synchronously process one instruction
	def process(self):
		while True:
			self.lock_i.acquire()
			item = self.queue_i.get()
			self.lock_i.release()
			if item != None: 

				# build what we can of the the header before data length
				outitem = ApiItem(item.id)
				firstbyte = item.data[0] & 0x1f 
				#outitem.data = firstbyte.to_bytes(1, sys.byteorder)
				#outitem.data += item.data[1:2]
				#outheader = bytearray([firstbyte.to_bytes(1, sys.byteorder), item.data[1:2]])	
				outheader = bytearray(b'')
				outheader += firstbyte.to_bytes(1, sys.byteorder)
				outheader += item.data[1:3]
				# empty data	
				outdata = bytearray(b'')
				error = 0x01

				try:
					# peer instruction
					if _flag_ctx_peer & item.data[2] > 0:
						
						# room context
						if _flag_ctx_multi & item.data[2] > 0:
							pass

						# chat context
						else:
							# remove peer
							if _flag_ctx_bank & item.data[2] > 0:
								pass

							# add peer
							else:
								# check that data is correct
								print(repr(item.datalength))
								if item.datalength != 65:
									error = _flag_error_format
									raise ValueError("pubkey", item.datalength)
								if item.data[7:] in self.idx_publickey_contact:
									error = _flag_error_exist
									raise ValueError("pubkey")
								# create contact and add to cache
								newcontact = pss.PssContact("", self.name)
								newcontact.set_public_key(item.data[7:])
								self.contacts.append(newcontact)
								self.idx_publickey_contact[item.data[7:]] = newcontact

					# ok status does not append data
					outheader = to_error(error, outheader)
					outdata = to_data(outdata)
					outitem.data = outheader + outdata

				except Exception as e:
					print("process err ", error, str(e))
					outheader = to_error(error, outheader)
					outitem.data += outheader
			
				self.lock_o.acquire()
				self.queue_o.add(outitem)
				self.lock_o.release()

			elif not self.running:
				return
			time.sleep(0.1)


	
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


	def stop(self):
		self.lock_main.acquire()
		self.running = False
		self.lock_main.release()
		self.thread_in.join()
		self.thread_out.join()
		self.thread_process.join()


## add given error to data
#
# \param error one byte error flag, byte aligned
# \param data bytearray of data to manipulate
def to_error(error, data):
	data[0] &= 0x1f
	data[0] |= (error & 0xff) << 5
	return data	


## returns new reference to data prefixed with serialized data length 
def to_data(indata):
	outdata = struct.pack(">I", len(indata))
	outdata += indata
	return outdata
