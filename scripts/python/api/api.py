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
import codecs

_flag_ctx_peer = 1 << 0
_flag_ctx_comm = 1 << 1
_flag_ctx_content = 1 << 2
_flag_ctx_tag = 1 << 3
_flag_ctx_bank = 1 << 6
_flag_ctx_multi = 1 << 7

_flag_error_format = 0x02
_flag_error_entity = 0x04


class ApiLogger:

	def __init__(self, filename):
		pass	


class ApiItem:

	def __init__(self, itemid):
		self.id = itemid
		self.err = 0
		self.header = b''
		self.data = b''
		self.datalength = 0
		self.src = b''


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
			self.item.header = data[:3]
			self.item.src = data[:7]
			datalength = struct.unpack(">I", data[3:7])
			self.item.datalength = datalength[0]
			data = data[7:]

		cap = len(data)
		if cap > self.remaining:
			cap = self.remaining
		self.item.data += data[:cap]
		self.item.src += data[:cap]
		self.remaining -= cap
		if self.remaining == 0:
			item = self.item
			self.item = None 
			return (item, data[cap:])
		return (None, None)


class ApiCache:

	def __init__(self):
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

		# feed pointers
		self.hsh_feed_chats = {}
		self.hsh_feed_rooms = {}
		self.hsh_dirty = False


class ApiServer(ApiCache): 


	def __init__(self, name, host="127.0.0.1", wsport="8546", bzzport="8500"):

		self.lock_i = threading.Lock() 
		self.lock_o = threading.Lock()
		self.lock_main = threading.Lock()
		self.lock_feed = threading.Lock()
		self.agent = None
		self.pss = None

		if name == "":
			self.name = str(uuid.uuid4())
		else:
			self.name = name

		self.pss = pss.Pss(name, host, wsport)
		if not self.pss.connect():
			raise Exception(self.pss.errstr)

		# perhaps account show be supplied to pss obj and not the other way around
		self.contact = pss.PssContact(self.name, self.name)

		self.agent = pss.Agent(host, bzzport)
		self.bzz = pss.Bzz(self.agent)
		self.queue_i = pss.Queue((1<<13)-1)
		self.queue_o = pss.Queue((1<<13)-1)
		self.running = True

		self.sockaddr = "tmp_{:}.sock".format(uuid.uuid4())
		self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		self.sock.bind(self.sockaddr)

		# initialize the cache
		super(ApiServer, self).__init__()

		self.thread_process = threading.Thread(None, self.process, "process")
		self.thread_process.start()
		self.thread_in = threading.Thread(None, self.handle_in, "handle_in")
		self.thread_in.start()
		self.thread_feed_out = threading.Thread(None, self.feed_out, "feed_out")
		self.thread_feed_out.start()
	


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


	## post new head hashes of all feed chat linked lists
	#
	# \todo better sleep calculation so is run every second
	def feed_out(self):
		while True:
			if not self.hsh_dirty and not self.running:
				sys.stderr.write("feed_out exiting")
				return
			updates = 0
			for k in self.chats.keys():
				if k in self.hsh_feed_chats:
					self.lock_feed.acquire()
					feedhash = self.chats[k].senderfeed.lasthsh
					actualhash = self.hsh_feed_chats[k]
					self.lock_feed.release()
					if feedhash != actualhash:
						updates += 1
						threading.Thread(None, self.chats[k].senderfeed.obj.update, "update_feed_" + str(k), [actualhash]).start()	
			sys.stderr.write("feed_out complete {}".format(updates))
			self.lock_feed.acquire()
			self.hsh_dirty = False
			self.lock_feed.release()
			time.sleep(1.0)
	

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
	#
	# \todo use same object for account in pss node as in self.contact
	def process(self):
		while True:
			self.lock_i.acquire()
			item = self.queue_i.get()
			self.lock_i.release()
			if item != None: 

				# build what we can of the the header before data length
				outitem = ApiItem(item.id)
				firstbyte = item.header[0] & 0x1f 
				outheader = bytearray(b'')
				outheader += firstbyte.to_bytes(1, sys.byteorder)
				outheader += item.header[1:3]

				# start with empty data	
				outdata = bytearray(b'')
				error = 0x01

				try:

					# set private key
					# for now cannot be changed without restarting the server
					if item.header[2] == 0:
						if item.datalength != 32:
							error = _flag_error_format
							raise ValueError("privatekey wrong length")
						self.pss.set_account_write(item.data)
						self.contact.set_key(item.data)
						self.add_contact_feed(self.contact)

					# comms instruction
					if _flag_ctx_comm & item.header[2] > 0:

						# room context
						if _flag_ctx_multi & item.header[2] > 0:
					
							# settings
							if _flag_ctx_bank & item.header[2] > 0:
								pass
				
							# send	
							else:
								roomnamelength = item.data[0]
								roomname = item.data[1:1+roomnamelength]
								payload = item.data[1+roomnamelength:]
								self.rooms[roomname].send(payload)
									
						# chat context
						else:
							# settings
							if _flag_ctx_bank & item.header[2] > 0:
								pass

							# send
							else:
								pubkey = item.data[:65]
								payload = item.data[65:]
								contact = self.idx_publickey_contact[pubkey]
								self.pss.send(contact, payload)
	
								# update the outgoing feed
								if self.contact.is_owner():
									hsh = self.chats[pubkey].write(payload)
									self.lock_feed.acquire()
									self.hsh_feed_chats[pubkey] = hsh
									self.hsh_dirty = True
									self.lock_feed.release()
	
					# peer instruction
					if _flag_ctx_peer & item.header[2] > 0:
						
						# room context
						if _flag_ctx_multi & item.header[2] > 0:

							# remove from room / exit room
							if _flag_ctx_bank & item.header[2] > 0:
								pass

							# add peer to room / join room
							else:
								roomnamelength = item.data[0]
								pubkey = None
								if item.datalength > roomnamelength+1:
									try:
										pubkey = item.data[1+roomdatalength:66+roomdatalength]
									except:
										error = _flag_error_format
										raise ValueError("wrong pubkey length")
								try:
									roomname = item.data[1:1+roomnamelength]
								except:
										error = _flag_error_format
										raise ValueError("wrong roomname length")
								self.hsh_feed_rooms[roomname] = pss.zerohsh

							room = pss.Room(self.bzz, roomname, self.contact)
							loaded = False
							try:
								roomhsh = room.get_state_hash()
								room.load(roomhsh, self.contact)
								loaded = True
								for k, p in room.participants.items():
									publickey = p.get_public_key()
									if publickey != self.contact.get_public_key():
										try:
											print("todo add contact", p)
											#self.add_contact(p)
										except KeyError as e:
											pass
							except Exception as e:
								sys.stderr.write("can't find state for room " + roomname.decode("ascii") + ": " + repr(e) + "\n")
								room.start(self.name)


						# chat context
						else:
							# remove peer
							if _flag_ctx_bank & item.header[2] > 0:
								pass

							# add peer
							else:
								# check that data is correct
								if item.datalength < 66:
									error = _flag_error_format
									raise ValueError("pubkey", item.datalength)
								newcontact = None
								address = b''
								pubkey = item.data[:65]
								overlaylength = item.data[65]

								# retrieve contact object if already exists
								if pubkey in self.idx_publickey_contact:
									newcontact = self.idx_publickey_contact[pubkey]
								else:
									newcontact = pss.PssContact("", self.name)

								# if overlay address is specified then set it
								if overlaylength > 0:
									address += item.data[66:66+overlaylength]
									newcontact.set_overlay(address)


								# if there is data left on input that's the nick. add it
								# delete the existing nick to contact index entry if it exists
								if len(item.data) > 66+overlaylength:	
									if newcontact.nick in self.idx_nick_contact:
										del self.idx_nick_contact[newcontact.nick]
									newcontact.nick = pss.clean_nick(item.data[66+overlaylength:].decode("ascii"))
									self.idx_nick_contact[newcontact.nick] = newcontact


								# add to cache
								newcontact.set_public_key(pubkey)
								self.contacts.append(newcontact)
								self.idx_publickey_contact[pubkey] = newcontact

								# add the peer to pss node
								self.pss.add(newcontact)

								try:
									self.add_contact_feed(newcontact)
								except:
									print("feed not possible")

					# ok status does not append data
					outheader = to_error(error, outheader)
					outdata = to_data(outdata)
					outitem.data = outheader + outdata

				except KeyError as e:
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



	## 
	#
	# \todo chattopic must be changed to correct topic for contact feed
	def add_contact_feed(self, contact):
		if not self.pss.can_write():
			raise AttributeError("can't create contact feed for '" + contact.get_nick() + "@" + self.name + ", missing private key")

		senderfeed = pss.Feed(
			self.bzz,
			self.pss.get_account(),
			pss.chattopic[:31]
		)
		peerfeed = pss.Feed(
			self.bzz,
			contact,
			pss.chattopic[:31]
		)

		coll = pss.FeedCollection(self.pss.get_name() + "." + contact.get_nick(), senderfeed)
		coll.add(contact.get_nick(), peerfeed)

		sys.stderr.write("wrote to " + contact.get_nick())
		# originally node name, change to peer name as we want to maintain feeds per peer instead, should be public key keyed
		self.chats[contact.get_public_key()] = coll



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

