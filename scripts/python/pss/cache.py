import os
import sys
import copy

from tools import clean_pubkey, clean_overlay, Queue
from user import PssContact
from bzz import Feed, FeedCollection, chattopic, roomtopic
from room import Room

CACHE_CONTACT_STOREFILE = ".pss-contacts"


# \todo abstract NODE to create a more intuitive structure of feeds under it
class Cache:
	
	def __init__(self, path=".", queuelength=10):
		self.bzzs = {}
		self.psses = {}
		self.selfs = {}	
		self.defaultname = ""

		# address book members
		self.contacts = []
		self.idx_publickey_contact = {}
		self.idx_publickey_pss = {}
		self.idx_nick_contact = {}
		self.idx_src_contacts = {}

		# pss chat history feeds
		self.feeds = {}
		self.chats = {}

		# index nicks to chat rooms
		self.rooms = {}
		self.idx_room_contacts = {}
		self.idx_contact_rooms = {}

		# verify path and handle trailing slash
		self.path = path
		self.file = None


	def add_node(self, pssobj):
		if pssobj.get_name() in self.psses.keys():
			raise AttributeError("pss key " + str(nodename) + " already in use")

		if self.defaultname == "":
			self.defaultname = pssobj.get_name()

		self.psses[pssobj.get_name()] = pssobj
		self.idx_publickey_pss[pssobj.get_public_key()] = pssobj
		self.update_node_contact(pssobj.get_name())
		return True

	
	def get_feed(self, name, nodename):
		account = self.psses[nodename].get_account()
		return self.feeds[account.get_public_key()][name]


	def add_feed(self, name, nodename, topicseed=""):
	
		contact = self.idx_nick_contact[name]
		publickey = self.psses[nodename].get_account().get_public_key()
		if publickey in self.feeds:
			return None

		if topicseed == "":
			topicseed = contact.get_address()
	
		if not publickey in self.feeds:
			self.feeds[publickey] = {}
		self.feeds[publickey][name] = Feed(
			self.get_active_bzz(),
			self.psses[nodename].get_account(),
			topicseed
		)

		return self.feeds[publickey][name]



	def add_room(self, name, nodename):
		node = self.get_pss(nodename)
		account = node.get_account()
		room = Room(self.get_active_bzz(), name, account)
		loaded = False
		try:
			roomhsh = room.get_state_hash()
			room.load(roomhsh, account)
			loaded = True
			for k, p in room.participants.iteritems():
				publickey = p.get_public_key()
				if publickey != node.get_public_key():
					self.add_contact(p)
		except Exception as e:
			sys.stderr.write("can't find state for room " + name + ": " + repr(e) + "\n")
			room.start(self.get_nodeself(nodename))

		self.rooms[name] = room
		return (room, loaded)
			


	def get_room(self, name):
		return self.rooms[name]



	def get_room_count(self):
		return len(self.rooms.keys())



	def set_nodeself(self, nodename, nick):
		self.selfs[nodename] = nick
	


	def add_bzz(self, bzzobj, name):
		if name in self.bzzs.keys():
			raise AttributeError("bzz key " + str(name) + " already in use")

		self.bzzs[name] = bzzobj
		return True



	# \todo handle source param, must be supplied	
	def add_contact(self, contact, store=False):

		if contact.get_nick() in self.idx_nick_contact.keys():
			raise KeyError("contact name '" + str(contact.get_nick()) + "' already in use")

		if contact.get_public_key() == "":
			raise AttributeError("public key missing from contact")

		# take over the reference of contact, caller can drop var
		self.contacts.append(contact)
		self.idx_publickey_contact[contact.get_public_key()] = contact
		self.idx_nick_contact[contact.get_nick()] = contact
		if store and self.file != None:
			self.file.write( 
				contact.get_nick() + "\t" 
				+ contact.get_public_key().encode("hex") + "\t" 
				+ contact.get_overlay().encode("hex") + "\t" 
				+ contact.get_src().encode("hex") + "\n"
			)
			self.file.flush()

		# \todo probably we shouldn't pass on all exceptions here
		try:
			srcnode = self.idx_publickey_pss[contact.get_src()]
			try:
				self.add_contact_feed(contact, srcnode)
			except AttributeError as e:
				#sys.stderr.write("addcontact: " + repr(e))
				pass
		except KeyError as e:
			#sys.stderr.write("addcontact: " + repr(e))
			pass


	def add_contact_feed(self, contact, srcnode):

		if not srcnode.can_write():
			raise AttributeError("can't create contact feed for '" + contact.get_nick() + "@" + srcnode.get_name() + ", missing private key")

		senderfeed = Feed(
			self.get_active_bzz(),
			srcnode.get_account(),
			chattopic	
		)
		peerfeed = Feed(
			self.get_active_bzz(),
			contact,
			chattopic
		)

		coll = FeedCollection(srcnode.get_name() + "." + contact.get_nick(), senderfeed)
		coll.add(contact.get_nick(), peerfeed)

		if not contact.get_public_key() in self.chats:
			self.chats[contact.get_public_key()] = {}

		self.chats[contact.get_public_key()][srcnode.get_name()] = coll



	def remove_contact(self):
		pass



	def get_nodeself(self, nodename):
		return self.selfs[nodename]



	def get_active_bzz(self):
		if (len(self.bzzs) == 0):
			return None

		return self.bzzs[self.defaultname]



	def have_node_name(self, name):
		return name in self.psses


	def can_feed(self, nodename):
		return self.get_active_bzz() != None and self.psses[nodename].can_write()
	

	def get_pss(self, name):
		return self.psses[name]



	# check all sources and add as recipients in node
	# returns array of contacts added
	def update_node_contact(self, nodename):
		node = self.psses[nodename]
		srckey = node.get_public_key()
		contacts = []
		try:
			for c in self.idx_src_contacts[srckey]:
				self.psses[nodename].add(c)
				contacts.append(c)

		except:
			pass

		if node.can_write():
			self.update_node_contact_feed(node)

		return contacts

	
	def update_node_contact_feed(self, srcnode):
		for c in self.idx_src_contacts[srcnode.get_public_key()]:
			self.add_contact_feed(c, srcnode)
				
	
	def get_contact_by_nick(self, name):
		try:
			contact = self.idx_nick_contact[name]
		except KeyError as e:
			raise KeyError("no cached contact with name '" + str(name) + "'")
		return contact



	def get_contact_by_public_key(self, publickey):
		contact = self.idx_publickey_contact[publickey]
		if contact == None:
			raise AttributeError("no cached contact with public key'" + str(name) + "'")
		return contact



	def get_store_path(self):
		return self.path + "/" + CACHE_CONTACT_STOREFILE



	def load_store(self):

		entrycount = 0
		okcount = 0

		try:
			f = open(self.get_store_path(), "r", 0600)
			while 1:
				# if there is a record
				# split fields on tab and chop newline
				record = f.readline()
				if len(record) == 0:
					break	


				# add it to the map and report
				entrycount += 1
				try: 
					(nick, pubkeyhx, overlayhx, srckeyhx) = record.split("\t")
					if ord(srckeyhx[len(srckeyhx)-1]) == 0x0a:
						srckeyhx = srckeyhx[:len(srckeyhx)-1]
					srckey = clean_pubkey(srckeyhx).decode("hex")
					pubkey = clean_pubkey(pubkeyhx).decode("hex")
					overlay = clean_overlay(overlayhx).decode("hex")
					contact = PssContact(nick, srckey)
					contact.set_public_key(pubkey)
					contact.set_overlay(overlay)
					
				# \todo delete the record from the contact store
				except Exception as e:
					pass

				try:
					self.add_contact(contact)
					okcount += 1
					if not srckey in self.idx_src_contacts:
						self.idx_src_contacts[srckey] = []
					self.idx_src_contacts[srckey].append(contact)
					self.idx_nick_contact[nick] = contact
					self.idx_publickey_contact[pubkey] = contact

				except Exception as e:
					sys.stderr.write("fail on " + str(nick) + ": " + repr(e) + "\n")
			f.close()
		except IOError as e:
			pass	

		# \todo dump valid entries to new file and copy over old
		self.file = open(self.get_store_path(), "a", 0600)
		return (entrycount, okcount)


	def close_node(self, name):
		self.psses[name].close()
		if (self.bzzs[name] != self.get_active_bzz()):
			self.bzzs[name].close()


	def close(self):

		for p in self.psses.values():
			p.close()

		for b in self.bzzs.values():
			b.close()

		self.file.close()
