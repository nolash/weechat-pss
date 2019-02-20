import os
import sys

from tools import clean_pubkey, clean_overlay, Queue
from user import PssContact
from bzz import Feed

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

		# index nicks to chat rooms
		self.rooms = {}
		self.idx_room_contacts = {}
		self.idx_contact_rooms = {}

		# verify path and handle trailing slash
		self.path = path
		self.file = None


	def add_node(self, pssobj, nodename):
		if nodename in self.psses.keys():
			raise AttributeError("pss key " + str(nodename) + " already in use")

		if self.defaultname == "":
			self.defaultname = nodename		

		self.psses[nodename] = pssobj
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
			self.get_active_bzz().agent,
			self.psses[nodename].get_account(),
			topicseed
		)

		return self.feeds[publickey][name]


	def set_nodeself(self, nodename, nick):
		self.selfs[nodename] = nick
	


	def add_bzz(self, bzzobj, name):
		if name in self.bzzs.keys():
			raise AttributeError("bzz key " + str(name) + " already in use")

		self.bzzs[name] = bzzobj
		return True



	# \todo handle source param, must be supplied	
	def add_contact(self, name, contact, store=False):

		if name in self.idx_nick_contact.keys():
			raise KeyError("contact name '" + str(name) + "' already in use")

		if contact.get_public_key() == "":
			raise AttributeError("public key missing from contact")

		# take over the reference of contact, caller can drop var
		self.contacts.append(contact)
		self.idx_publickey_contact[contact.get_public_key()] = contact
		self.idx_nick_contact[name] = contact
		if store and self.file != None:
			self.file.write( 
				name + "\t" 
				+ contact.get_public_key().encode("hex") + "\t" 
				+ contact.get_overlay().encode("hex") + "\t" 
				+ contact.get_src().encode("hex") + "\n"
			)
			self.file.flush()
		
		return True


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
	def update_node(self, nodename):
		srckey = self.psses[nodename].get_public_key()
		contacts = []
		for c in self.idx_src_contacts[srckey]:
			self.psses[nodename].add(c)
			contacts.append(c)
		return contacts
					
	
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
					self.add_contact(nick, contact)
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
