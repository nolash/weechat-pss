import json
import copy
import struct
import sys

from user import PssContact, Account, publickey_to_address
from bzz import FeedCollection, Feed, zerohsh, new_topic_mask
from tools import clean_pubkey, clean_name, now_int, clean_hex
from message import is_message


class Participant(PssContact):

	
	def __init__(self, nick, src, trusted=False):
		self.trusted = trusted
		PssContact.__init__(self, nick, src)

# Room represents a multi-user chat room
#
# A multi-user chat room is defined solely by a 1-32 byte name, within one single name space,
#
# The Room object contains the collection of feeds to post to
# and the collection of feeds to listen from 
# in order to aggregate the activities of all participants
# 
# An outgoing room feed topic is xor room name xor peer addr, where the user is room owner
# An incoming room feed topic is xor room name xor peer addr, where the user is peer
#
# The room also contains a feed where the topic only xor room name, which contains the participant list of the room and any other relevant parameters. This data structure is stored on swarm in the form provided by the class' serialize method. The user of this feed is room owner.
# 
# \todo consider using feed name for room name
class Room:


	def __init__(self, bzz, name, acc):
		self.name = clean_name(name)
		topic = new_topic_mask(self.name, "", "\x02")
		self.feed_room = Feed(bzz, acc, topic)
		self.bzz = bzz
		self.participants = {}
		self.hsh_room = ""
		

	# sets the name and the room parameter feed
	# used to instantiate a new room
	# \todo valid src parameter
	def start(self, nick, srckey=None):
		#self.feed_out = Feed(self.bzz, self.feed_room.account, self.name, True)
		senderfeed = Feed(self.bzz, self.feed_room.account, new_topic_mask(self.name, "", "\x06"))
		self.feedcollection = FeedCollection("room:"+self.name, senderfeed)

		participant = Participant(nick, srckey)
		participant.set_from_account(self.feed_room.account)
		self.add(nick, participant)


	def get_name(self):
		return self.name


	
	def can_write(self):
		return self.feed_room.account.is_owner()



	def get_state_hash(self):
		return self.feed_room.head()


	
	def get_participants(self):
		return self.participants.values()



	# loads a room from an existing saved record
	# used to reinstantiate an existing room
	# hsh is binary hash
	# \todo avoid double encoding of account address
	# \todo get output update head hash at time of load
	def load(self, hsh, owneraccount=None):
		savedJson = self.bzz.get(hsh.encode("hex"))
		sys.stderr.write("savedj " + repr(savedJson) + " from hash " + hsh.encode("hex") + "\n")
		self.hsh_room = hsh
		r = json.loads(savedJson)
		self.name = clean_name(r['name'])

		# outgoing feed user is room publisher
		if owneraccount == None:
			owneraccount = self.feed_room.account
		senderfeed = Feed(self.bzz, owneraccount, new_topic_mask(self.name, "", "\x06"))
		self.feedcollection = FeedCollection("room:"+self.name, senderfeed)

		for pubkeyhx in r['participants']:
			pubkey = clean_pubkey(pubkeyhx).decode("hex")
			nick = publickey_to_address(pubkey)
			p = Participant(nick.encode("hex"), None)
			p.set_public_key(pubkey)
			try:
				self.add(nick, p, False)
			except Exception as e:
				sys.stderr.write("skipping already added feed: '" + pubkey.encode("hex"))
				
		

	# adds a new participant to the room
	# \todo do we really need nick in addition to participant.nick here
	# \todo add save updated participant list to swarm
	def add(self, nick, participant, save=True):

		topic = new_topic_mask(self.name, "", "\x06")
		participantfeed = Feed(self.bzz, participant, topic)
		self.feedcollection.add(participant.nick, participantfeed)
		self.participants[nick] = participant
		if save:
			self.hsh_room = self.save()



	# create new update on outfeed
	# an update has the following format, where p is number of participants:
	# 0 - 31		swarm hash pointing to participant list at time of the update
	# 32 - (32+(p*3))	3 bytes data offset per participant
	# (32+(p*3)) - 		tightly packed update data per participant, in order of offsets
	# 
	# if filters are used, zero-length update entries will be made for the participants filtered out
	def send(self, msg, fltrdefaultallow=True, fltr=[]):
		if not is_message(msg):
			raise ValueError("invalid message")

		# update will hold the actual update data
		update_header = self.hsh_room 
		
		update_body = ""
		crsr = 0

		for k, v in self.participants.iteritems():
			ciphermsg = ""
			filtered = False
			if k in fltr and fltrdefaultallow:
				filtered = True
			elif not fltrdefaultallow and not k in fltr:
				filtered = True
			if filtered:	
				sys.stderr.write("Skipping filtered " + k) 
			else:
				ciphermsg = v.encrypt_to(msg)

			update_header += struct.pack("<I", crsr)[:3]
			update_body += ciphermsg
			crsr += len(ciphermsg)

		hsh = self.feedcollection.write(update_header + update_body)
		return hsh


	# returns a tuple with previous update hash (in binary) and last time (8 byte int)
	def extract_meta(self, body):
		# two hashes, 8 byte time, 3 byte offset (and no data)
		if len(body) < 72: 
			raise ValueError("invalid update data")
		
		hsh = body[:32]
		tim = struct.unpack(">I", body[32:36])[0]
		serial = body[36]
		return hsh, tim, serial


	# extracts an update message matching the recipient pubkey
	# \todo do not use string literals of offset calcs
	def extract_message(self, body, account):
		participantcount = 0
		payloadoffset = -1
		payloadlength = 0
		ciphermsg = ""

		# retrieve update from swarm
		# body = self.bzz.get(hsh.encode("hex"))

		# if recipient list for the update matches the one in memory
		# we use the position of the participant in the list as the body offset index
		matchidx = -1
		idx = 0
		if self.hsh_room == body[:32]:
			participantcount = len(self.participants)
			for p in self.participants.values():
				if p.get_public_key() == account.get_public_key():
					matchidx = idx
				idx += 1
		# if not we need to retrieve the one that was relevant at the time of update
		# and match the index against that
		else:
			roomhshhx = self.bzz.get(body[:32].encode("hex"))
			savedroom = json.loads(roomhshhx)
			participantcount = len(savedroom['participants'])
			for p in savedroom['participants']:
				sys.stderr.write("participant: " + repr(p) + "\n")
				if clean_hex(p) == clean_pubkey(account.get_public_key().encode("hex")):
					matchidx = idx
				idx += 1

		# if no matches then this pubkey is not relevant for the room at that particular update	
		if matchidx == -1:
			raise ValueError("pubkey " + account.get_public_key().encode("hex") + " not valid for this update")
	
		# parse the position of the update and extract it
		payloadthreshold = 32+(participantcount*3)
		payloadoffsetcrsr = 32+(3*matchidx)
		payloadoffsetbytes = body[payloadoffsetcrsr:payloadoffsetcrsr+3]
		payloadoffset = struct.unpack("<I", payloadoffsetbytes + "\x00")[0]
		if participantcount-1 == matchidx:
			ciphermsg = body[32+(participantcount*3)+payloadoffset:]
		else:
			payloadoffsetcrsr += 3
			payloadoffsetbytes = body[payloadoffsetcrsr:payloadoffsetcrsr+3]
			payloadstop = struct.unpack("<I", payloadoffsetbytes + "\x00")[0]
			ciphermsg = body[payloadthreshold+payloadoffset:payloadthreshold+payloadstop]
	
		return ciphermsg	


	
	# removes a participant from the room
	# \todo add save updated participant list to swarm
	# \todo pass participant instead?
	def remove(self, nick):
		self.feedcollection.remove(nick)
		del self.participants[nick]
		self.save()



	# outputs the serialized format in which the room parameters are stored in swarm
	# \todo proper nested json serialize
	def serialize(self):
		jsonStr = """{
	"name":\"""" + self.name + """\",
	"pubkey":\"0x""" + self.feed_room.account.publickeybytes.encode("hex") + """\",
	"participants":["""
		#participantList = ""
		for k, p in self.participants.iteritems():
			jsonStr += "\"" + p.get_public_key().encode("hex") + "\",\n"
		#	participantList += p.serialize()
		jsonStr = jsonStr[0:len(jsonStr)-2]
		jsonStr += """
	]
}"""
		return jsonStr



	def save(self):
		s = self.serialize()
		self.hsh_room = self.bzz.add(s).decode("hex")
		self.feed_room.update(self.hsh_room)
		return self.hsh_room
