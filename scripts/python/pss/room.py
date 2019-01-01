import json
import copy
import struct

from user import PssContact, Account
from bzz import FeedCollection, Feed
from tools import clean_nick, clean_pubkey, clean_address, clean_name
from message import is_message


class Participant(PssContact):
	trust = 0


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

	# name of room, used for feed topic
	name = ""

	# swarm hsh of serialized representation of room
	hsh = ""

	# Agent object, http transport
	agent = None

	# bzz object
	bzz = None

	# room parameters feed
	feed_room = None

	# Output feed 
	feed_out = None

	# Object representation of participants, Participant type
	participants = None # Participant type

	# Input feed aggregator
	feedcollection_in = None

	def __init__(self, bzz, feed):
		self.agent = feed.agent
		self.feed_room = feed
		self.bzz = bzz
		self.participants = {}
		self.feedcollection_in = FeedCollection()
		

	# sets the name and the room parameter feed
	# used to instantiate a new room
	# \todo valid src parameter
	def start(self, nick, roomname):
		self.name = clean_name(roomname)
		pubkey = "\x04"+self.feed_room.account.publickeybytes
		self.add(nick, Participant(clean_nick(nick), pubkey.encode("hex"), self.feed_room.account.address.encode("hex"), pubkey.encode("hex")))
		self.feed_out = Feed(self.agent, self.feed_room.account, self.name, True)
		self.save()

	
	def can_write(self):
		return self.feed_room.account.is_owner()



	# loads a room from an existing saved record
	# used to reinstantiate an existing room
	# \todo avoid double encoding of account address
	def load(self, hsh, owneraccount=None):
		savedJson = self.bzz.get(hsh.encode("hex"))
		print "savedj " + savedJson
		self.hsh = hsh
		r = json.loads(savedJson)
		self.name = clean_name(r['name'])
		for pubkeyhx in r['participants']:
			acc = Account()
			acc.set_public_key(clean_pubkey(pubkeyhx).decode("hex"))
			nick = acc.address.encode("hex")
			p = Participant(nick, acc.publickeybytes.encode("hex"), acc.address.encode("hex"), "")
			self.add(nick, p)

		# outgoing feed user is room publisher
		if owneraccount == None:
			owneraccount = self.feed_room.account

		self.feed_out = Feed(self.agent, owneraccount, self.name, True)



	# adds a new participant to the room
	# \todo do we really need nick in addition to participant.nick here
	# \todo add save updated participant list to swarm
	def add(self, nick, participant):

		# account reflects the peer's address / key
		acc = Account()
		acc.set_address(clean_address(participant.address).decode("hex"))

		# incoming feed user is peer
		participantfeed_in = Feed(self.agent, acc, self.name, False)
		self.feedcollection_in.add(participant.nick, participantfeed_in)
		self.participants[nick] = participant
		self.save()



	# create new update on outfeed
	# an update has the following format, where p is number of participants:
	# 0 - 31		swarm hash pointing to participant list at time of the update
	# 32 - (32+(p*3))	3 bytes data offset per participant
	# (32+(p*3)) - 		tightly packed update data per participant, in order of offsets
	def send(self, msg, fltrdefaultallow=True, fltr=[]):
		if not is_message(msg):
			raise ValueError("invalid message")

		# update will hold the actual update data
		update_header = copy.copy(self.hsh)
		update_body = ""
		crsr = 0

		for k, v in self.participants.iteritems():
			filtered = False
			if k in fltr and fltrdefaultallow:
				filtered = True
			elif not fltrdefaultallow and not k in fltr:
				filtered = True
			if filtered:	
				sys.stderr.write("Skipping filtered " + k) 
				continue
			
			ciphermsg = v.encrypt_to(msg)
			update_header += struct.pack("<I", crsr)[:3]
			update_body += ciphermsg
			crsr += len(ciphermsg)

		hsh = self.bzz.add(update_header + update_body)
		self.feed_out.update(hsh)
		return hsh

	
	# removes a participant from the room
	# \todo add save updated participant list to swarm
	# \todo pass participant instead?
	def remove(self, nick):
		self.feedcollection_in.remove(nick)
		del self.participants[nick]
		self.save()



	# outputs the serialized format in which the room parameters are stored in swarm
	# \todo proper nested json serialize
	def serialize(self):
		jsonStr = """{
	"name":\"""" + self.name + """\",
	"pubkey":\"0x04""" + self.feed_room.account.publickeybytes.encode("hex") + """\",
	"participants":["""
		#participantList = ""
		for p in self.participants.values():
			jsonStr += "\"" + p.key + "\",\n"
		#	participantList += p.serialize()
		jsonStr = jsonStr[0:len(jsonStr)-2]
		jsonStr += """
	]
}"""
		return jsonStr



	def save(self):
		s = self.serialize()
		self.hsh = self.bzz.add(s).decode("hex")
		return self.hsh
