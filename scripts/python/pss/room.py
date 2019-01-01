import json

from user import PssContact, Account
from bzz import FeedCollection, Feed
from tools import clean_nick, clean_pubkey, clean_address


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

	# Agent object, http transport
	agent = None

	# room parameters feed
	feed = None

	# Object representation of participants, Participant type
	participants = None # Participant type

	# Input feed aggregator
	feedcollection_in = None

	# Output feed aggregator
	feedcollection_out = None

	def __init__(self, agent, feed):
		self.agent = agent
		self.participants = {}
		self.feed = feed
		self.feedcollection_in = FeedCollection()
		self.feedcollection_out = FeedCollection()
		

	# sets the name and the room parameter feed
	# used to instantiate a new room
	# \todo room param feed should likely be constructed within this method
	def set_name(self, name):
		self.name = clean_nick(name)


	# loads a room from an existing saved record
	# used to reinstantiate an existing room
	# \todo avoid double encoding of account address
	def load(self, savedJson):
		r = json.loads(savedJson)
		self.name = r['name']
		for pubkeyhx in r['participants']:
			acc = Account()
			acc.set_public_key(clean_pubkey(pubkeyhx).decode("hex"))
			nick = acc.address.encode("hex")
			p = Participant(nick, acc.publickeybytes.encode("hex"), acc.address.encode("hex"), "")
			self.add(nick, p)


	# adds a new participant to the room
	# \todo do we really need nick in addition to participant.nick here
	# \todo add save updated participant list to swarm
	def add(self, nick, participant):

		# account reflects the peer's address / key
		acc = Account()
		acc.set_address(clean_address(participant.address).decode("hex"))

		# create the user/room name xor
		roomparticipantname = ""
		namepad = self.name
		nickpad = participant.address[2:].decode("hex")
		while len(namepad) < 32:
			namepad += "\x00"	
		while len(nickpad) < 32:
			nickpad += "\x00"	
		for i in range(32):
			roomparticipantname += chr(ord(namepad[i]) ^ ord(nickpad[i]))

		# incoming feed user is peer
		participantfeed_in = Feed(self.agent, acc, roomparticipantname, False)
		self.feedcollection_in.add(participant.nick, participantfeed_in)

		# outgoing feed user is room publisher
		participantfeed_out = Feed(self.agent, self.feed.account, roomparticipantname, True)
		self.feedcollection_out.add(participant.nick, participantfeed_out)

		self.participants[nick] = participant

	
	# removes a participant from the room
	# \todo add save updated participant list to swarm
	# \todo pass participant instead?
	def remove(self, nick):
		del self.participants[nick]
		self.feedcollection_in.remove(nick)
		self.feedcollection_out.remove(nick)


	# outputs the serialized format in which the room parameters are stored in swarm
	# \todo proper nested json serialize
	def serialize(self):
		jsonStr = """{
	"name":\"""" + self.name + """\",
	"pubkey":\"0x04""" + self.feed.account.publickeybytes.encode("hex") + """\",
	"participants":["""
		#participantList = ""
		for p in self.participants.values():
			jsonStr += "\"" + p.key + "\",\n"
		#	participantList += p.serialize()
		jsonStr = jsonStr[0:len(jsonStr)-2]
		jsonStr += """
	]
}"""
		print jsonStr
		return jsonStr
