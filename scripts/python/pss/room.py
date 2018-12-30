import json

from user import PssContact, Account
from bzz import FeedCollection, Feed
from tools import clean_nick, clean_pubkey, clean_address


class Participant(PssContact):
	trust = 0


# \todo consider using feed name for room name
class Room:
	name = ""
	agent = None
	feed = None
	participants = {} # Participant type
	feedcollection = None

	def __init__(self, agent):
		self.agent = agent
		self.feedcollection = FeedCollection()
		

	def set(self, name, mainfeed):
		self.name = clean_nick(name)
		self.feed = mainfeed


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
			

	# \todo do we really need nick in addition to participant.nick here
	def add(self, nick, participant):
		self.participants[nick] = participant
		acc = Account()
		acc.set_address(clean_address(participant.address).decode("hex"))
		roomparticipantname = ""
		namepad = self.name
		nickpad = participant.address[2:].decode("hex")
		while len(namepad) < 32:
			namepad += "\x00"	
		while len(nickpad) < 32:
			nickpad += "\x00"	
		for i in range(32):
			roomparticipantname += chr(ord(namepad[i]) ^ ord(nickpad[i]))

		participantfeed = Feed(self.agent, acc, roomparticipantname, False)
		self.feedcollection.add(participant.nick, participantfeed)


	# \todo pass participant instead?
	def remove(self, nick):
		del self.participants[nick]
		self.feedcollection.remove(nick)


	# \todo proper nested json serialize
	def serialize(self):
		jsonStr = """{
	"name":\"""" + self.name + """\",
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
