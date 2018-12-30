from user import PssContact, Account
from bzz import FeedCollection, Feed
from tools import clean_nick


class Participant(PssContact):
	trust = 0


# \todo consider using feed name for room name
class Room:
	name = ""
	agent = None
	feed = None
	participants = {} # Participant type
	feedcollection = None
	
	def __init__(self, name, agent, mainfeed):
		self.name = clean_nick(name)
		self.agent = agent
		self.feed = mainfeed
		self.feedcollection = FeedCollection()


	# \todo do we really need nick in addition to participant.nick here
	def add(self, nick, participant):
		self.participants[nick] = participant
		acc = Account()
		acc.set_address(participant.address)
		roomparticipantname = ""
		namepad = self.name
		nickpad = participant.nick
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
	"participants":{"""
		#participantList = ""
		for p in self.participants.values():
			jsonStr += p.serialize() + ","
		#	participantList += p.serialize()
		jsonStr = jsonStr[0:len(jsonStr)-1]
		jsonStr += """
	}
}"""
		return jsonStr
