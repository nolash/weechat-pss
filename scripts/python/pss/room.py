from contact import PssContact
from bzz import FeedCollection, Feed
from pss import Account


class Participant(PssContact):
	trust = 0


class Room:
	name = ""
	agent = None
	participants = {} # Participant type
	feedcollection = None
	
	def __init__(self, name, agent):
		self.name = name
		self.agent = agent
		self.feedcollection = FeedCollection()


	# \todo do we really need nick in addition to participant.nick here
	def add(self, nick, participant):
		self.participants[nick] = participant
		acc = Account()
		acc.set_address(participant.address)
		participantfeed = Feed(self.agent, acc, participant.nick, False)
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
