class Participant():
	contact = None # Contact type
	trust = 0

	def __init__(self, contact):
		self.contact = contact


	def serialize(self):
		return self.contact.serialize()

class Room:
	name = ""
	participants = {} # Participant type
	
	def __init__(self, name):
		self.name = name	


	def add(self, nick, participant):
		self.participants[nick] = participant

	def remove(self, nick, participant):
		del self.participants[nick]


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
