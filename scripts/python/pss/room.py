class Participant():
	contact = None # Contact type
	trust = 0

	def __init__(self, contact):
		self.contact = contact


class Room:
	name = ""
	participants = {} # Participant type
	
	def __init__(self, name):
		self.name = name	


	def add(self, nick, participant):
		self.participants[nick] = participant	
