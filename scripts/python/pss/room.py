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

## Room represents a multi-user chat room
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

	## \brief Sets up new feed for room
	#
	# Creates a Feed object from given parameters
	#
	# \param bzz Bzz handler object
	# \param name Name for feed (used as value in high-order bytes of feed topic)
	# \param account Account object containing the key to create the feed with
	def __init__(self, bzz, name, account):
		self.name = clean_name(name)
		topic = new_topic_mask(self.name, "", "\x02")
		self.feed_room = Feed(bzz, account, topic)
		self.bzz = bzz
		self.participants = {}
		self.hsh_room = ""
		

	## \brief Activates room
	#
	# Sets up FeedCollection object for the participants' feeds, and publishes participant list (with self as participant)
	# 
	# sets the name and the room parameter feed
	# \param nick Name to advertise for self
	# \param srckey Public key to register for the outgoing feed for self
	def start(self, nick, srckey=None):
		senderfeed = Feed(self.bzz, self.feed_room.account, new_topic_mask(self.name, "", "\x06"))
		self.feedcollection = FeedCollection("room:"+self.name, senderfeed)

		participant = Participant(nick, srckey)
		participant.set_from_account(self.feed_room.account)
		self.add(nick, participant)


	## Human name of room
	#
	#\return take a wild guess...
	def get_name(self):
		return self.name


	## Check if write to room is possible
	#
	# \return True; if private key for room is available
	def can_write(self):
		return self.feed_room.account.is_owner()



	## Swarm hash of current participant list
	#
	## \return hash, binary format
	def get_state_hash(self):
		return self.feed_room.head()


	## \brief Get all participants in your participant list for the room
	#
	# \return Array of Participant objects	
	def get_participants(self):
		return self.participants.values()



	## Loads a room from an existing saved record
	#
	# used to reinstantiate an existing room
	# \param hsh Swarm hash of participant list in binary
	# \param owneraccount If Account object with private key write access will be enabled
	# \todo avoid double encoding of account address
	# \todo get output update head hash at time of load
	# \todo evaluate whether these todos are stale :D
	def load(self, hsh, owneraccount=None):
		savedJson = self.bzz.get(hsh.encode("hex"))
		#sys.stderr.write("savedj " + repr(savedJson) + " from hash " + hsh.encode("hex") + "\n")
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
				
		

	## Add new participant to room
	#
	# \param nick Name to add participant under
	# \param participant Participant object containing public key of new participant
	# \param save True; save participant list to swarm
	# \todo do we really need nick in addition to participant.nick here
	# \todo is nick relevant here? it's not stored in participant list
	# \todo evaluate whether these todos are stale, too
	def add(self, nick, participant, save=True):

		topic = new_topic_mask(self.name, "", "\x06")
		participantfeed = Feed(self.bzz, participant, topic)
		self.feedcollection.add(participant.nick, participantfeed)
		self.participants[nick] = participant
		if save:
			self.hsh_room = self.save()



	## \brief Create new update in room
	#
	# Adds a new update to the room feed.
	#
	# An update has the following format, where p is number of participants:
	# 0 - 31		swarm hash pointing to participant list at time of the update
	# 32 - (32+(p*3))	3 bytes data offset per participant
	# (32+(p*3)) - 		tightly packed update data per participant, in order of offsets
	# 
	# if filters are used, zero-length update entries will be made for the participants filtered out
	# \param msg Raw message data
	# \param filtrdefaultallow True; activate filter
	# \param fltr Participants Array of Participant objects to omit updates to
	# \todo implement content filtering
	# \todo evaluate if fltrdefaultallow is needed (why not just empty array)
	# \todo filtered content should be 0x800000 in content length instead (that would allow for updates up to 8MB, which is plenty more than should be posted
	# \return Swarm chunk hash of update, binary format
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


	## Extract metadata from response body
	#
	# \param body Raw response body data to parse
	# \return a tuple with previous update hash (in binary), timestamp (4 byte int) and serial (sub-timestamp sequence)
	def extract_meta(self, body):
		# two hashes, 8 byte time, 3 byte offset (and no data)
		if len(body) < 72: 
			raise ValueError("invalid update data")
		
		hsh = body[:32]
		tim = struct.unpack(">I", body[32:36])[0]
		serial = body[36]
		return hsh, tim, serial


	## \brief Extract a participant's message
	# 
	# Extracts an update message matching the recipient pubkey
	#
	# \param body Raw response body data to parse
	# \param account Account with participant's key
	# \return Ciphertext of message (plaintext message as long as crypto is not implemented)
	# \todo do not use string literals of offset calcs
	def extract_message(self, body, account):
		participantcount = 0
		payloadoffset = -1
		payloadlength = 0
		ciphermsg = ""

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


	
	## Remove participant from room
	#
	# \param nick Name key of participant to remove
	# \todo pass participant instead
	def remove(self, nick):
		self.feedcollection.remove(nick)
		del self.participants[nick]
		self.save()



	## \brief Create participant list data
	#
	# outputs the serialized format in which the room parameters are stored in swarm
	#
	# \return json string of participant list  
	# \todo binary serialization instead of json
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


	## Save current participant list to swarm
	#	
	# \return New swarm hash of participant list
	def save(self):
		s = self.serialize()
		self.hsh_room = self.bzz.add(s).decode("hex")
		self.feed_room.update(self.hsh_room)
		return self.hsh_room
