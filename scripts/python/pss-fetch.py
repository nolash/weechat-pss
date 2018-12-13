#!/usr/bin/python2

# this script is NOT a plugin script. Don't load it into weechat
# \todo move all json processing to this layer

import websocket
from websocket._exceptions import WebSocketConnectionClosedException
import sys
import json
import os
import socket 
import errno
import time
import tempfile
import select

# our constants
retryDelay = [1, 2, 4, 8, 16, 32]
fifoRetryMax = 4
name = ""
ws = None
connected = False
running = True
fd = -1

def connect_to_ws(host, port, topic):
	""" handles connection to websocket server
	
	returns False on failed attempt, True on success
	"""
	global ws, fd
	r = {}

	# try connect
	try:
		ws = websocket.create_connection("ws://" + host + ":" + port)
	except IOError as e:
		# socket.error is instance of IOError
		if isinstance(e, IOError):
			sys.stderr.write("conn fail " + str(errno.errorcode[e[0]]) + "\n")
		return False 

	# subscribe to incoming events
	ws.send(
		json.dumps(
			{'json-rpc':'2.0','id':0,'method':'pss_subscribe','params':['receive',topic,False,False]}
		)
	)

	# receive and store subscription id
	# (we can't use it for anything yet, though)
	try:
		r = json.loads(ws.recv())
	except IOError as e:
		# socket.error is instance of IOError
		if isinstance(e, IOError):
			sys.stderr.write("recv fail " + str(errno.errorcode[e[0]]) + "\n")
		return False 
	#sub = r['result']

	return True

def connect_delay(s):
	""" creates progressive delay of connection attempts

	"""
	if s > len(retryDelay)-1:
		time.sleep(retryDelay[len(retryDelay)-1])
	else:
		time.sleep(retryDelay[s])
	return
	
if __name__ == "__main__":

	# defaults
	host = "127.0.0.1"
	port = "8546"
	topic = "0xdeadbee2"

	# require name which is used in named pipe
	if len(sys.argv) == 1:
		sys.stderr.write(sys.argv[0] + " <name> [host] [port]" + "\n")
		sys.exit(1)
	name = sys.argv[1]
	
	if len(sys.argv) > 4:
		port = sys.argv[3]	

	if len(sys.argv) > 3:
		host = sys.argv[2]

	# if fifo does not exist, then die
	try:
		fd = os.open(tempfile.gettempdir() + "/pss_weechat_" + name + ".fifo", os.O_WRONLY)
	except OSError as e:
		sys.stderr.write("fifo not available for " + name + "\n")
		sys.exit(1)
	
	# create connections
	i = 0
	while not connected:
		os.write(fd, "\x03")
		connected = connect_to_ws(host, port, topic)
		connect_delay(i)
		i += 1
	os.write(fd, "\x02")

	# poll websocket connection for messages	
	while running:


		# listen on both websocket for receives for forward to fifo
		# and fifo for sends to forward to websocket
		# \todo what happens on disconnect here if the other side writes to fifo
		sys.stderr.write("selection\n")
		rr, wr, xr = select.select([ws, fd], [], [fd])

		for nr in rr:

			# case websocket ready 
			if nr == ws:
				sys.stderr.write("ws read\n")
				msg = ""
				written = False

				# if receive fails due to connection being broken, attempt reconnect until back	
				try:
					msg = ws.recv()
				except WebSocketConnectionClosedException as e:
					print "got exception " + str(type(e))
					connected = False
					os.write(fd, "\x03")
					i = 0
					while not connected:
						connect_delay(i)
						connected = connect_to_ws(host, port, topic)	
						i += 1
					os.write(fd, "\x02")
					continue

				# if temporary fifo problem, try again to write until max attempts
				i = 0
				while not written:	
					try:	
						os.write(fd, msg)
						written = True				
					except OSError as e:
						if i > fifoRetryMax:
							raise RuntimeError("FIFO still unavailable even after " + str(fifoRetryMax) + " tries. Assuming it went away so I'm outta here. Sorry")
						sys.stderr.write("socket error: " + repr(e))
						connect_delay(i)
						i += 1

			# case fifo ready
			elif nr == fd:
				
				msg = ""

				sys.stderr.write("ws write\n")
				# probably we should implement out stream reader here, for now let's just pretend one msg per read, for now let's just pretend one msg per read
				msg = os.read(fd, 5120)

				ws.send(msg)
	
	os.close(fd)
