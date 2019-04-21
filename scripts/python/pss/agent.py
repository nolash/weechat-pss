from urllib.request import Request
import copy
import re
import os
import select
import sys
import socket
import time

REQUEST_TIMEOUT = 30.0

regexStatusLine = re.compile("^HTTP/1.1 (\d{3}) (.+)\n", re.M)


## \brief Agent handles HTTP requests and responses for swarm
#
# \todo handle with bytes methods only, not string
class Agent:


	## Connects to swarm and sets up base request headers
	#
	# \param host swarm host
	# \param port swarm port
	# \param sock socket.socket object for connection. If None creates a new socket
	def __init__(self, host="127.0.0.1", port=8500, sock=None):
		# common request params
		if sock == None:
			self._sock = socket.create_connection((host,port))
			sock = self._sock.fileno()
		self.fileno = sock
		self._sock.settimeout(None)
		self.host = host
		self.port = str(port)
		self.up = False

		self.debugfile = open("debugsock.log", "a")

		self.basereq = Request("http://" + host + ":" + str(port) + "/")
		self.basereq.add_header("Connection", "keep-alive")
		self.basereq.add_header("Content-type", "application/x-www-form-urlencoded")
		self.basereq.add_header("Accept", "*/*")

	def __del__(self):
		self._sock.close()
		self.debugfile.close()	
	
	
	## creates an urllib.request object with necessary headers
	def new_request(self):
		req = Request("http://" + self.host + ":" + self.port)
		req.add_header("Connection", "keep-alive")
		req.add_header("Content-type", "application/x-www-form-urlencoded")
		req.add_header("Accept", "*/*")
		return req


	# \todo add retries on select
	# \bug must stop read on response threshold!!
	def _write(self, requeststring):
		self.debugfile.write("[" + str(id(self)) + "] request: " + repr(requeststring) + "\n")
		self.debugfile.flush()
		select.select([], [self.fileno], [], REQUEST_TIMEOUT)
		towrite = len(requeststring)
		while towrite > 0:
			written = os.write(self.fileno, requeststring)
			towrite -= written
		# \todo sleep interrupts on select fail signals, need better mechanism for waits (while waiting for external process for handling the io)
		for i in range(100):
			time.sleep(1)
			try:
				select.select([self.fileno], [], [], REQUEST_TIMEOUT)
				#sys.stderr.write("success\n")
				break
			except OSError as e:
				#sys.stderr.write("oserror: " + repr(e) + "\n")
				if e[0] != 11:
					break
			except Exception as e:
				#sys.stderr.write("othererror: " + repr(e) + "\n")
				if e[0] != 4:
					break
		r = os.read(self.fileno, 4104)
		self.debugfile.write("[" + str(id(self)) + "] response: " + repr(r) + "\n")
		try:
			(head, body) = r.split(b"\x0d\x0a\x0d\x0a")
		except:
			try:
				(head, body) = r.split(b"\x0a\x0a")
			except:
				raise ValueError("invalid http body", r)

		rhead = head.decode("ascii")
		m = regexStatusLine.match(rhead)
		if m.group(1) != "200":
			raise Exception("HTTP send to swarm failed: " + str(m.group(0)))

		return body


	## performs a HTTP GET to swarm
	#
	# \param path the path to GET
	# \param querystring query string to add
	# \return response body
	def get(self, path, querystring=""):
		req = self.new_request()
		requestpath = path
		if querystring != "":
			requestpath += "?" + querystring
		requeststring = serialize_request(req, requestpath)
		return self._write(requeststring)


	## performs a HTTP POST to Swarm
	#
	# \param path the path to POST
	# \param data data payload
	# \param querystring query string to add
	# \return response body
	# \todo check if we use querystring here
	def send(self, path, data, querystring=""):

		req = self.new_request()
		req.data = data
		req.add_header("Content-length", str(len(data)))

		requestpath = path
		if querystring != "":
			requestpath += "?" + querystring
		requeststring = serialize_request(req, requestpath)	
		return self._write(requeststring)


	## close the TCP socket connection to Swarm
	def close(self):
		pass


## returns Request object serialized as literal HTTP request in bytes object
#
# \param req Request object
# \return HTTP request in bytes
def serialize_request(req, path):
	requeststring = bytes(req.get_method() + " " + path, "ascii")
	requeststring += bytes(" HTTP/1.1\nHost: " + req.host + "\n", "ascii")
	for (k, v) in req.header_items():
		requeststring += bytes(k + ": " + v + "\n", "ascii")
	if req.data != None:
		requeststring += b"\n" + req.data
	else:
		requeststring += b"\n"
	return requeststring
