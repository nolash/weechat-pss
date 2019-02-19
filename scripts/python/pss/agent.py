import urllib2
import copy
import re
import os
import select
import sys
import socket
import time

REQUEST_TIMEOUT = 10.0

regexStatusLine = re.compile("^HTTP/1.1 (\d{3}) (.+)\n", re.M)


class Agent:

	def __init__(self, host="127.0.0.1", port=8500, sock=None):
		# common request params
		if sock == None:
			self._sock = socket.create_connection((host,port))
			sock = self._sock.fileno()
		self.sock = sock	
		self.host = host
		self.port = str(port)
		self.up = False

		self.basereq = urllib2.Request("http://" + host + ":" + str(port) + "/")
		self.basereq.add_header("Connection", "keep-alive")
		self.basereq.add_header("Content-type", "application/x-www-form-urlencoded")
		self.basereq.add_header("Accept", "*/*")
			

	def new_request(self):
		req = urllib2.Request("http://" + self.host + ":" + self.port + "/")
		req.add_header("Connection", "keep-alive")
		req.add_header("Content-type", "application/x-www-form-urlencoded")
		req.add_header("Accept", "*/*")
		return req


	# \todo add retries on select
	def _write(self, requeststring):
		#sys.stderr.write("request: " + repr(requeststring) + "\n" + "len: " + str(len(requeststring)))
		#sys.stderr.write("write sock " + repr(self.sock))
		select.select([], [self.sock], [], REQUEST_TIMEOUT)
		towrite = len(requeststring)
		while towrite > 0:
			written = os.write(self.sock, requeststring)
			#sys.stderr.write("wrote: " + str(written))
			towrite -= written
		select.select([self.sock], [], [], REQUEST_TIMEOUT)
		r = os.read(self.sock, 4104)
		m = regexStatusLine.match(r)
		if m.group(1) != "200":
			print r
			raise Exception("HTTP send to swarm failed: " + str(m.group(0)))

		body = ""
		try:
			_, body  = r.split("\x0d\x0a\x0d\x0a")
		except:
			_, body = r.split("\x0a\x0a")
		return body


	def get(self, path, querystring=""):
		req = self.new_request()
		requeststring = req.get_method() + " " + path
		if querystring != "":
			requeststring += "?" + querystring
		requeststring += " HTTP/1.1\nHost: " + req.get_host() + "\r\n\r\n"
		return self._write(requeststring)


	def send(self, path, data, querystring=""):
		req = self.new_request()
		req.add_header("Content-length", str(len(data)))
		req.add_data(data)
		
		requeststring = req.get_method() + " " + path
		if querystring != "":
			requeststring += "?" + querystring
		requeststring += " HTTP/1.1\nHost: " + req.get_host() + "\r\n"
		for (k, v) in req.header_items():
			requeststring += k + ": " + v + "\r\n"
		requeststring += "\r\n" + req.get_data()
		return self._write(requeststring)

	def close():
		self._sock.close()
