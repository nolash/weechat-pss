import urllib2
import copy
import re

regexStatusLine = re.compile("^HTTP/1.1 (\d{3}) (.+)\n", re.M)


class Agent:
	sock = None
	up = False
	basereq = None


	
	def __init__(self, host, port, sock):
		# common request params
		self.basereq = urllib2.Request("http://" + host + ":" + str(port) + "/")
		self.basereq.add_header("Connection", "keep-alive")
		self.basereq.add_header("Content-type", "application/x-www-form-urlencoded")
		self.basereq.add_header("Accept", "*/*")
		


	def new_request(self):
		return copy.copy(self.basereq)
	


	def send(self, path, data, querystring=""):
		req = new_request()
		req.add_header("Content-length", str(len(data)))
		req.add_data(data)
		
		requeststring = req.get_method() + " " + path
		if querystring != "":
			requeststring += querystring
		requeststring += " HTTP/1.1\nHost: " + req.get.host() + "\n"
		for (k, v) in req.header_items():
			requeststring += k + ": " + v + "\n"
		requeststring += "\n" + req.get_data()	
		self.sock.send(requeststring)
		r = sock.recv(1024)
		regexStatusLine.match(r)
		if r.groups(1) != "200":
			raise Exception("HTTP send to swarm failed: " + r.groups(0))
