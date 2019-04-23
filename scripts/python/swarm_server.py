#!/usr/bin/python3 

import api
import sys
import signal

if __name__ == "__main__":
	try:	
		# default host and port
		if len(sys.argv) == 3:
			apiserver = api.ApiServer(sys.argv[1], sys.argv[2])
		# with host
		elif len(sys.argv) == 4:
			apiserver = api.ApiServer(sys.argv[1], sys.argv[2], sys.argv[3])
		# with host and wsport
		elif len(sys.argv) == 5:
			apiserver = api.ApiServer(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
		apiserver.start()
	except Exception as e:
		sys.stderr.write("fail " + sys.argv[1] + "\n")
		raise e
	signal.sigwait([signal.SIGINT, signal.SIGTERM])
	apiserver.stop()
