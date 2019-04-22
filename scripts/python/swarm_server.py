#!/usr/bin/python3 

import api
import sys
import signal

if __name__ == "__main__":
	try:
		apiserver = api.ApiServer(sys.argv[1], sys.argv[2])
		apiserver.start()
	except Exception as e:
		sys.stderr.write("fail " + sys.argv[1] + "\n")
		raise e
	signal.sigwait([signal.SIGINT, signal.SIGTERM])
	apiserver.stop()
