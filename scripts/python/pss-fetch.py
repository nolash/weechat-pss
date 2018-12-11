import websocket
import sys
import json
import os

if __name__ == "__main__":
	ws = websocket.create_connection("ws://" + sys.argv[1] + ":" + sys.argv[2])
	ws.send(
		json.dumps(
			{'json-rpc':'2.0','id':0,'method':'pss_subscribe','params':['receive',sys.argv[3],False,False]}
		)
	)
	ws.recv()
	os.mkfifo("/tmp/pss_gets.fifo", 0666)
	fd = os.open("/tmp/pss_gets.fifo", os.O_WRONLY)
	while 1:
		os.write(fd, ws.recv())
	
	os.close(fd)
	os.unlink("/tmp/pss_gets.fifo")
