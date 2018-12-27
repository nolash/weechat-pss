CONNECT = 1
SET = 2
ADD = 3
SEND = 4
JOIN = 5
INVITE = 6
KEY = 7
ADDR = 8
STOP = 9

class CommandException(Exception):
    pass

string_to_cmd = {
	"connect": CONNECT,
	"set": SET,
	"add": ADD,
	"send": SEND,
	"msg": SEND,
	"join": JOIN,
	"invite": INVITE,
	"key": KEY,
	"pubkey": KEY,
	"address": ADDR,
	"addr": ADDR,
	"stop": STOP,
}

# check functions still need proper error handling
def chk_connect(params):
	if len(params) > 3:
		raise CommandException("too many parameters")
	if len(params) < 1:
		raise CommandException("too few parameters")
	
	#TODO add check regex 

def chk_set(params):
	pass

def chk_add(params):
	pass

def chk_send(params):
	pass

def chk_join(params):
	pass

def chk_invite(params):
	pass

def chk_key(params):
	pass

def chk_addr(params):
	pass

def chk_stop(params):
	pass

cmd_to_checker = {
	CONNECT: chk_connect,
	SET: chk_set,
	ADD: chk_add,
	SEND: chk_send,
	JOIN: chk_join,
	INVITE: chk_invite,
	KEY: chk_key,
	ADDR: chk_addr,
	STOP: chk_stop,
}

# split and isolate pssname, command, and params
# command string can be at position 0 or 1
# if command is at 1, then 0 has to be the name
def split(argList):
	arg_zero = string_to_cmd.get(argList[0])
	if arg_zero != None:
		return (None, arg_zero, argList[1:])
		
	arg_one = string_to_cmd.get(argList[1])
	if arg_one != None and arg_one != CONNECT:
		return (argList[0], arg_one, argList[2:])

	if arg_one == CONNECT:
		raise CommandException("connect command isn't bound to a pssName")

	raise CommandException("command unknown")

# parse args removing white spaces
def argsParse(args):
	argList = args.split(" ")
	argList = [x for x in argList if x != ""]

	return argList

def parseCommand(args):
	argList = argsParse(args)
	pssName, command, params = split(argList)

	check = cmd_to_checker.get(command)
	check(params)

	return (pssName, command, params)