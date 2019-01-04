class CommandException(Exception):
    pass

cmd_list = [
	"connect",
	"set",
	"add",
	"send",
	"msg",
	"join",
	"invite",
	"key",
	"pubkey",
	"address",
	"addr",
	"stop",
]

aliases = {
	"msg": "send",
	"pubkey": "key",
	"address": "addr",
}

# check functions still need proper error handling
def chk_connect(pssName, command, params):
	if pssName != None:
		raise CommandException("connect command isn't bound to a pssName")
	if len(params) > 3:
		raise CommandException("too many parameters")
	if len(params) < 1:
		raise CommandException("too few parameters")
	
	#TODO add check regex 

def chk_set(pssName, command, params):
	pass

def chk_add(pssName, command, params):
	pass

def chk_send(pssName, command, params):
	pass

def chk_join(pssName, command, params):
	pass

def chk_invite(pssName, command, params):
	pass

def chk_key(pssName, command, params):
	pass

def chk_addr(pssName, command, params):
	pass

def chk_stop(pssName, command, params):
	pass

# split and isolate pssname, command, and params
# command string can be at position 0 or 1
# if command is at 1, then 0 has to be the name
def parseList(argList):
	if argList[0] in cmd_list and argList[1] not in cmd_list:
		argList.insert(0, None)

	if argList[1] not in cmd_list:
		raise CommandException("command unknown")
	
	return (argList[0], argList[1], argList[2:])

# parse args removing white spaces
def argsToList(args):
	argList = args.split(" ")
	argList = [x for x in argList if x != ""]

	return argList

def parseCommand(args):
	argList = argsToList(args)
	pssName, alias, params = parseList(argList)
	command = aliases.get(alias, alias)

	globals()["chk_" + command](pssName, command, params)

	return (pssName, command, params)