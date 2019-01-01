import command
import unittest

class TestCommandUntil(unittest.TestCase):
	def test_argsToList(self):
		argList = command.argsToList("  a   command --here   ")

		self.assertEqual(argList[0], "a")
		self.assertEqual(argList[1], "command")
		self.assertEqual(argList[2], "--here")
	
	def test_parseList(self):
		# test a correct connect
		argList = ["connect", "lash", "127.0.0.1"]
		pssName, cmd, params = command.parseList(argList)

		self.assertEqual(pssName, None)
		self.assertEqual(cmd, "connect")
		self.assertEqual(params, ["lash", "127.0.0.1"])

		# test a correct add
		argList = ["me", "add", "lash", "pubkey", "addr"]
		pssName, cmd, params = command.parseList(argList)

		self.assertEqual(pssName, "me")
		self.assertEqual(cmd, "add")
		self.assertEqual(params, ["lash", "pubkey", "addr"])

		# test a correct but abiguous case
		argList = ["send", "add", "lash", "pubkey", "addr"]
		pssName, cmd, params = command.parseList(argList)

		self.assertEqual(pssName, "send")
		self.assertEqual(cmd, "add")
		self.assertEqual(params, ["lash", "pubkey", "addr"])

		# test an unknown command
		argList = ["test", "whatever", "string"]
		with self.assertRaises(command.CommandException) as context:
			command.parseList(argList)
		self.assertTrue("command unknown" in context.exception)

class TestCommandCheck(unittest.TestCase):
	pass

class TestCommandIntegratio(unittest.TestCase):
	def test_parseCommand(self):
		# test a correct connect
		args = "connect   lash   127.0.0.1"
		pssName, cmd, params = command.parseCommand(args)

		self.assertEqual(pssName, None)
		self.assertEqual(cmd, "connect")
		self.assertEqual(params, ["lash", "127.0.0.1"])

		# test a malformed command
		argList = "me connect   lash   127.0.0.1"
		with self.assertRaises(command.CommandException) as context:
			command.parseCommand(argList)
		self.assertTrue("connect command isn't bound to a pssName" in context.exception)

		# test an unknown command
		argList = "test whatever string"
		with self.assertRaises(command.CommandException) as context:
			command.parseCommand(argList)
		self.assertTrue("command unknown" in context.exception)


if __name__ == "__main__":
	unittest.main()
