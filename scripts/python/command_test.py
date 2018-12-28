import command
import unittest

class TestCommandUntil(unittest.TestCase):
	def test_argsParse(self):
		argList = command.argsParse("  a   command --here   ")

		self.assertEqual(argList[0], "a")
		self.assertEqual(argList[1], "command")
		self.assertEqual(argList[2], "--here")
	
	def test_split_command(self):
		# test a correct connect
		argList = ["connect", "lash", "127.0.0.1"]
		pssName, cmd, params = command.split(argList)

		self.assertEqual(pssName, None)
		self.assertEqual(cmd, command.CONNECT)
		self.assertEqual(params, ["lash", "127.0.0.1"])

		# test a correct add
		argList = ["me", "add", "lash", "pubkey", "addr"]
		pssName, cmd, params = command.split(argList)

		self.assertEqual(pssName, "me")
		self.assertEqual(cmd, command.ADD)
		self.assertEqual(params, ["lash", "pubkey", "addr"])

		# test an unknown command
		argList = ["test", "whatever", "string"]
		with self.assertRaises(command.CommandException) as context:
			command.split(argList)
		self.assertTrue("command unknown" in context.exception)
