import os
import sys
import unittest

# use with Python 3
# from unittest import mock
# use with Python 2
import mock

# 'weechat' mock, necessary to shut down runtime dependency errors
weechat = mock.Mock()
sys.modules['weechat'] = weechat

# import MUST be done after weechat mock
import singlepss


class TestCommand(unittest.TestCase):
    def test_argsParse(self):
        command, params = singlepss.argsParse("  a   command --here   ")

        # testing command
        self.assertEqual(command, "a")

        # testing param size
        self.assertEqual(len(params), 2)

        # testing param content
        self.assertEqual(params[0], "command")
        self.assertEqual(params[1], "--here")
