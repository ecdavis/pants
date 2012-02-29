import os.path
import socket
import unittest

import pants

from pants.test._pants_util import *

class FileSender(pants.Connection):
    def on_connect(self):
        with open(os.path.dirname(__file__) + "/data.txt", 'r') as test_file:
            self.write_file(test_file)

class TestSendfile(PantsTestCase):
    def setUp(self):
        self.server = pants.Server(FileSender).listen(('127.0.0.1', 4040))
        PantsTestCase.setUp(self)

    def test_sendfile(self):
        with open(os.path.dirname(__file__) + "/data.txt", 'r') as test_file:
            expected_data = ''.join(test_file.readlines())

        sock = socket.socket()
        sock.settimeout(1.0)
        sock.connect(('127.0.0.1', 4040))
        actual_data = sock.recv(1024)
        self.assertEquals(actual_data, expected_data)
        sock.close()

    def tearDown(self):
        PantsTestCase.tearDown(self)
        self.server.close()
