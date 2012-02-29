import socket
import unittest

import pants

from pants.test._pants_util import *

class LineOriented(pants.Connection):
    def on_connect(self):
        self.read_delimiter = '\r\n'

    def on_read(self, data):
        self.write(data * 2)

class ChunkOriented(pants.Connection):
    def on_connect(self):
        self.read_delimiter = 4

    def on_read(self, data):
        self.write(data * 2)

class TestReadDelimiter(PantsTestCase):
    def setUp(self):
        self.line_server = pants.Server(LineOriented).listen(('127.0.0.1', 4040))
        self.chunk_server = pants.Server(ChunkOriented).listen(('127.0.0.1', 5050))
        PantsTestCase.setUp(self)

    def test_read_delimiter_string(self):
        sock = socket.socket()
        sock.settimeout(1.0)
        sock.connect(('127.0.0.1', 4040))
        request = "line1\r\nline2\r\n"
        sock.send(request)
        response = sock.recv(1024)
        self.assertEquals(response, "line1line1line2line2")
        sock.close()

    def test_read_delimiter_number(self):
        sock = socket.socket()
        sock.settimeout(1.0)
        sock.connect(('127.0.0.1', 5050))
        request = ('1' * 4) + ('2' * 4)
        sock.send(request)
        response = sock.recv(1024)
        self.assertEquals(response, ('1' * 8) + ('2' * 8))
        sock.close()

    def tearDown(self):
        PantsTestCase.tearDown(self)
        self.line_server.close()
        self.chunk_server.close()
