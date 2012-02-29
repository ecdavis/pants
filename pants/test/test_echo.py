import socket
import unittest

import pants

from pants.test._pants_util import *

class Echo(pants.Connection):
    def on_read(self, data):
        self.write(data)

class TestEcho(PantsTestCase):
    def setUp(self):
        self.server = pants.Server(Echo).listen(('127.0.0.1', 4040))
        PantsTestCase.setUp(self)

    def test_echo_with_one_client(self):
        sock = socket.socket()
        sock.settimeout(1.0)
        sock.connect(('127.0.0.1', 4040))
        request = repr(sock)
        sock.send(request)
        response = sock.recv(1024)
        self.assertEquals(response, request)
        sock.close()

    def test_echo_with_two_sequential_clients(self):
        sock1 = socket.socket()
        sock1.settimeout(1.0)
        sock1.connect(('127.0.0.1', 4040))
        request1 = repr(sock1)
        sock1.send(request1)
        response1 = sock1.recv(1024)
        self.assertEquals(response1, request1)
        sock1.close()

        sock2 = socket.socket()
        sock2.settimeout(1.0)
        sock2.connect(('127.0.0.1', 4040))
        request2 = repr(sock2)
        sock2.send(request2)
        response2 = sock2.recv(1024)
        self.assertEquals(response2, request2)
        sock2.close()

    def test_echo_with_two_concurrent_clients(self):
        sock1 = socket.socket()
        sock1.settimeout(1.0)
        sock2 = socket.socket()
        sock2.settimeout(1.0)
        sock1.connect(('127.0.0.1', 4040))
        sock2.connect(('127.0.0.1', 4040))
        request1 = repr(sock1)
        request2 = repr(sock2)
        sock1.send(request1)
        sock2.send(request2)
        response1 = sock1.recv(1024)
        response2 = sock2.recv(1024)
        self.assertEquals(response1, request1)
        self.assertEquals(response2, request2)
        sock1.close()
        sock2.close()

    def tearDown(self):
        PantsTestCase.tearDown(self)
        self.server.close()
