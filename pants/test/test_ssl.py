import os
import socket
import ssl
import unittest

import pants

from pants.test._pants_util import *

SSL_OPTIONS = {
    'server_side': True,
    'certfile': 'cert.pem',
    'keyfile': 'cert.pem'
    }

class Echo(pants.Connection):
    def on_read(self, data):
        self.write(data)

class TestSSLEcho(PantsTestCase):
    def setUp(self):
        self.server = pants.Server(Echo, ssl_options=SSL_OPTIONS).listen(('127.0.0.1', 4040))
        PantsTestCase.setUp(self)

    def test_ssl_echo(self):
        sock = socket.socket()
        sock.settimeout(1.0)
        ssl_sock = ssl.wrap_socket(sock)
        ssl_sock.connect(('127.0.0.1', 4040))
        request = repr(ssl_sock)
        ssl_sock.send(request)
        response = ssl_sock.recv(1024)
        self.assertEquals(response, request)
        ssl_sock.close()

    def tearDown(self):
        PantsTestCase.tearDown(self)
        self.server.close()

class FileSender(pants.Connection):
    def on_connect(self):
        with open(os.path.dirname(__file__) + "/data.txt", 'r') as test_file:
            # The file is flushed here to get around an awkward issue
            # that was only happening with the unit test. sendfile() was
            # blocking for some strange reason.
            self.write_file(test_file, flush=True)

class TestSSLSendfile(PantsTestCase):
    def setUp(self):
        self.server = pants.Server(FileSender, ssl_options=SSL_OPTIONS).listen(('127.0.0.1', 4040))
        PantsTestCase.setUp(self)

    def test_sendfile(self):
        with open(os.path.dirname(__file__) + "/data.txt", 'r') as test_file:
            expected_data = ''.join(test_file.readlines())

        sock = socket.socket()
        sock.settimeout(1.0)
        ssl_sock = ssl.wrap_socket(sock)
        ssl_sock.connect(('127.0.0.1', 4040))
        actual_data = ssl_sock.recv(1024)
        self.assertEquals(actual_data, expected_data)
        ssl_sock.close()

    def tearDown(self):
        PantsTestCase.tearDown(self)
        self.server.close()
