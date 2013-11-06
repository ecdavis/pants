###############################################################################
#
# Copyright 2012 Pants Developers (see AUTHORS.txt)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################

import os
import socket
import ssl
import unittest

import pants

from pants.test._pants_util import *

CERT_PATH = os.path.dirname(__file__) + '/cert.pem'
CERT_EXISTS = os.path.exists(CERT_PATH)
SSL_OPTIONS = {
    'server_side': True,
    'certfile': CERT_PATH,
    'keyfile': CERT_PATH
    }

class GoogleClient(pants.Stream):
    def __init__(self, **kwargs):
        pants.Stream.__init__(self, **kwargs)

        self.on_ssl_handshake_called = False
        self.on_connect_called = False
        self.on_read_called = False
        self.on_close_called = False

    def on_ssl_handshake(self):
        self.on_ssl_handshake_called = True

    def on_connect(self):
        self.on_connect_called = True
        self.read_delimiter = '\r\n\r\n'
        self.write("HEAD / HTTP/1.1\r\n\r\n")

    def on_read(self, data):
        self.on_read_called = True
        self.close()

    def on_close(self):
        self.on_close_called = True
        self.engine.stop()

class TestSSLClient(PantsTestCase):
    def setUp(self):
        self.client = GoogleClient(ssl_options={}).connect(('google.com', 443))
        PantsTestCase.setUp(self)

    def test_ssl_client(self):
        self._engine_thread.join(5.0) # Give it plenty of time to talk to Google.
        self.assertTrue(self.client.on_ssl_handshake_called)
        self.assertTrue(self.client.on_connect_called)
        self.assertTrue(self.client.on_read_called)
        self.assertTrue(self.client.on_close_called)

    def tearDown(self):
        PantsTestCase.tearDown(self)
        self.client.close()

class Echo(pants.Stream):
    def on_read(self, data):
        self.write(data)

@unittest.skipIf(not CERT_EXISTS, "no SSL certificate present in unit test directory")
class TestSSLServer(PantsTestCase):
    def setUp(self):
        self.server = pants.Server(ConnectionClass=Echo, ssl_options=SSL_OPTIONS).listen(('127.0.0.1', 4040))
        PantsTestCase.setUp(self)

    def test_ssl_server(self):
        sock = socket.socket()
        sock.settimeout(1.0)
        ssl_sock = ssl.wrap_socket(sock)
        ssl_sock.connect(('127.0.0.1', 4040))
        request = repr(ssl_sock)
        ssl_sock.send(request)
        response = ssl_sock.recv(1024)
        self.assertEqual(response, request)
        ssl_sock.close()

    def tearDown(self):
        PantsTestCase.tearDown(self)
        self.server.close()

class FileSender(pants.Stream):
    def on_connect(self):
        with open(os.path.dirname(__file__) + "/data.txt", 'r') as test_file:
            # The file is flushed here to get around an awkward issue
            # that was only happening with the unit test. sendfile() was
            # blocking for some strange reason.
            self.write_file(test_file, flush=True)

@unittest.skipIf(not CERT_EXISTS, "no SSL certificate present in unit test directory")
class TestSSLSendfile(PantsTestCase):
    def setUp(self):
        self.server = pants.Server(ConnectionClass=FileSender, ssl_options=SSL_OPTIONS).listen(('127.0.0.1', 4040))
        PantsTestCase.setUp(self)

    def test_sendfile(self):
        with open(os.path.dirname(__file__) + "/data.txt", 'r') as test_file:
            expected_data = ''.join(test_file.readlines())

        sock = socket.socket()
        sock.settimeout(1.0)
        ssl_sock = ssl.wrap_socket(sock)
        ssl_sock.connect(('127.0.0.1', 4040))
        actual_data = ssl_sock.recv(1024)
        self.assertEqual(actual_data, expected_data)
        ssl_sock.close()

    def tearDown(self):
        PantsTestCase.tearDown(self)
        self.server.close()
