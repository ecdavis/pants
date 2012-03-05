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

import socket
import unittest

import pants

from pants.test._pants_util import *

class LineOriented(pants.Connection):
    def on_connect(self):
        self.read_delimiter = '\r\n'

    def on_read(self, data):
        self.write(data * 2)

class TestReadDelimiterString(PantsTestCase):
    def setUp(self):
        self.server = pants.Server(LineOriented).listen(('127.0.0.1', 4040))
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

    def tearDown(self):
        PantsTestCase.tearDown(self)
        self.server.close()

class ChunkOriented(pants.Connection):
    def on_connect(self):
        self.read_delimiter = 4

    def on_read(self, data):
        self.write(data * 2)

class TestReadDelimiterChunk(PantsTestCase):
    def setUp(self):
        self.server = pants.Server(ChunkOriented).listen(('127.0.0.1', 4040))
        PantsTestCase.setUp(self)

    def test_read_delimiter_number(self):
        sock = socket.socket()
        sock.settimeout(1.0)
        sock.connect(('127.0.0.1', 4040))
        request = ('1' * 4) + ('2' * 4)
        sock.send(request)
        response = sock.recv(1024)
        self.assertEquals(response, ('1' * 8) + ('2' * 8))
        sock.close()

    def tearDown(self):
        PantsTestCase.tearDown(self)
        self.server.close()
