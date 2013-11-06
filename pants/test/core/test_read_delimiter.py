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

import json
import re
import socket
import struct
import unittest

import pants

from pants.test._pants_util import *

try:
    import netstruct
except ImportError:
    netstruct = None

class LineOriented(pants.Stream):
    def on_connect(self):
        self.read_delimiter = '\r\n'

    def on_read(self, data):
        self.write(data * 2)

class TestReadDelimiterString(PantsTestCase):
    def setUp(self):
        self.server = pants.Server(ConnectionClass=LineOriented).listen(('127.0.0.1', 4040))
        PantsTestCase.setUp(self)

    def test_read_delimiter_string(self):
        sock = socket.socket()
        sock.settimeout(1.0)
        sock.connect(('127.0.0.1', 4040))
        request = "line1\r\nline2\r\n"
        sock.send(request)
        response = sock.recv(1024)
        sock.close()
        self.assertEqual(response, "line1line1line2line2")

    def tearDown(self):
        PantsTestCase.tearDown(self)
        self.server.close()

class StructOriented(pants.Stream):
    def on_connect(self):
        self.read_delimiter = struct.Struct("!2H")

    def on_read(self, val1, val2):
        self.write(str(val1 * val2))

class TestReadDelimiterStruct(PantsTestCase):
    def setUp(self):
        self.server = pants.Server(StructOriented).listen(('127.0.0.1', 4040))
        PantsTestCase.setUp(self)

    def tearDown(self):
        PantsTestCase.tearDown(self)
        self.server.close()

    def test_read_delimiter_struct(self):
        sock = socket.socket()
        sock.settimeout(1.0)
        sock.connect(('127.0.0.1', 4040))
        sock.send(struct.pack("!2H", 42, 81))
        response = sock.recv(1024)
        sock.close()
        self.assertEqual(int(response), 42*81)

class NetStructOriented(pants.Stream):
    def on_connect(self):
        self.read_delimiter = netstruct.NetStruct("ih$5b")

    def on_read(self, *data):
        self.write(json.dumps(data))

@unittest.skipIf(netstruct is None, "netstruct library not installed")
class TestReadDelimiterNetStruct(PantsTestCase):
    def setUp(self):
        self.server = pants.Server(NetStructOriented).listen(('127.0.0.1', 4040))
        PantsTestCase.setUp(self)

    def tearDown(self):
        PantsTestCase.tearDown(self)
        self.server.close()

    def test_read_delimiter_netstruct(self):
        sock = socket.socket()
        sock.settimeout(1.0)
        sock.connect(('127.0.0.1', 4040))
        print sock.send("\x00\x00\x05\x12\x00\x07default\x00\x00\x01\x00\x08")
        response = sock.recv(1024)
        sock.close()
        self.assertEqual(
            json.loads(response),
            [1298, 'default', 0, 0, 1, 0, 8]
        )

class RegexOriented(pants.Stream):
    def on_connect(self):
        self.read_delimiter = re.compile(r"\s\s+")

    def on_read(self, data):
        self.write(data)

class TestReadDelimiterRegex(PantsTestCase):
    def setUp(self):
        self.server = pants.Server(RegexOriented).listen(('127.0.0.1', 4040))
        PantsTestCase.setUp(self)

    def tearDown(self):
        PantsTestCase.tearDown(self)
        self.server.close()

    def test_read_delimiter_regex(self):
        sock = socket.socket()
        sock.settimeout(1.0)
        sock.connect(('127.0.0.1', 4040))
        sock.send("This is  a test.  ")
        response = sock.recv(1024)
        sock.close()
        self.assertEqual(response, "This isa test.")

class ChunkOriented(pants.Stream):
    def on_connect(self):
        self.read_delimiter = 4

    def on_read(self, data):
        self.write(data * 2)

class TestReadDelimiterChunk(PantsTestCase):
    def setUp(self):
        self.server = pants.Server(ConnectionClass=ChunkOriented).listen(('127.0.0.1', 4040))
        PantsTestCase.setUp(self)

    def test_read_delimiter_number(self):
        sock = socket.socket()
        sock.settimeout(1.0)
        sock.connect(('127.0.0.1', 4040))
        request = ('1' * 4) + ('2' * 4)
        sock.send(request)
        response = sock.recv(1024)
        sock.close()
        self.assertEqual(response, ('1' * 8) + ('2' * 8))

    def tearDown(self):
        PantsTestCase.tearDown(self)
        self.server.close()
