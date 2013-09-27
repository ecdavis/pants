###############################################################################
#
# Copyright 2013 Pants Developers (see AUTHORS.txt)
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
import zlib

import pants

from pants.test._pants_util import *

def decompress_filter():
    obj = zlib.decompressobj()
    data = yield None
    while True:
        out = obj.decompress(data)
        if obj.unused_data:
            yield out + obj.unused_data
            break

        data = yield out

class CompressedStream(pants.Stream):
    def on_connect(self):
        self.set_read_filter(decompress_filter())

    def on_read(self, data):
        self.write(data)

class TestReadFilterZlib(PantsTestCase):
    def setUp(self):
        self.server = pants.Server(ConnectionClass=CompressedStream).listen(('127.0.0.1', 4040))
        PantsTestCase.setUp(self)

    def test_read_filter_zlib(self):
        sock = socket.socket()
        sock.settimeout(1.0)
        sock.connect(('127.0.0.1', 4040))
        request = "x\x9c+\xc9\xc8,V\x00\xa2D\x85\x92\xd4\xe2\x12\x00&3\x05\x16"
        sock.send(request)
        sock.send(" this is a test")
        response = sock.recv(1024)
        sock.close()
        self.assertEquals(response, "this is a test this is a test")

    def tearDown(self):
        PantsTestCase.tearDown(self)
        self.server.close()
