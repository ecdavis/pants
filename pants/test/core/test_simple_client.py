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
import unittest

import pants

from pants.test._pants_util import *

class GoogleClient(pants.Stream):
    def __init__(self, **kwargs):
        pants.Stream.__init__(self, **kwargs)

        self.on_connect_called = False
        self.on_read_called = False
        self.on_close_called = False

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

class TestSimpleClient(PantsTestCase):
    def setUp(self):
        self.client = GoogleClient()
        PantsTestCase.setUp(self)

    def test_simple_client(self):
        self.client.connect(('google.com', 80))
        self._engine_thread.join(5.0) # Give it plenty of time to talk to Google.
        self.assertTrue(self.client.on_connect_called)
        self.assertTrue(self.client.on_read_called)
        self.assertTrue(self.client.on_close_called)

    @unittest.skip("pants.util.dns is currently disabled")
    def test_simple_client_with_pants_resolve(self):
        # Switched to httpbin.org from google.come because the lack of IPv6
        # routing was making it fail with Google.
        self.client.connect(('httpbin.org', 80), native_resolve=False)
        self._engine_thread.join(5.0) # Give it plenty of time to talk to httpbin.
        self.assertTrue(self.client.on_connect_called)
        self.assertTrue(self.client.on_read_called)
        self.assertTrue(self.client.on_close_called)

    def tearDown(self):
        PantsTestCase.tearDown(self)
        self.client.close()
