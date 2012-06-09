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

from pants.engine import Engine
from pants._channel import _Channel

class TestChannelConstructorArguments(unittest.TestCase):
    def test_channel_constructor_no_args(self):
        channel = _Channel()
        self.assertTrue(channel.engine is Engine.instance())
        self.assertTrue(channel._socket is None)
        self.assertTrue(channel.fileno is None)
        self.assertTrue(channel.family is None)

    def test_channel_constructor_socket_arg(self):
        sock = socket.socket()
        channel = _Channel(socket=sock)
        self.assertTrue(channel._socket is sock)
        self.assertEquals(channel.fileno, sock.fileno())
        self.assertEquals(channel.family, sock.family)

    def test_channel_constructor_engine_arg(self):
        engine = Engine()
        channel = _Channel(engine=engine)
        self.assertTrue(channel.engine is engine)

class TestChannelEngineInteraction(unittest.TestCase):
    def test_channel_gets_added_to_engine(self):
        engine = Engine()
        channel = _Channel(socket=socket.socket(), engine=engine)
        self.assertTrue(channel in engine._channels.values())
        self.assertTrue(engine._channels[channel.fileno] is channel)

    def test_channel_gets_removed_from_engine(self):
        engine = Engine()
        channel = _Channel(socket=socket.socket(), engine=engine)
        channel.close()
        self.assertTrue(channel.fileno not in engine._channels)
        self.assertTrue(channel not in engine._channels.values())
