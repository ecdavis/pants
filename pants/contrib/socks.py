###############################################################################
#
# Copyright 2011-2012 Pants Developers (see AUTHORS.txt)
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

###############################################################################
# Imports
###############################################################################

import socket
import struct

from pants.stream import Stream
import pants.util.dns


###############################################################################
# Constants
###############################################################################

SOCKS_VERSION = '\x05'


###############################################################################
# Exception Types
###############################################################################

class BadVersion(Exception):
    pass


class NoAuthenticationMethods(Exception):
    pass


class Unauthorized(Exception):
    pass


###############################################################################
# The Function
###############################################################################

def do_socks_handshake(self, addr, callback, error_callback=None, auth=None):
    """
    Perform a SOCKSv5 handshake, and call callback when it's completed. If
    authorization data is provided, we'll log onto the server too.

    ===============  ============
    Argument         Description
    ===============  ============
    addr             The address for the proxy server to connect to. This must be a tuple of ``(hostname, port)``.
    callback         A function to call when the handshake has completed.
    error_callback   *Optional.* A function to be called if the handshake has failed.
    auth             *Optional.* If provided, it must be a tuple of ``(username, password)``.
    ===============  ============
    """
    if not self.connected:
        raise RuntimeError("Tried to start SOCKS handshake on disconnected %r." % self)

    # Build our on_read.
    def on_read(data):
        if not self._socks_state:
            if data[0] != SOCKS_VERSION:
                if error_callback:
                    self._safely_call(error_callback,
                        BadVersion("Expected version 5, got %d." % ord(data[0])))
                self.close(False)
                return

            elif (auth and data[1] != '\x02') or (not auth and data[1] != '\x00'):
                if error_callback:
                    self._safely_call(error_callback,
                        NoAuthenticationMethods())
                self.close(False)
                return

            if auth:
                self.write("\x01%d%s%d%s" % (
                    len(auth[0]), auth[0], len(auth[1]), auth[1]))
                self._socks_state = 1

            else:
                self._socks_state = 1
                self.on_read("%s\x00" % SOCKS_VERSION)

        elif self._socks_state == 1:
            if data[0] != SOCKS_VERSION:
                if error_callback:
                    self._safely_call(error_callback,
                        BadVersion("Expected version 5, got %d." % ord(data[0])))
                self.close(False)
                return

            elif data[1] != '\x00':
                if error_callback:
                    self._safely_call(error_callback,
                        Unauthorized(data[1]))
                self.close(False)
                return

            self.write("%s\x01\x00\x03%s%s%s" % (
                SOCKS_VERSION,
                chr(len(addr[0])),
                addr[0],
                struct.pack('!H', addr[1])
                ))
            self._socks_state = 2
            self.read_delimiter = 4

        elif self._socks_state == 2:
            if data[0] != SOCKS_VERSION:
                if error_callback:
                    self._safely_call(error_callback,
                        BadVersion("Expected version 5, got %d." % ord(data[0])))
                self.close(False)
                return

            elif data[1] != '\x00':
                if error_callback:
                    self._safely_call(error_callback,
                        Exception(data[1]))
                self.close(False)
                return

            self._socks_state = 4
            if data[3] == '\x01':
                self._socks_fam = 1
                self.read_delimiter = 4
            elif data[3] == '\x03':
                self._socks_state = 3
                self.read_delimiter = 1
                self._socks_fam = 0
            elif data[3] == '\x04':
                self.read_delimiter = 16
                self._socks_fam = 2

            self._socks_port = struct.unpack("!H", data[-2:])

        elif self._socks_state == 3:
            if self.read_delimiter == 1:
                self._socks_state = 4
                self.read_delimiter = ord(data[0])

        elif self._socks_state == 4:
            if self._socks_fam == 1:
                data = socket.inet_ntop(socket.AF_INET, data)
            elif self._socks_fam == 2:
                try:
                    data = socket.inet_ntop(socket.AF_INET6, data)
                except (AttributeError, socket.error):
                    pass

            self.remote_address = (data, self._socks_port)

            # Cleanup!
            self.on_read = self._socks_read
            self.read_delimiter = self._socks_delim

            del self._socks_read
            del self._socks_delim
            del self._socks_port
            del self._socks_state
            del self._socks_fam

            self._safely_call(callback)

    # Start doing it!
    self._socks_state = 0
    self.write("%s\x01%s" % (
        SOCKS_VERSION, '\x02' if auth else '\x00'))

    self._socks_read = self.on_read
    self._socks_delim = self.read_delimiter
    self.on_read = on_read
    self.read_delimiter = 2

Stream.do_socks_handshake = do_socks_handshake
