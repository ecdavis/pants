###############################################################################
#
# Copyright 2011 Pants (see AUTHORS.txt)
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

import hashlib

from pants import __version__ as pants_version
from http import log

###############################################################################
# WebSocketConnection Class
###############################################################################

class WebSocketConnection(object):
    """
    Provides WebSocket communications on top of pants.contrib.http, using the
    draft-ietf-hybi-thewebsocketprotocol-00 specification.

    This is not a standard pants Connection class, and does not inherit from
    it, but the interface tries to remain the same when at all possible.
    """

    def __init__(self, request, negotiated=False, server=None):
        """
        Initializes the web socket connection using the given request.

        Args:
            request: The request the WebSocket was received through.
            negotiated: Whether or not the WebSocket has already been
                negotiated. If this is False, WebSocketConnection will attempt
                to perform a WebSocket handshake, after which it will call
                handle_connect.
            server: The server to associate this WebSocketConnection with. If
                this isn't provided, it's automatically set to the server of
                the underlying HTTPConnection. This is useful to override if
                you use server.channels to keep track of open connections.
                Optional.
        """
        self._connection    = conn = request.connection
        self._request       = request

        # State Storage
        self._expect_frame  = True
        self._in_buffer     = ""
        self._read_buffer   = u""
        self._state         = 0

        # External Stuff
        self.read_delimiter = None
        self.fileno         = conn.fileno
        self.frame          = None
        self.server         = server or conn.server

        # Connect ourself to the connection.
        conn.handle_read    = self._handle_read_event
        conn.handle_write   = self._handle_write_event
        conn.handle_close   = self._handle_close_event

        # Don't negotiate if not necessary.
        if negotiated:
            self._state = 1
            conn.read_delimiter = None
            return

        # Read the final key for challenge response.
        conn.read_delimiter = 8

    ##### Properties ##########################################################

    @property
    def remote_addr(self):
        """
        The remote address to which the WebSocket is connected.
        """
        return self._connection.remote_addr

    @property
    def local_addr(self):
        """
        The local address of the WebSocket.
        """
        return self._connection.local_addr

    ##### General Methods #####################################################

    def active(self):
        """
        Check if the WebSocket is currently active.

        Returns:
            True or False
        """
        return self._state == 1 and self._connection.active()

    def readable(self):
        """
        Check if the WebSocket is currently readable.

        Returns:
            True or False
        """
        return self._state == 1

    def writable(self):
        """
        Check if the WebSocket is still writing data to the client.

        Returns:
            True or False
        """
        return self._state == 1 and self._connection.writable()

    def close(self):
        """
        Close the WebSocket. Any currently pending data will be sent. Any
        further data will not be sent.
        """
        if not self._connection.active():
            return

        self._state = 3
        self._connection.close()

    def close_immediately(self):
        """
        Close the WebSocket immediately. Pending data will not be sent.
        """
        if not self._connection.active():
            return

        self._connection.close_immediately()

    ##### I/O Methods #########################################################

    def send(self, data):
        """
        A wrapper for WebSocketConnection.write() that can be safely overridden.

        Args:
            data: The data to be sent.
        """
        self.write(data)

    def write(self, data):
        """
        Writes data to the WebSocket.

        Args:
            data: The data to be sent.
        """
        if not self.active():
            raise IOError('Attempted to write to closed WebSocket %d.' % \
                self.fileno)

        if isinstance(data, unicode):
            data = data.encode('utf-8')
        elif not isinstance(data, str):
            raise ValueError('Only strings may be written to sockets.')

        if '\xFF' in data:
            raise ValueError('Invalid character \xFF in data to be sent.')

        self._connection.write('\x00%s\xFF' % data)

    ##### Public Event Handlers ###############################################

    def handle_connect(self):
        """
        Placeholder. Called after the channel has connected to a remote host.
        """
        pass

    def handle_close(self):
        """
        Placeholder. Called when the WebSocket is about to close.
        """
        pass

    def handle_read(self, data):
        """
        Placeholder. Called when the WebSocket receives data.

        Args:
            data: The chunk of received data.
        """
        pass

    def handle_write(self):
        """
        Placeholder. Called when the channel has written a block of data to
        the client.
        """
        pass

    ##### Internal Event Handlers #############################################

    def _handle_close_event(self):
        try:
            self.handle_close()
        finally:
            if self.server is not self._connection.server:
                if self.fileno in self.server.channels:
                    del self.server.channels[self.fileno]

    def _handle_read_event(self, data):
        if self._state == 0:
            self._connection.read_delimiter = None

            # Determine the proper scheme for the handshake.
            if self._request.protocol == 'https':
                scheme = 'wss'
            else:
                scheme = 'ws'

            # Write the handshake.
            self._connection.write(
                "HTTP/1.1 101 Web Socket Protocol Handshake\r\n"
                "Upgrade: WebSocket\r\n"
                "Connection: Upgrade\r\n"
                "Server: HTTPants (pants/%s)\r\n"
                "Sec-WebSocket-Origin: %s\r\n"
                "Sec-WebSocket-Location: %s://%s%s\r\n\r\n" % (
                    pants_version, self._request.headers['Origin'],
                    scheme, self._request.host, self._request.uri
                ))

            try:
                self._connection.write(challenge_response(
                    self._request.headers, data))
            except ValueError:
                log.debug('Malformed WebSocket challenge.')
                self._connection.close_immediately()
                return

            # Success?
            self._state = 2
            return

        elif self._state > 1:
            # Ignore it.
            return

        self._in_buffer += data
        if not self._in_buffer:
            return

        if self._expect_frame:
            self._expect_frame = False
            self.frame = ord(self._in_buffer[0])
            self._in_buffer = self._in_buffer[1:]

            if self.frame & 0x80 == 0x80:
                self._read_frame_length()

        if not self.frame & 0x80:
            # Simple Frame.
            ind = self._in_buffer.find('\xFF')
            if ind == -1:
                return

            # Read the data.
            self._read_buffer += self._in_buffer[:ind].decode('utf-8')
            self._in_buffer = self._in_buffer[ind+1:]
            self._expect_frame = True

        else:
            # Read until we have enough.
            if len(self._in_buffer) > self.frame_length:
                try:
                    self._read_buffer += self._in_buffer[:self.frame_length]
                except UnicodeDecodeError:
                    # Since this is, supposedly, raw data, use latin1 to make
                    # it unicode.
                    self._read_buffer += self._in_buffer[:self.frame_length].\
                        decode('latin1')
                self._in_buffer = self._in_buffer[self.frame_length:]
                self.frame_length = None
                self._expect_frame = True
            else:
                return

        # Act on the data.
        while self._read_buffer:
            rd = self.read_delimiter

            if not rd:
                data = self._read_buffer
                self._read_buffer = u''

            elif isinstance(rd, basestring):
                ind = self._read_buffer.find(rd)
                if ind == -1:
                    break
                data = self._read_buffer[:ind]
                self._read_buffer = self._read_buffer[ind+len(rd):]

            elif isinstance(rd, int):
                if len(self._read_buffer) < rd:
                    break
                data = self._read_buffer[:rd]
                self._read_buffer = self._read_buffer[rd:]

            else:
                break

            self.handle_read(data)

        # Do we still have input buffer?
        if self._in_buffer:
            self._handle_read_event()

    def _handle_write_event(self):
        if not self._connection.writable() and self._state == 2:
            # Make sure our chosen server has us.
            if self.server is not self._connection.server:
                self.server.channels[self.fileno] = self

            self._state = 1
            self.handle_connect()
            return

        self.handle_write()

###############################################################################
# Support Functions
###############################################################################

def challenge_response(headers, key3):
    """
    Calculate the response for a WebSocket security challenge and return it.
    """
    resp = hashlib.md5()

    for key in (headers.get('Sec-WebSocket-Key1'),
                headers.get('Sec-WebSocket-Key2')):
        n = ''
        s = 0
        for c in key:
            if c.isdigit(): n += c
            elif c == ' ': s += 1
        n = int(n)

        if n > 4294967295 or s == 0 or n % s != 0:
            raise ValueError("The provided keys aren't valid.")
        n /= s

        resp.update(
            chr(n >> 24 & 0xFF) +
            chr(n >> 16 & 0xFF) +
            chr(n >> 8  & 0xFF) +
            chr(n       & 0xFF)
        )

    resp.update(key3)
    return resp.digest()
