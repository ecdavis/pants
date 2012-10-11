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

import base64
import hashlib
import logging
import re
import struct

from pants.util.struct_delimiter import struct_delimiter


###############################################################################
# Constants
###############################################################################

CLOSE_REASONS = {
    1000: 'Normal Closure',
    1001: 'Endpoint Going Away',
    1002: 'Protocol Error',
    1003: 'Unacceptable Data Type',
    1005: 'No Status Code',
    1006: 'Abnormal Close',
    1007: 'Invalid UTF-8 Data',
    1008: 'Message Violates Policy',
    1009: 'Message Too Big',
    1010: 'Extensions Not Present',
    1011: 'Unexpected Condition Prevented Fulfillment',
    1015: 'TLS Handshake Error'
}

# Handshake Key
WEBSOCKET_KEY = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# Supported WebSocket Versions
WEBSOCKET_VERSIONS = (13, 8, 0)

# Frame Opcodes
FRAME_CONTINUATION = 0
FRAME_TEXT = 1
FRAME_BINARY = 2
FRAME_CLOSE = 8
FRAME_PING = 9
FRAME_PONG = 10

# Special read_delimiter Value
EntireMessage = object()

# Regex Stuff
RegexType = type(re.compile(""))


###############################################################################
# Logging
###############################################################################

log = logging.getLogger(__name__)


###############################################################################
# WebSocketConnection Class
###############################################################################

class WebSocketConnection(object):
    """
    An implementation of `WebSockets <http://en.wikipedia.org/wiki/WebSockets>`_
    using the HTTP server provided as :class:`pants.contrib.http.HTTPServer`
    for the initial handshake, and adhering to the Pants design standards.

    Using this class, you can code using the same ``read_delimiter`` and
    named functions you would use when coding with
    :class:`~pants.stream.Stream`. WebSocket negotiation and framing occurs
    transparently.

    =========  ============
    Argument   Description
    =========  ============
    request    The :class:`~pants.contrib.http.HTTPRequest` to begin negotiating WebSockets upon.
    =========  ============
    """
    protocols = None
    read_delimiter = EntireMessage
    regex_search = True

    allow_old_handshake = False

    def __init__(self, request):
        # Store the request and play nicely with web.
        self._connection = request.connection
        request.auto_finish = False

        # Base State
        self.fileno = self._connection.fileno

        self._recv_buffer = ""
        self._read_buffer = u""

        self.connected = False
        self._closed = False

        # Set remote/local address early for on_handshake.
        self._update_address()

        # First up, make sure we're dealing with an actual WebSocket request.
        # If we aren't, return a simple 426 Upgrade Required page.
        fail = False
        headers = {}

        if not request.headers.get('Connection','').lower() == 'upgrade' and \
                not request.headers.get('Upgrade','').lower() == 'websocket':
            fail = True

        # It's a WebSocket. Rejoice. Make sure the handshake information is
        # all acceptable.
        elif not self._safely_call(self.on_handshake, request, headers):
            fail = True

        # Determine which version of WebSockets we're dealing with.
        if 'Sec-WebSocket-Version' in request.headers:
            # New WebSockets. Handshake.
            if not 'Sec-WebSocket-Key' in request.headers:
                fail = True
            else:

                accept = base64.b64encode(hashlib.sha1(
                    request.headers['Sec-WebSocket-Key'] + WEBSOCKET_KEY
                    ).digest())

                headers['Upgrade'] = 'websocket'
                headers['Connection'] = 'Upgrade'
                headers['Sec-WebSocket-Accept'] = accept

                self.version = int(request.headers['Sec-WebSocket-Version'])

                if self.version not in WEBSOCKET_VERSIONS:
                    headers['Sec-WebSocket-Version'] = False
                    fail = True

        elif not self.allow_old_handshake:
            # No old WebSockets allowed.
            fail = True

        else:
            # Old WebSockets. Wut?
            self.version = 0
            self._headers = headers
            self._request = request

            self._connection.on_read = self._finish_handshake
            self._connection.on_close = self._con_close
            self._connection.on_write = self._con_write
            self._connection.read_delimiter = 8
            return

        if fail:
            if 'Sec-WebSocket-Version' in headers:
                request.send_status(400)
                request.send_headers({
                    'Content-Type': 'text/plain',
                    'Content-Length': 15,
                    'Sec-WebSocket-Version': ', '.join(str(x) for x in
                                                        WEBSOCKET_VERSIONS)
                })
                request.send('400 Bad Request')
            else:
                request.send_status(426)
                headers = {
                    'Content-Type': 'text/plain',
                    'Content-Length': '20'
                    }
                request.send_headers(headers)
                request.send("426 Upgrade Required")
            request.finish()
            return

        # Still here? No fail! Send the handshake response, hook up event
        # handlers, and call on_connect.
        request.send_status(101)
        request.send_headers(headers)

        self._connection.on_read = self._con_read
        self._connection.on_close = self._con_close
        self._connection.on_write = self._con_write
        self._connection.read_delimiter = None

        self.connected = True
        self._safely_call(self.on_connect)

    def _finish_handshake(self, key3):
        self._connection.read_delimiter = None
        request = self._request
        headers = self._headers
        del self._headers
        del self._request

        if request.protocol == 'https':
            scheme = 'wss'
        else:
            scheme = 'ws'

        request.send_status(101)
        headers.update({
            'Upgrade': 'WebSocket',
            'Connection': 'Upgrade',
            'Sec-WebSocket-Origin': request.headers['Origin'],
            'Sec-WebSocket-Location': '%s://%s%s' % (
                scheme, request.host, request.uri)
            })
        request.send_headers(headers)

        try:
            request.send(challenge_response(
                request.headers, key3))
        except ValueError:
            log.warning("Malformed WebSocket challenge to %r." % self)
            self.close()
            return

        # Move on.
        self._expect_frame = True

        # Finish up.
        self.connected = True
        self._connection.on_read = self._con_old_read
        self._safely_call(self.on_connect)

    ##### Control Methods #####################################################

    def close(self, flush=False, reason=1000, message=None):
        """
        Close the WebSocket connection. If flush is True, wait for any remaining
        data to be sent and send a close frame before closing the connection.

        =========  ==========  ============
        Argument   Default     Description
        =========  ==========  ============
        flush      ``False``   *Optional.* If True, ensure all the data gets sent before closing.
        reason     ``1000``    *Optional.* The reason the socket is closing, from the ``CLOSE_REASONS`` dictionary.
        message    ``None``    *Optional.* A message string to send with the reason code, rather than the default.
        =========  ==========  ============
        """
        if self._connection is None:
            return

        if flush:
            if not self.version:
                self._connection.close(True)
            else:
                # Look up the reason.
                if not message:
                    message = CLOSE_REASONS.get(reason, 'Unknown Close')
                reason = struct.pack("!H", reason) + message

                self.write(reason, frame=FRAME_CLOSE)
                self._connection.close(True)
            return

        self.read_delimiter = None
        self._read_buffer = u""
        self._recv_buffer = ""

        self.connected = False
        self._closed = True
        self._update_address()

        if self._connection and self._connection.connected:
            self._connection.close()
            self._connection = None

    ##### Public Event Handlers ###############################################

    def on_read(self, data):
        """
        Placeholder. Called when data is read from the WebSocket.

        =========  ============
        Argument   Description
        =========  ============
        data       A chunk of data received from the socket. Binary data will be provided as a string, and text data will be provided as a unicode string.
        =========  ============
        """
        pass

    def on_write(self):
        """
        Placeholder. Called after the WebSocket has finished writing data.
        """
        pass

    def on_connect(self):
        """
        Placeholder. Called after the WebSocket has connected to a client and
        completed its handshake.
        """

    def on_close(self):
        """
        Placeholder. Called after the WebSocket has finished closing.
        """
        pass

    def on_handshake(self, request, headers):
        """
        Placeholder. Called during the initial handshake, making it possible to
        validate the request with custom logic, such as Origin checking and
        other forms of authentication.

        If this function returns False, or a value that would be interpreted
        as False, the handshake will stop and the connection will be aborted.

        =========  ============
        Argument   Description
        =========  ============
        request    The :class:`~pants.contrib.http.HTTPRequest` being upgraded to a WebSocket.
        headers    An empty dict. Any values set here will be sent as headers when accepting (or rejecting) the connection.
        =========  ============
        """
        return True

    ##### I/O Methods #########################################################

    def write(self, data, binary=False, frame=None):
        """
        Write data to the WebSocket.

        ==========  ========  ============
        Arguments   Default   Description
        ==========  ========  ============
        data                  A string of data to write to the WebSocket. Unicode will be converted automatically.
        binary      False     If this is True, the data will be written as a binary frame, rather than text frame.
        ==========  ========  ============
        """
        if self._connection is None:
            log.warning("Attempted to write to closed %r." % self)
            return

        if not self.connected:
            log.warning("Attempted to write to disconnected %r." % self)
            return

        if binary and self.version == 0:
            raise ValueError("Attempted to send binary data to old-version WebSocket.")

        if isinstance(data, unicode):
            data = data.encode('utf-8')
        elif not isinstance(data, str):
            raise ValueError("Only strings may be written to WebSockets.")

        if not binary and '\xFF' in data:
            raise ValueError("Invalid character 0xFF in data to be sent.")

        if not self.version:
            self._connection.write("\x00%s\xFF" % data)
        else:
            if frame is None:
                if binary:
                    frame = 2
                else:
                    frame = 1

            self._connection.write(chr(0x80 | frame))
            if len(data) > 125:
                if len(data) > 65535:
                    self._connection.write(chr(127))
                    self._connection.write(struct.pack("!Q", len(data)))
                else:
                    self._connection.write(chr(126))
                    self._connection.write(struct.pack("!H", len(data)))
            else:
                self._connection.write(chr(len(data)))
            self._connection.write(data)

    ##### Internal Methods ####################################################

    def _safely_call(self, thing_to_call, *args, **kwargs):
        """
        Safely execute a callable.

        The callable is wrapped in a try block and executed. If an
        exception is raised it is logged.

        ==============  ============
        Argument        Description
        ==============  ============
        thing_to_call   The callable to execute.
        *args           The positional arguments to be passed to the callable.
        **kwargs        The keyword arguments to be passed to the callable.
        ==============  ============
        """
        try:
            return thing_to_call(*args, **kwargs)
        except Exception:
            log.exception("Exception raised on %r." % self)

    def _update_address(self):
        """
        Update the WebSocket's ``remote_address`` and ``local_address``
        attributes with the values provided by the associated :class:`~pants.contrib.http.HTTPConnection`.
        """
        if not self._closed and self._connection:
            self.remote_address = self._connection.remote_address
            self.local_address = self._connection.local_address
        else:
            self.remote_address = None
            self.local_address = None

    ##### Internal Event Handler Methods ######################################

    def _con_old_read(self, data):
        """
        Process incoming data, the old way.
        """
        self._recv_buffer += data

        if self._expect_frame:
            self._expect_frame = False
            self._frame = ord(self._recv_buffer[0])
            self._recv_buffer = self._recv_buffer[1:]

            if self._frame & 0x80 == 0x80:
                log.error("Unsupported frame type for old-style WebSockets %02X on %r." %
                    (self._frame, self))
                self.close()
                return

        # Simple Frame.
        ind = self._recv_buffer.find('\xFF')
        if ind == -1:
            return

        # Read the data.
        self._read_buffer += self._recv_buffer[:ind].decode('utf-8')
        self._recv_buffer = self._recv_buffer[ind+1:]
        self._expect_frame = True

        # Act on the data.
        self._process_read_buffer()

    def _con_read(self, data):
        """
        Process incoming data.
        """
        self._recv_buffer += data

        if len(self._recv_buffer) < 2:
            return

        byte1 = ord(self._recv_buffer[0])
        fragment = 0x80 & byte1
        rsv1 = 0x40 & byte1
        rsv2 = 0x20 & byte1
        rsv3 = 0x10 & byte1
        opcode = 0x0F & byte1

        byte2 = ord(self._recv_buffer[1])
        mask = 0x80 & byte2
        length = 0x7F & byte2

        if length == 126:
            if len(self._recv_buffer) < 4:
                return
            length = struct.unpack("!H", self._recv_buffer[2:4])
            headlen = 4

        elif length == 127:
            if len(self._recv_buffer) < 10:
                return
            length = struct.unpack("!Q", self._recv_buffer[2:10])
            headlen = 10

        else:
            headlen = 2

        if mask:
            if len(self._recv_buffer) < headlen + 4:
                return
            mask = [ord(x) for x in self._recv_buffer[headlen:headlen+4]]
            headlen += 4

        if len(self._recv_buffer) < headlen + length:
            return

        # Got a full message!
        data = self._recv_buffer[headlen:headlen+length]
        self._recv_buffer = self._recv_buffer[headlen+length:]

        if mask:
            new_data = ""
            for i in xrange(len(data)):
                new_data += chr(ord(data[i]) ^ mask[i % 4])
            data = new_data
            del new_data

        # Control Frame Nonsense!
        if opcode == FRAME_CLOSE:
            if data:
                reason, = struct.unpack("!H", data[:2])
                message = data[2:]
            else:
                reason = 1000
                message = None

            self.close(True, reason, message)
            return

        elif opcode == FRAME_PING:
            if self.connected:
                self.write(data, frame=FRAME_PONG)

        elif opcode == FRAME_BINARY and self.read_delimiter is EntireMessage:
            self._safely_call(self.on_read, data)
            return

        elif opcode == FRAME_TEXT:
            try:
                data = data.decode('utf-8')
            except UnicodeDecodeError:
                self.close(True, reason=1007)
                return

        else:
            data = data.decode('latin1')

        self._read_buffer += data
        self._process_read_buffer()

    def _con_close(self):
        """
        Close the WebSocket.
        """
        if hasattr(self, '_request'):
            del self._request
        if hasattr(self, '_headers'):
            del self._headers

        self.connected = False
        self._closed = True
        self._update_address()
        self._safely_call(self.on_close)

    def _con_write(self):
        if self.connected:
            self._safely_call(self.on_write)

    ##### Internal Processing Methods #########################################

    def _process_read_buffer(self):
        """
        Process the read_buffer. This is only used when the ReadDelimiter isn't
        EntireMessage.
        """
        while self._read_buffer:
            delimiter = self.read_delimiter

            if delimiter is None or delimiter is EntireMessage:
                data = self._read_buffer
                self._read_buffer = u""
                self._safely_call(self.on_read, data)

            elif isinstance(delimiter, (int, long)):
                if len(self._read_buffer) < delimiter:
                    break
                data = self._read_buffer[:delimiter]
                self._read_buffer = self._read_buffer[delimiter:]
                self._safely_call(self.on_read, data)

            elif isinstance(delimiter, basestring):
                mark = self._read_buffer.find(delimiter)
                if mark == -1:
                    break
                data = self._read_buffer[:mark]
                self._read_buffer = self._read_buffer[mark + len(delimiter):]
                self._safely_call(self.on_read, data)

            elif isinstance(delimiter, struct_delimiter):
                # Use item access because it's faster. This'll need to be
                # changed if struct_delimiter ever changes.
                if len(self._read_buffer) < delimiter[1]:
                    break
                data = self._read_buffer[:delimiter[1]]
                self._read_buffer = self._read_buffer[delimiter[1]:]

                # Safely unpack it. This should *probably* never error.
                try:
                    data = delimiter.unpack(data)
                except struct.error:
                    log.exception("Unable to unpack data on %r." % self)
                    self.close()
                    break

                # Unlike most on_read calls, this one sends every variable of
                # the parsed data as its own argument.
                self._safely_call(self.on_read, *data)

            elif isinstance(delimiter, RegexType):
                # Depending on regex_search, we could do this two ways.
                if self.regex_search:
                    match = delimiter.search(self._read_buffer)
                    if not match:
                        break

                    data = self._read_buffer[:match.start()]
                    self._read_buffer = self._read_buffer[match.end():]

                else:
                    # Require the match to be at the beginning.
                    data = delimiter.match(self._read_buffer)
                    if not data:
                        break

                    self._read_buffer = self._read_buffer[data.end():]

                # Send either the string or the match object.
                self._safely_call(self.on_read, data)

            else:
                log.warning("Invalid read_delimiter on %r." % self)
                break

            if self._connection is None or not self.connected:
                break

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
