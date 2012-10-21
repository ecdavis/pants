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
from pants.stream import StreamBufferOverflow

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
# WebSocket Class
###############################################################################

class WebSocket(object):
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
    allow_old_handshake = False

    def __init__(self, request):
        # Store the request and play nicely with web.
        self._connection = request.connection
        self.engine = self._connection.engine
        request.auto_finish = False

        # Base State
        self.fileno = self._connection.fileno
        self._remote_address = None
        self._local_address = None

        # I/O attributes
        self._read_delimiter = EntireMessage
        self._recv_buffer_size_limit = self._buffer_size

        self._recv_buffer = ""
        self._read_buffer = u""

        self.connected = False
        self._closed = False

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
            self.close(False)
            return

        # Move on.
        self._expect_frame = True

        # Finish up.
        self.connected = True
        self._connection.on_read = self._con_old_read
        self._safely_call(self.on_connect)

    ##### Properties ##########################################################

    @property
    def remote_address(self):
        """
        The remote address to which the WebSocket is connected.

        By default, this will be the value of ``socket.getpeername`` or
        None. It is possible for user code to override the default
        behaviour and set the value of the property manually. In order
        to return the property to its default behaviour, user code then
        has to delete the value. Example::

            # default behaviour
            channel.remote_address = custom_value
            # channel.remote_address will return custom_value now
            del channel.remote_address
            # default behaviour
        """
        if self._remote_address is not None:
            return self._remote_address
        elif self._connection:
            return self._connection.remote_address
        else:
            return None

    @remote_address.setter
    def remote_address(self, val):
        self._remote_address = val

    @remote_address.deleter
    def remote_address(self):
        self._remote_address = None

    @property
    def local_address(self):
        """
        The address of the WebSocket on the local machine.

        By default, this will be the value of ``socket.getsockname`` or
        None. It is possible for user code to override the default
        behaviour and set the value of the property manually. In order
        to return the property to its default behaviour, user code then
        has to delete the value. Example::

            # default behaviour
            channel.local_address = custom_value
            # channel.local_address will return custom_value now
            del channel.local_address
            # default behaviour
        """
        if self._local_address is not None:
            return self._local_address
        elif self._connection:
            return self._connection.local_address
        else:
            return None

    @local_address.setter
    def local_address(self, val):
        self._local_address = val

    @local_address.deleter
    def local_address(self):
        self._local_address = None

    @property
    def read_delimiter(self):
        """
        The magical read delimiter which determines how incoming data is
        buffered by the WebSocket.

        As data is read from the socket, it is buffered internally by
        the WebSocket before being passed to the
        :meth:`~pants.http.WebSocket.on_read` callback. The value of the
        read delimiter determines when the data is passed to the
        callback. Valid values are ``None``, a string, an integer/long,
        a compiled regular expression, an instance of
        :class:`pants.struct_delimiter <pants.util.struct_delimiter.struct_delimiter>`,
        or the ``pants.http.EntireMessage`` object.

        When the read delimiter is the ``EntireMessage`` object, entire
        WebSocket messages will be passed to
        :meth:`~pants.http.WebSocket.on_read` immediately, once fully buffered.
        This is the default behavior.

        When the read delimiter is ``None``, data will be passed to
        :meth:`~pants.http.WebSocket.on_read` immediately after it is
        read from the socket.

        When the read delimiter is a string, data will be buffered
        internally until that string is encountered in the incoming
        data. All data up to and including the read delimiter is then
        passed to :meth:`~pants.http.WebSocket.on_read`.

        When the read delimiter is an integer or a long, it is treated
        as the number of bytes to read before passing the data to
        :meth:`~pants.http.WebSocket.on_read`.

        When the read delimiter is a
        :class:`pants.struct_delimiter <pants.util.struct_delimiter.struct_delimiter>`
        instance, the length of the delimiter's format is calculated and
        fully buffered before being parsed and sent to
        :meth:`~pants.http.WebSocket.on_read`. Unlike other types of read
        delimiters, this can result in more than one argument being
        passed to ``on_read``. Example::

            from pants import struct_delimiter
            from pants.http import WebSocket

            class Example(WebSocket):
                def on_connect(self):
                    self.read_delimiter = struct_delimiter("!ILH")

                def on_read(self, packet_type, length, id):
                    pass

        .. seealso::

            ``struct_delimiter`` uses :mod:`struct`, and accepts the
            formatting strings used by :func:`struct.pack` and
            :func:`struct.unpack`. See :ref:`python:struct-format-strings`.

        When the read delimiter is a compiled regular expression, there
        are two possible behaviors, selected by the value of
        :attr:`~pants.http.WebSocket.regex_search`. If ``regex_search``
        is True, as is default, the delimiter's ``search`` method is
        used, and if a match is found, the string before that match is
        passed to :meth:`~pants.http.WebSocket.on_read` while all data up
        to the end of the matched content is removed from the buffer.

        If ``regex_search`` is False, the delimiter's ``match`` method
        is used instead, and if a match is found, the match object
        itself will be passed to :meth:`~pants.http.WebSocket.on_read`,
        giving you access to the capture groups. Again, all data up to
        the end of the matched content is removed from the buffer.

        Attempting to set the read delimiter to any other value will
        raise a :exc:`TypeError`.

        The effective use of the read delimiter can greatly simplify the
        implementation of certain protocols.
        """
        return self._read_delimiter

    @read_delimiter.setter
    def read_delimiter(self, value):
        if value is None or isinstance(value, basestring) or\
           isinstance(value, RegexType):
            self._read_delimiter = value
            self._recv_buffer_size_limit = self._buffer_size

        elif isinstance(value, (int, long)):
            self._read_delimiter = value
            self._recv_buffer_size_limit = max(self._buffer_size, value)

        elif isinstance(value, struct_delimiter):
            self._read_delimiter = value
            self._recv_buffer_size_limit = max(self._buffer_size, value.length)

        elif value is EntireMessage:
            self._read_delimiter = value
            self._recv_buffer_size_limit = self._buffer_size

        else:
            raise TypeError("Attempted to set read_delimiter to a value with an invalid type.")

    # Setting these at the class level makes them easy to override on a
    # per-class basis.
    regex_search = True
    _buffer_size = 2 ** 16  # 64kb

    @property
    def buffer_size(self):
        """
        The maximum size, in bytes, of the internal buffer used for
        incoming data.

        When buffering data it is important to ensure that inordinate
        amounts of memory are not used. Setting the buffer size to a
        sensible value can prevent coding errors or malicious use from
        causing your application to consume increasingly large amounts
        of memory. By default, a maximum of 64kb of data will be stored.

        The buffer size is mainly relevant when using a string value for
        the :attr:`~pants.http.WebSocket.read_delimiter`. Because you
        cannot guarantee that the string will appear, having an upper
        limit on the size of the data is appropriate.

        If the read delimiter is set to a number larger than the buffer
        size, the buffer size will be increased to accommodate the read
        delimiter.

        When the internal buffer's size exceeds the maximum allowed, the
        :meth:`~pants.http.WebSocket.on_overflow_error` callback will be
        invoked.

        Attempting to set the buffer size to anything other than an
        integer or long will raise a :exc:`TypeError`.
        """
        return self._buffer_size

    @buffer_size.setter
    def buffer_size(self, value):
        if not isinstance(value, (long, int)):
            raise TypeError("buffer_size must be an int or a long")
        self._buffer_size = value
        if isinstance(self._read_delimiter, (int, long)):
            self._recv_buffer_size_limit = max(value, self._read_delimiter)
        elif isinstance(self._read_delimiter, struct_delimiter):
            self._recv_buffer_size_limit = max(value,
                self._read_delimiter.length)
        else:
            self._recv_buffer_size_limit = value

    ##### Control Methods #####################################################

    def close(self, flush=True, reason=1000, message=None):
        """
        Close the WebSocket connection. If flush is True, wait for any remaining
        data to be sent and send a close frame before closing the connection.

        =========  ==========  ============
        Argument   Default     Description
        =========  ==========  ============
        flush      ``True``    *Optional.* If False, closes the connection immediately, without ensuring all buffered data is sent.
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

        if self._connection and self._connection.connected:
            self._connection.close(False)
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

    def on_overflow_error(self, exception):
        """
        Placeholder. Called when an internal buffer on the WebSocket has
        exceeded its size limit.

        By default, logs the exception and closes the WebSocket.

        ==========  ============
        Argument    Description
        ==========  ============
        exception   The exception that was raised.
        ==========  ============
        """
        log.exception(exception)
        self.close(reason=1009)

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

    def write_file(self, sfile, nbytes=0, offset=0, flush=False):
        """
        Write a file to the WebSocket.

        This method sends an entire file as one huge binary frame, so be
        careful with how you use it.

        Calling :meth:`write_file()` on a closed or disconnected WebSocket will
        raise a :exc:`RuntimeError`.

        ==========  ====================================================
        Arguments   Description
        ==========  ====================================================
        sfile       A file object to write to the WebSocket.
        nbytes      *Optional.* The number of bytes of the file to
                    write. If 0, all bytes will be written.
        offset      *Optional.* The number of bytes to offset writing
                    by.
        flush       *Optional.* If True, flush the internal write
                    buffer. See :meth:`~pants.stream.Stream.flush` for
                    details.
        ==========  ====================================================
        """
        if self._connection:
            raise RuntimeError("write_file() called on closed %r." % self)
        elif not self.connected:
            raise RuntimeError("write_file() called on disconnected %r." % self)
        elif not self.version:
            raise RuntimeError("Cannot send binary frame on version 0 WebSocket.")

        # Determine the length we're sending.
        current_pos = sfile.tell()
        sfile.seek(0, 2)
        size = sfile.tell()
        sfile.seek(current_pos)

        if offset > size:
            raise ValueError("offset outsize of file size.")
        elif offset:
            size -= offset
        if nbytes < size:
            size = nbytes

        self._connection.write(chr(0x82))
        if size > 125:
            if size > 65535:
                self._connection.write(chr(127) + struct.pack("!Q", size))
            else:
                self._connection.write(chr(126) + struct.pack("!H", size))
        else:
            self._connection.write(chr(size))

        self._connection.write_file(sfile, nbytes, offset, flush)

    def write_packed(self, *data, **kwargs):
        """
        Write packed binary data to the WebSocket.

        The WebSocket must be connected to a remote host. Additionally, the
        current :attr:`read_delimiter` must be an instance of
        :class:`pants.struct_delimiter <pants.util.struct_delimiter.struct_delimiter>`
        if a format argument isn't provided.

        By default, this will send the data as a binary message.

        ==========  ====================================================
        Argument    Description
        ==========  ====================================================
        *data       Any number of values to be passed through
                    :mod:`struct` and written to the remote host.
        format      *Optional.* A formatting string to pack the
                    provided data with. If one isn't provided, the read
                    delimiter will be used.
        binary      *Optional.* Whether or not to send the message as a
                    binary message. Set this to False to send the
                    message as text.
        ==========  ====================================================
        """
        format = kwargs.get("format", None)
        if not format:
            if not isinstance(self._read_delimiter, struct_delimiter):
                raise ValueError("No format is available for writing data with "
                                 "struct.")
            format = self._read_delimiter[0]

        self.write(struct.pack(format, *data), kwargs.get("binary", True))

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
                self.close(False)
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
                self.close(reason=1007)
                return

        else:
            data = data.decode('latin1')

        self._read_buffer += data
        self._process_read_buffer()

        if len(self._read_buffer) > self._recv_buffer_size_limit:
            e = StreamBufferOverflow("Buffer length exceeded upper limit on %r." % self)
            self._safely_call(self.on_overflow_error, e)
            return

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
        self._safely_call(self.on_close)
        self._connection = None

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
            delimiter = self._read_delimiter

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
                    self.close(False)
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
