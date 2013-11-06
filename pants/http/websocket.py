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
"""
``pants.http.websocket`` implements the WebSocket protocol, as described by
:rfc:`6455`, on top of the Pants HTTP server using an API similar to that
provided by :class:`pants.stream.Stream`.


Using WebSockets
================

To start working with WebSockets, you'll need to create a subclass of
:class:`WebSocket`. As with :class:`~pants.stream.Stream`, :class:`WebSocket`
instances are meant to contain the majority of your networking logic through
the definition of custom event handlers. Event handlers are methods that have
names beginning with ``on_`` that can be safely overridden within
your subclass.


Listening for Connections
-------------------------

:class:`WebSocket` is designed to be used as a request handler for the Pants
HTTP server, :class:`pants.http.server.HTTPServer`. As such, to begin listening
for WebSocket connections, you must create an instance of
:class:`~pants.http.server.HTTPServer` using your custom :class:`WebSocket`
subclass as its request handler.

.. code-block:: python

    from pants.http import HTTPServer, WebSocket
    from pants import Engine

    class EchoSocket(WebSocket):
        def on_read(self, data):
            self.write(data)

    HTTPServer(EchoSocket).listen(8080)
    Engine.instance().start()

If you need to host traditional requests from your HTTPServer instance, you may
invoke the WebSocket handler simply by creating an instance of your
:class:`WebSocket` subclass with the appropriate
:class:`pants.http.server.HTTPRequest` instance as its only argument:

.. code-block:: python

    from pants.http import HTTPServer, WebSocket
    from pants import Engine

    class EchoSocket(WebSocket):
        def on_read(self, data):
            self.write(data)

    def request_handler(request):
        if request.path == '/_ws':
            EchoSocket(request)
        else:
            request.send_response("Nothing to see here.")

    HTTPServer(request_handler).listen(8080)
    Engine.instance().start()


``WebSocket`` and ``Application``
---------------------------------

:class:`WebSocket` has support for :class:`pants.web.application.Application`
and can easily be used as a request handler for any route. Additionally,
variables captured from the URL by :class:`~pants.web.application.Application`
will be made accessible to the :meth:`WebSocket.on_connect` event handler. The
following example of a WebSocket echo server displays a customized welcome
message depending on the requested URL.

.. code-block:: python

    from pants.http import WebSocket
    from pants.web import Application

    app = Application()

    @app.route("/ws/<name>")
    class EchoSocket(WebSocket):
        def on_connect(self, name):
            self.write(u"Hello, {name}!".format(name=name))

        def on_read(self, data):
            self.write(data)

    app.run(8080)


WebSocket Security
==================

Secure Connections
------------------

:class:`WebSocket` relies upon the :class:`pants.http.server.HTTPServer`
instance serving it to provide SSL. This can be as easy as calling the server's
:meth:`~pants.http.server.HTTPServer.startSSL` method.

To determine whether or not the :class:`WebSocket` instance is using a
secure connection, you may use the :attr:`~WebSocket.is_secure` attribute.


Custom Handshakes
-----------------

You may implement custom logic during the WebSocket's handshake by overriding
the :meth:`WebSocket.on_handshake` event handler. The ``on_handshake`` handler
is called with a reference to the :class:`~pants.http.server.HTTPRequest`
instance the WebSocket handshake is happening upon as well as an empty
dictionary that may be used to set custom headers on the HTTP response.

``on_handshake`` is expected to return a True value if the request is alright.
Returning a False value will result in the generation of an error page. The
following example of a custom handshake requires a secret HTTP header in the
request, and that the connection is secured:

.. code-block:: python

    from pants.http import WebSocket

    class SecureSocket(WebSocket):
        def on_handshake(self, request, headers):
            return self.is_secure and 'X-Pizza' in request.headers

        def on_connect(self):
            self.write(u"Welcome to PizzaNet.")


Reading and Writing Data
========================

WebSockets are a bit different than normal :class:`~pants.stream.Stream`
instances, as a WebSocket can transmit both byte strings and unicode strings,
and data is encapsulated into formatted messages with definite lengths. Because
of this, reading from one can be slightly different.

Mostly, however, the :attr:`~WebSocket.read_delimiter` works in exactly the
same way as that of :class:`pants.stream.Stream`.

Unicode Strings and Byte Strings
--------------------------------

:class:`WebSocket` strictly enforces the difference between byte strings and
unicode strings. As such, the connection will be closed with a protocol error
if any of the following happen:

    1.  The string types of the :attr:`~WebSocket.read_delimiter` and the
        buffer differ.

    2.  There is an existing string still in the buffer when the client sends
        another string of a different type.

    3.  The :attr:`~WebSocket.read_delimiter` is currently a struct and the
        buffer does not contain a byte string.

Of those conditions, the most likely to occur is the first. Take the following
code:

.. code-block:: python

    from pants.http import WebSocket, HTTPServer
    from pants import Engine

    def process(text):
        return text.decode('rot13')

    class LineOriented(WebSocket):
        def on_connect(self):
            self.read_delimiter = "\\n"

        def on_read(self, line):
            self.write(process(line))

    HTTPServer(LineOriented).listen(8080)
    Engine.instance().start()

And, on the client:

.. code-block:: html

    <!DOCTYPE html>
    <textarea id="editor"></textarea><br>
    <input type="submit" value="Send">
    <script>
        var ws = new WebSocket("ws://localhost:8080/"),
            input = document.querySelector('#editor'),
            button = document.querySelector('input');

        ws.onmessage = function(e) {
            alert("Got back: " + e.data);
        }

        button.addEventListener("click", function() {
            ws.send(input.value + "\\n");
        });
    </script>

On Python 2.x, the read delimiter will be a byte string. The WebSocket will
expect to receive a byte string. However, the simple JavaScript shown above
sends *unicode* strings. That simple service would fail immediately
on Python 2.

To avoid the problem, be sure to use the string type you really want for your
read delimiters. For the above, that's as simple as setting the read
delimiter with:

.. code-block:: python

    self.read_delimiter = u"\\n"


WebSocket Messages
------------------

In addition to the standard types of :attr:`~WebSocket.read_delimiter`,
:class:`WebSocket` instances support the use of a special value called
:attr:`EntireMessage`. When using ``EntireMessage``, full messages will
be sent to your :attr:`~WebSocket.on_read` event handler, as framed by
the remote end-point.

``EntireMessage`` is the default :attr:`~WebSocket.read_delimiter` for
WebSocket instances, and it makes it dead simple to write simple services.

The following example implements a simple RPC system over WebSockets:

.. code-block:: python

    import json

    from pants.http.server import HTTPServer
    from pants.http.websocket import WebSocket, FRAME_TEXT
    from pants import Engine

    class RPCSocket(WebSocket):
        methods = {}

        @classmethod
        def method(cls, name):
            ''' Add a method to the RPC. '''
            def decorator(method):
                cls.methods[name] = method
                return method
            return decorator

        def json(self, **data):
            ''' Send a JSON object to the remote end-point. '''
            # JSON outputs UTF-8 encoded text by default, so use the frame
            # argument to let WebSocket know it should be sent as text to the
            # remote end-point, rather than as binary data.
            self.write(json.dumps(data), frame=FRAME_TEXT)

        def on_read(self, data):
            # Attempt to decode a JSON message.
            try:
                data = json.loads(data)
            except ValueError:
                self.json(ok=False, result="can't decode JSON")
                return

            # Lookup the desired method. Return an error if it doesn't exist.
            method = data['method']
            if not method in self.methods:
                self.json(ok=False, result="no such method")
                return

            method = self.methods[method]
            args = data.get("args", tuple())
            kwargs = data.get("kwargs", dict())
            ok = True

            # Try running the method, and capture the result. If it errors, set
            # the result to the error string and ok to False.
            try:
                result = method(*args, **kwargs)
            except Exception as ex:
                ok = False
                result = str(ex)

            self.json(ok=ok, result=result)


    @RPCSocket.method("rot13")
    def rot13(string):
        return string.decode("rot13")

    HTTPServer(RPCSocket).listen(8080)
    Engine.instance().start()

As you can see, it never even *uses* :attr:`~WebSocket.read_delimiter`. The
client simply sends JSON messages, with code such as:

.. code-block:: javascript

    my_websocket.send(JSON.stringify({method: "rot13", args: ["test"]}));

This behavior is completely reliable, even when the client is sending
fragmented messages.

"""

###############################################################################
# Imports
###############################################################################

import base64
import hashlib
import re
import struct
import sys

if sys.platform == "win32":
    from time import clock as time
else:
    from time import time

from pants.stream import StreamBufferOverflow
from pants.http.utils import log

try:
    from netstruct import NetStruct as _NetStruct
except ImportError:
    # Create the fake class because isinstance expects a class.
    class _NetStruct(object):
        def __init__(self, *a, **kw):
            raise NotImplementedError


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
Struct = struct.Struct

# Structs
STRUCT_H = Struct("!H")
STRUCT_Q = Struct("!Q")


###############################################################################
# WebSocket Class
###############################################################################

class WebSocket(object):
    """
    An implementation of `WebSockets <http://en.wikipedia.org/wiki/WebSockets>`_
    on top of the Pants HTTP server using an API similar to that of
    :class:`pants.stream.Stream`.

    A :class:`WebSocket` instance represents a WebSocket connection to a
    remote client. In the future, WebSocket will be modified to support acting
    as a client in addition to acting as a server.

    When using WebSockets you write logic as you could for
    :class:`~pants.stream.Stream`, using the same :attr:`read_delimiter` and
    event handlers, while the WebSocket implementation handles the initial
    negotiation and all data framing for you.

    =========  ============
    Argument   Description
    =========  ============
    request    The :class:`~pants.http.server.HTTPRequest` to begin negotiating a WebSocket connection over.
    =========  ============
    """

    protocols = None
    allow_old_handshake = False

    def __init__(self, request, *arguments):
        # Store the request and play nicely with web.
        self._connection = request.connection
        self.engine = self._connection.engine
        request.auto_finish = False
        self._arguments = arguments

        # Base State
        self.fileno = self._connection.fileno
        self._remote_address = None
        self._local_address = None
        self._pings = {}
        self._last_ping = 0

        # I/O attributes
        self._read_delimiter = EntireMessage
        self._recv_buffer_size_limit = self._buffer_size

        self._recv_buffer = ""
        self._read_buffer = None
        self._rb_type = None
        self._frag_frame = None

        self.connected = False
        self._closed = False

        # Copy the HTTPRequest's security state.
        self.is_secure = request.is_secure

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
                    'Content-Length': '20',
                    'Sec-WebSocket-Version': ', '.join(str(x) for x in
                        WEBSOCKET_VERSIONS)
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
        self._safely_call(self.on_connect, *self._arguments)
        del self._arguments


    def _finish_handshake(self, key3):
        self._connection.read_delimiter = None
        request = self._request
        headers = self._headers
        del self._headers
        del self._request

        scheme = 'wss' if self.is_secure else 'ws'

        request.send_status(101)
        headers.update({
            'Upgrade': 'WebSocket',
            'Connection': 'Upgrade',
            'Sec-WebSocket-Origin': request.headers['Origin'],
            'Sec-WebSocket-Location': '%s://%s%s' % (
                scheme, request.host, request.url)
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
        self._safely_call(self.on_connect, *self._arguments)
        del self._arguments


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
        the WebSocket before being passed to the :meth:`on_read` callback. The
        value of the read delimiter determines when the data is passed to the
        callback. Valid values are ``None``, a string, an integer/long,
        a compiled regular expression, an instance of :class:`struct.Struct`,
        an instance of :class:`netstruct.NetStruct`, or the
        :attr:`~pants.http.websocket.EntireMessage` object.

        When the read delimiter is the ``EntireMessage`` object, entire
        WebSocket messages will be passed to :meth:`on_read` immediately once
        they have been received in their entirety. This is the default behavior
        for :class:`WebSocket` instances.

        When the read delimiter is ``None``, data will be passed to
        :meth:`on_read` immediately after it has been received.

        When the read delimiter is a byte string or unicode string, data will
        be buffered internally until that string is encountered in the incoming
        data. All data up to but excluding the read delimiter is then passed
        to :meth:`on_read`. The segment matching the read delimiter itself is
        discarded from the buffer.

        .. note::

            When using strings as your read delimiter, you must be careful to
            use unicode strings if you wish to send and receive strings to a
            remote JavaScript client.

        When the read delimiter is an integer or a long, it is treated
        as the number of bytes to read before passing the data to
        :meth:`on_read`.

        When the read delimiter is an instance of :class:`struct.Struct`, the
        Struct's ``size`` is fully buffered and the data is unpacked before the
        unpacked data is sent to :meth:`on_read`. Unlike other types of read
        delimiters, this can result in more than one argument being sent to the
        :meth:`on_read` event handler, as in the following example::

            import struct
            from pants.http import WebSocket

            class Example(WebSocket):
                def on_connect(self):
                    self.read_delimiter = struct.Struct("!ILH")

                def on_read(self, packet_type, length, id):
                    pass

        You must send binary data from the client when using structs as your
        read delimiter. If Pants receives a unicode string while a struct
        read delimiter is set, it will close the connection with a protocol
        error. This holds true for the :class:`~netstruct.Netstruct`
        delimiters as well.

        When the read delimiter is an instance of :class:`netstruct.NetStruct`,
        the NetStruct's :attr:`~netstruct.NetStruct.minimum_size` is buffered
        and unpacked with the NetStruct, and additional data is buffered as
        necessary until the NetStruct can be completely unpacked. Once ready,
        the data will be passed to :meth:`on_read`. Using Struct and NetStruct
        are *very* similar.

        When the read delimiter is a compiled regular expression
        (:class:`re.RegexObject`), there are two possible behaviors that you
        may switch between by setting the value of :attr:`regex_search`. If
        :attr:`regex_search` is True, as is the default, the delimiter's
        :meth:`~re.RegexObject.search` method is used and, if a match is found,
        the string before that match is passed to :meth:`on_read`. The segment
        that was matched by the regular expression will be discarded.

        If :attr:`regex_search` is False, the delimiter's
        :meth:`~re.RegexObject.match` method is used instead and, if a match
        is found, the match object itself will be passed to :meth:`on_read`,
        giving you access to the capture groups. Again, the segment that was
        matched by the regular expression will be discarded from the buffer.

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

        elif isinstance(value, Struct):
            self._read_delimiter = value
            self._recv_buffer_size_limit = max(self._buffer_size, value.size)

        elif isinstance(value, _NetStruct):
            self._read_delimiter = value
            self._recv_buffer_size_limit = max(self._buffer_size,
                                               value.minimum_size)

        elif value is EntireMessage:
            self._read_delimiter = value
            self._recv_buffer_size_limit = self._buffer_size

        else:
            raise TypeError("Attempted to set read_delimiter to a value with an invalid type.")

        # Reset NetStruct state when we change the read delimiter.
        self._netstruct_iter = None
        self._netstruct_needed = None


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
        the :attr:`read_delimiter`. Because you cannot guarantee that the
        string will appear, having an upper limit on the size of the data
        is appropriate.

        If the read delimiter is set to a number larger than the buffer
        size, the buffer size will be increased to accommodate the read
        delimiter.

        When the internal buffer's size exceeds the maximum allowed, the
        :meth:`on_overflow_error` callback will be invoked.

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
        elif isinstance(self._read_delimiter, Struct):
            self._recv_buffer_size_limit = max(value,
                self._read_delimiter.size)
        elif isinstance(self._read_delimiter, _NetStruct):
            self._recv_buffer_size_limit = max(value,
                self._read_delimiter.minimum_size)
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
        reason     ``1000``    *Optional.* The reason the socket is closing, as defined at :rfc:`6455#section-7.4`.
        message    ``None``    *Optional.* A message string to send with the reason code, rather than the default.
        =========  ==========  ============
        """
        if self._connection is None or self._closed:
            return

        self.read_delimiter = None
        self._read_buffer = None
        self._rb_type = None
        self._recv_buffer = ""
        self._closed = True

        if flush:
            if not self.version:
                self._connection.close(True)
            else:
                # Look up the reason.
                if not message:
                    message = CLOSE_REASONS.get(reason, 'Unknown Close')
                reason = STRUCT_H.pack(reason) + message

                self.write(reason, frame=FRAME_CLOSE)
                self._connection.close(True)
                self.connected = False
                self._connection = None
            return

        self.connected = False

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
        data       A chunk of data received from the socket. Binary data will be provided as a byte string, and text data will be provided as a unicode string.
        =========  ============
        """
        pass


    def on_write(self):
        """
        Placeholder. Called after the WebSocket has finished writing data.
        """
        pass


    def on_connect(self, *arguments):
        """
        Placeholder. Called after the WebSocket has connected to a client and
        completed its handshake. Any additional arguments passed to the
        :class:`WebSocket` instance's constructor will be passed to this
        method when it is invoked, making it easy to use :class:`WebSocket`
        together with the URL variables captured by
        :class:`pants.web.application.Application`, as shown in the
        following example::

            from pants.web import Application
            from pants.http import WebSocket

            app = Application()
            @app.route("/ws/<int:id>")
            class MyConnection(WebSocket):
                def on_connect(self, id):
                    pass
        """
        pass


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

        If this function returns a False value, the handshake will be stopped
        and an error will be sent to the client.

        =========  ============
        Argument   Description
        =========  ============
        request    The :class:`pants.http.server.HTTPRequest` being upgraded to a WebSocket.
        headers    An empty dict. Any values set here will be sent as headers when accepting (or rejecting) the connection.
        =========  ============
        """
        return True


    def on_pong(self, data):
        """
        Placeholder. Called when a PONG control frame is received from the
        remote end-point in response to an earlier ping.

        When used together with the :meth:`ping` method, ``on_pong`` may be
        used to measure the connection's round-trip time. See :meth:`ping` for
        more information.

        =========  ============
        Argument   Description
        =========  ============
        data       Either the RTT expressed as seconds, or an arbitrary byte string that served as the PONG frame's payload.
        =========  ============
        """
        pass


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

    def ping(self, data=None):
        """
        Write a ping frame to the WebSocket. You may, optionally, provide a
        byte string of data to be used as the ping's payload. When the
        end-point returns a PONG, and the :meth:`on_pong` method is called,
        that byte string will be provided to ``on_pong``. Otherwise, ``on_pong``
        will be called with the elapsed time.

        =========  ============
        Argument   Description
        =========  ============
        data       *Optional.* A byte string of data to be sent as the ping's payload.
        =========  ============
        """
        if data is None:
            self._last_ping += 1
            data = str(self._last_ping)
            self._pings[data] = time()

        self.write(data, FRAME_PING)


    def write(self, data, frame=None, flush=False):
        """
        Write data to the WebSocket.

        Data will not be written immediately, but will be buffered internally
        until it can be sent without blocking the process.

        Calling :meth:`write` on a closed or disconnected WebSocket will raise
        a :exc:`RuntimeError`.

        If data is a unicode string, the data will be sent to the remote
        end-point as text using the frame opcode for text. If data is a byte
        string, the data will be sent to the remote end-point as binary data
        using the frame opcode for binary data. If you manually specify a frame
        opcode, the provided data *must* be a byte string.

        An appropriate header for the data will be generated by this method,
        using the length of the data and the frame opcode.

        ==========  ============================================================
        Arguments   Description
        ==========  ============================================================
        data        A string of data to write to the WebSocket. Unicode will be
                    converted automatically.
        frame       *Optional.* The frame opcode for this message.
        flush       *Optional.* If True, flush the internal write buffer. See
                    :meth:`pants.stream.Stream.flush` for details.
        ==========  ============================================================
        """
        if self._connection is None:
            raise RuntimeError("write() called on closed %r" % self)

        if not self.connected:
            raise RuntimeError("write() called on disconnected %r." % self)

        if frame is None:
            if isinstance(data, unicode):
                frame = FRAME_TEXT
                data = data.encode('utf-8')
            elif isinstance(data, bytes):
                frame = FRAME_BINARY
            else:
                raise TypeError("data must be unicode or bytes")

        elif frame == FRAME_TEXT:
            if isinstance(data, unicode):
                data = data.encode('utf-8')
            elif not isinstance(data, bytes):
                raise TypeError("data must be bytes or unicode for FRAME_TEXT.")

        elif not isinstance(data, bytes):
            raise TypeError("data must be bytes for frames other "
                            "than FRAME_TEXT.")

        if self.version == 0:
            if frame != FRAME_TEXT:
                raise TypeError("Attempted to send non-unicode data across "
                                "outdated WebSocket protocol.")

            self._connection.write(b"\x00" + data + b"\xFF", flush=flush)
            return

        header = chr(0x80 | frame)
        plen = len(data)
        if plen > 65535:
            header += b"\x7F" + STRUCT_Q.pack(plen)
        elif plen > 125:
            header += b"\x7E" + STRUCT_H.pack(plen)
        else:
            header += chr(plen)

        self._connection.write(header + data, flush=flush)


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
        if not self._connection:
            raise RuntimeError("write_file() called on closed %r." % self)
        elif not self.connected:
            raise RuntimeError("write_file() called on disconnected %r." % self)
        elif not self.version:
            raise TypeError("Attempted to send non-unicode data across "
                            "outdated WebSocket protocol.")

        # Determine the length we're sending.
        current_pos = sfile.tell()
        sfile.seek(0, 2)
        size = sfile.tell()
        sfile.seek(current_pos)

        if offset > size:
            raise ValueError("offset outsize of file size.")
        elif offset:
            size -= offset

        if nbytes == 0:
            nbytes = size
        elif nbytes < size:
            size = nbytes

        header = b"\x82"
        if size > 65535:
            header += b"\x7F" + STRUCT_Q.pack(size)
        elif size > 125:
            header += b"\x7E" + STRUCT_H.pack(size)
        else:
            header += chr(size)

        self._connection.write(header)
        self._connection.write_file(sfile, nbytes, offset, flush)


    def write_packed(self, *data, **kwargs):
        """
        Write packed binary data to the WebSocket.

        Calling :meth:`write_packed` on a closed or disconnected WebSocket will
        raise a :exc:`RuntimeError`.

        If the current :attr:`read_delimiter` is an instance of
        :class:`struct.Struct` or :class:`netstruct.NetStruct` the format
        will be read from that Struct, otherwise you will need to provide
        a ``format``.

        ==========  ====================================================
        Argument    Description
        ==========  ====================================================
        \*data      Any number of values to be passed through
                    :mod:`struct` and written to the remote host.
        format      *Optional.* A formatting string to pack the
                    provided data with. If one isn't provided, the read
                    delimiter will be used.
        flush       *Optional.* If True, flush the internal write
                    buffer. See :meth:`~pants.stream.Stream.flush` for
                    details.
        ==========  ====================================================
        """
        frame = kwargs.get("frame", FRAME_BINARY)

        if not self._connection:
            raise RuntimeError("write_packed() called on closed %r." % self)
        elif not self.connected:
            raise RuntimeError("write_packed() called on disconnected %r."
                               % self)
        elif not self.version and frame != FRAME_TEXT:
            raise TypeError("Attempted to send non-unicode data across "
                            "outdated WebSocket protocol.")

        format = kwargs.get("format", None)
        flush = kwargs.get("flush", False)

        if format:
            self.write(struct.pack(format, *data), frame=frame, flush=flush)

        elif not isinstance(self._read_delimiter, (Struct, _NetStruct)):
            raise ValueError("No format is available for writing packed data.")

        else:
            self.write(self._read_delimiter.pack(*data), frame=frame, flush=flush)


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

        while len(self._recv_buffer) >= 2:
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
                if len(self._recv_buffer) > self._recv_buffer_size_limit:
                    # TODO: Callback for handling this event?
                    self.close(reason=1009)
                return

            # Read the data.
            try:
                data = self._recv_buffer[:ind].decode('utf-8')
            except UnicodeDecodeError:
                self.close(reason=1007)
                return

            if not self._read_buffer:
                self._read_buffer = data
                self._rb_type = type(self._read_buffer)
            else:
                self._read_buffer += data

            self._recv_buffer = self._recv_buffer[ind+1:]
            self._expect_frame = True

            # Act on the data.
            self._process_read_buffer()


    def _con_read(self, data):
        """
        Process incoming data.
        """
        self._recv_buffer += data

        while len(self._recv_buffer) >= 2:
            byte1 = ord(self._recv_buffer[0])
            final = 0x80 & byte1
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
                length = STRUCT_H.unpack(self._recv_buffer[2:4])
                headlen = 4

            elif length == 127:
                if len(self._recv_buffer) < 10:
                    return
                length = STRUCT_Q.unpack(self._recv_buffer[2:10])
                headlen = 10

            else:
                headlen = 2

            if mask:
                if len(self._recv_buffer) < headlen + 4:
                    return
                mask = [ord(x) for x in self._recv_buffer[headlen:headlen+4]]
                headlen += 4

            total_size = headlen + length
            if len(self._recv_buffer) < total_size:
                if len(self._recv_buffer) > self._recv_buffer_size_limit:
                    # TODO: Callback for handling this event?
                    self.close(reason=1009)
                return

            # Got a full message!
            data = self._recv_buffer[headlen:total_size]
            self._recv_buffer = self._recv_buffer[total_size:]

            if mask:
                new_data = ""
                for i in xrange(len(data)):
                    new_data += chr(ord(data[i]) ^ mask[i % 4])
                data = new_data
                del new_data

            # Control Frame Nonsense!
            if opcode == FRAME_CLOSE:
                if data:
                    reason = STRUCT_H.unpack(data[:2])[0]
                    message = data[2:]
                else:
                    reason = 1000
                    message = None

                self.close(True, reason, message)
                return

            elif opcode == FRAME_PING:
                if self.connected:
                    self.write(data, frame=FRAME_PONG)

            elif opcode == FRAME_PONG:
                sent = self._pings.pop(data, None)
                if sent:
                    data = time() - sent

                self._safely_call(self.on_pong, data)
                return

            elif opcode == FRAME_CONTINUATION:
                if not self._frag_frame:
                    self.close(reason=1002)
                    return

                opcode = self._frag_frame
                self._frag_frame = None

            if opcode == FRAME_TEXT:
                try:
                    data = data.decode('utf-8')
                except UnicodeDecodeError:
                    self.close(reason=1007)
                    return

            if not self._read_buffer:
                self._read_buffer = data
                self._rb_type = type(data)
            elif not isinstance(data, self._rb_type):
                # TODO: Improve wrong string type handling with event handler.
                log.error("Received string type not matching buffer on %r." % self)
                self.close(reason=1002)
                return
            else:
                self._read_buffer += data

            if not final:
                if not opcode in (FRAME_BINARY, FRAME_TEXT):
                    log.error("Received fragment control frame on %r." % self)
                    self.close(reason=1002)
                    return

                self._frag_frame = opcode
                if self._read_delimiter is EntireMessage:
                    return

            self._process_read_buffer()

            if self._read_buffer and len(self._read_buffer) > self._recv_buffer_size_limit:
                e = StreamBufferOverflow("Buffer length exceeded upper limit "
                                         "on %r." % self)
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
                self._read_buffer = None
                self._rb_type = None
                self._safely_call(self.on_read, data)

            elif isinstance(delimiter, (int, long)):
                size = len(self._read_buffer)
                if size < delimiter:
                    break
                elif size == delimiter:
                    data = self._read_buffer
                    self._read_buffer = None
                    self._rb_type = None
                else:
                    data = self._read_buffer[:delimiter]
                    self._read_buffer = self._read_buffer[delimiter:]

                self._safely_call(self.on_read, data)

            elif isinstance(delimiter, (bytes, unicode)):
                if not isinstance(delimiter, self._rb_type):
                    log.error("buffer string type doesn't match read_delimiter "
                              "on %r." % self)
                    self.close(reason=1002)
                    break

                mark = self._read_buffer.find(delimiter)
                if mark == -1:
                    break
                else:
                    data = self._read_buffer[:mark]
                    self._read_buffer = self._read_buffer[mark + len(delimiter):]
                    if not self._read_buffer:
                        self._read_buffer = None
                        self._rb_type = None

                self._safely_call(self.on_read, data)

            elif isinstance(delimiter, Struct):
                if self._rb_type is not bytes:
                    log.error("buffer is not bytes for struct read_delimiter "
                              "on %r." % self)
                    self.close(reason=1002)
                    break

                size = len(self._read_buffer)
                if size < delimiter.size:
                    break
                elif size == delimiter.size:
                    data = self._read_buffer
                    self._read_buffer = None
                    self._rb_type = None
                else:
                    data = self._read_buffer[:delimiter.size]
                    self._read_buffer = self._read_buffer[delimiter.size:]

                # Safely unpack it. This should *probably* never error.
                try:
                    data = delimiter.unpack(data)
                except struct.error:
                    log.exception("Unable to unpack data on %r." % self)
                    self.close(reason=1002)
                    break

                # Unlike most on_read calls, this one sends every variable of
                # the parsed data as its own argument.
                self._safely_call(self.on_read, *data)

            elif isinstance(delimiter, _NetStruct):
                if self._rb_type is not bytes:
                    log.error("buffer is not bytes for struct read_delimiter "
                              "on %r." % self)
                    self.close(reason=1002)
                    break

                if not self._netstruct_iter:
                    # We need to get started.
                    self._netstruct_iter = delimiter.iter_unpack()
                    self._netstruct_needed = next(self._netstruct_iter)

                size = len(self._read_buffer)
                if size < self._netstruct_needed:
                    break
                elif size == self._netstruct_needed:
                    data = self._read_buffer
                    self._read_buffer = None
                    self._rb_type = None
                else:
                    data = self._read_buffer[:self._netstruct_needed]
                    self._read_buffer = self._read_buffer[self._netstruct_needed:]

                data = self._netstruct_iter.send(data)
                if isinstance(data, (int, long)):
                    self._netstruct_needed = data
                    continue

                # Still here? Then we've got an object. Delete the NetStruct
                # state and send the data.
                self._netstruct_needed = None
                self._netstruct_iter = None

                self._safely_call(self.on_read, *data)

            elif isinstance(delimiter, RegexType):
                if not isinstance(delimiter.pattern, self._rb_type):
                    log.error("buffer string type does not match "
                              "read_delimiter on %r." % self)
                    self.close(reason=1002)
                    break

                # Depending on regex_search, we could do this two ways.
                if self.regex_search:
                    match = delimiter.search(self._read_buffer)
                    if not match:
                        break

                    data = self._read_buffer[:match.start()]
                    self._read_buffer = self._read_buffer[match.end():]
                    if not self._read_buffer:
                        self._read_buffer = None
                        self._rb_type = None

                else:
                    # Require the match to be at the beginning.
                    data = delimiter.match(self._read_buffer)
                    if not data:
                        break

                    self._read_buffer = self._read_buffer[data.end():]
                    if not self._read_buffer:
                        self._read_buffer = None
                        self._rb_type = None

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
