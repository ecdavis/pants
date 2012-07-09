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
Streaming connection channel. Used to develop streaming client and
server connection handlers.
"""

###############################################################################
# Imports
###############################################################################

import errno
import functools
import os
import socket
import ssl

from pants._channel import _Channel, HAS_IPV6
from pants.engine import Engine


###############################################################################
# Logging
###############################################################################

import logging
log = logging.getLogger("pants")


###############################################################################
# Stream Class
###############################################################################

class Stream(_Channel):
    """
    The stream-oriented connection channel.

    A :class:`~pants.stream.Stream` instance represents either a local
    connection to a remote server or a remote connection to a local
    server over a streaming, connection-oriented protocol such as TCP.

    =================  ================================================
    Keyword Argument   Description
    =================  ================================================
    engine             *Optional.* The engine to which the channel
                       should be added. Defaults to the global engine.
    socket             *Optional.* A pre-existing socket to wrap. This
                       can be a regular :obj:`~socket.socket` or an
                       :obj:`~ssl.SSLSocket`. If a socket is not
                       provided, a new socket will be created for the
                       channel when required.
    ssl_options        *Optional.* If provided,
                       :meth:`~pants.stream.Stream.startSSL` will be
                       called with these options once the stream is
                       ready. By default, SSL will not be enabled.
    =================  ================================================
    """
    SEND_STRING = 0
    SEND_FILE = 1
    SEND_SSL_HANDSHAKE = 2

    def __init__(self, **kwargs):
        sock = kwargs.get("socket", None)
        if sock and sock.type != socket.SOCK_STREAM:
            raise TypeError("Cannot create a %s with a socket type other than SOCK_STREAM."
                    % self.__class__.__name__)

        _Channel.__init__(self, **kwargs)

        # Socket
        self._remote_address = None
        self._local_address = None

        # I/O attributes
        self.read_delimiter = None
        self._recv_buffer = ""
        self._recv_buffer_size_limit = 2 ** 16  # 64kb
        self._send_buffer = []

        # Channel state
        self.connected = False
        self.connecting = False
        self._closing = False

        # SSL state
        self.ssl_enabled = False
        self._ssl_enabling = False
        self._ssl_socket_wrapped = False
        self._ssl_handshake_done = False
        self._ssl_call_on_connect = False
        if isinstance(kwargs.get("socket", None), ssl.SSLSocket):
            self._ssl_socket_wrapped = True
            self.startSSL()
        elif kwargs.get("ssl_options", None) is not None:
            self.startSSL(kwargs["ssl_options"])

    ##### Properties ##########################################################

    @property
    def remote_address(self):
        """
        """
        if self._remote_address is not None:
            return self._remote_address
        elif self._socket:
            return self._socket.getpeername()
        else:
            return None
    
    @remote_address.setter
    def remote_address(self, val):
        self._remote_address = val

    @property
    def local_address(self):
        """
        """
        if self._remote_address is not None:
            return self._local_address
        elif self._socket:
            return self._socket.getsockname()
        else:
            return None
    
    @local_address.setter
    def local_address(self, val):
        self._local_address = val

    @property
    def read_delimiter(self):
        """
        The magical read delimiter which determines how incoming data is
        buffered by the stream.

        As data is read from the socket, it is buffered internally by
        the stream before being passed to the
        :meth:`~pants.stream.Stream.on_read` callback. The value of the
        read delimiter determines when the data is passed to the
        callback. Valid values are ``None``, a string, or an
        integer/long.

        When the read delimiter is ``None``, data will be passed to
        :meth:`~pants.stream.Stream.on_read` immediately after it is
        read from the socket. This is the default behaviour.

        When the read delimiter is a string, data will be buffered
        internally until that string is encountered in the incoming
        data. All data up to and including the read delimiter is then
        passed to :meth:`~pants.stream.Stream.on_read`.

        When the read delimiter is an integer or a long, it is treated
        as the number of bytes to read before passing the data to
        :meth:`~pants.stream.Stream.on_read`.

        Attempting to set the read delimiter to any other value will
        raise a :exc:`TypeError`.

        The effective use of the read delimiter can greatly simplify the
        implementation of certain protocols.
        """
        return self._read_delimiter

    @read_delimiter.setter
    def read_delimiter(self, value):
        if value is None or isinstance(value, basestring):
            self._read_delimiter = value
            self._recv_buffer_size_limit = self._buffer_size

        elif isinstance(value, (int, long)):
            self._read_delimiter = value
            self._recv_buffer_size_limit = max(self._buffer_size, value)

        else:
            raise TypeError("read_delimiter must be None, a string, an int, or a long")

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
        the :attr:`~pants.stream.Stream.read_delimiter`. Because you
        cannot guarantee that the string will appear, having an upper
        limit on the size of the data is appropriate.

        If the read delimiter is set to a number larger than the buffer
        size, the buffer size will be increased to accommodate the read
        delimiter.

        When the internal buffer's size exceeds the maximum allowed, the
        :meth:`~pants.stream.Stream.on_overflow_error` callback will be
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
        else:
            self._recv_buffer_size_limit = value

    ##### Control Methods #####################################################

    def startSSL(self, ssl_options={}):
        """
        Enable SSL on the channel and perform a handshake at the next
        opportunity.

        SSL is only enabled on a channel once all currently pending data
        has been written. If a problem occurs at this stage,
        :meth:`~pants.stream.Stream.on_ssl_error` is called. Once SSL
        has been enabled, the SSL handshake begins - this typically
        takes some time and may fail, in which case
        :meth:`~pants.stream.Stream.on_ssl_handshake_error` will be
        called. When the handshake is successfully completed,
        :meth:`~pants.stream.Stream.on_ssl_handshake` is called and the
        channel is secure.

        Typically, this method is called before
        :meth:`~pants.stream.Stream.connect`. In this case,
        :meth:`~pants.stream.Stream.on_ssl_handshake` will be called
        before :meth:`~pants.stream.Stream.on_connect`. If
        :meth:`~pants.stream.Stream.startSSL` is called after
        :meth:`~pants.stream.Stream.connect`, the reverse is true.

        It is possible, although unusual, to start SSL on a channel that
        is already connected and active. In this case, as noted above,
        SSL will only be enabled and the handshake performed after all
        currently pending data has been written.

        The SSL options argument will be passed through to
        :func:`ssl.wrap_socket` as keyword arguments - see the
        :mod:`ssl` documentation for further information. You will
        typically want to provide the ``keyfile``, ``certfile`` and
        ``ca_certs`` options. The ``do_handshake_on_connect`` option
        **must** be ``False``, or a :exc:`ValueError` will be raised.

        Attempting to enable SSL on a closed channel or a channel that
        already has SSL enabled on it will raise a :exc:`RuntimeError`.

        Returns the channel.

        ============ ===================================================
        Arguments    Description
        ============ ===================================================
        ssl_options  *Optional.* Keyword arguments to pass to
                     :func:`ssl.wrap_socket`.
        ============ ===================================================
        """
        if self.ssl_enabled or self._ssl_enabling:
            raise RuntimeError("startSSL() called on SSL-enabled %r" % self)

        if self._closed or self._closing:
            raise RuntimeError("startSSL() called on closed %r" % self)

        if ssl_options.setdefault("do_handshake_on_connect", False) is not False:
            raise ValueError("SSL option 'do_handshake_on_connect' must be False.")

        self._ssl_enabling = True
        self._send_buffer.append((Stream.SEND_SSL_HANDSHAKE, ssl_options))

        if self.connected:
            self._process_send_buffer()

        return self

    def connect(self, address, native_resolve=True):
        """
        Connect the channel to a remote socket.

        The given ``address`` is resolved and used by the channel to
        connect to the remote server. If an error occurs at any stage in
        this process, :meth:`~pants.stream.Stream.on_connect_error` is
        called. When a connection is successfully established,
        :meth:`~pants.stream.Stream.on_connect` is called.

        Addresses can be represented in a number of different ways. A
        single string is treated as a UNIX address. A single integer is
        treated as a port and converted to a 2-tuple of the form
        ``('', port)``. A 2-tuple is treated as an IPv4 address and a
        4-tuple is treated as an IPv6 address. See the :mod:`socket`
        documentation for further information on socket addresses.

        If no socket exists on the channel, one will be created with a
        socket family appropriate for the given address.

        An error will occur during the connection if the given address
        is not of a valid format or of an inappropriate format for the
        socket (e.g. if an IP address is given to a UNIX socket).

        Calling :meth:`connect()` on a closed channel or a channel that
        is already connected will raise a :exc:`RuntimeError`.

        Returns the channel.

        ===============  ===============================================
        Arguments        Description
        ===============  ===============================================
        address          The remote address to connect to.
        native_resolve   *Optional.* If True, use Python's builtin
                         address resolution. Otherwise, Pants'
                         non-blocking address resolution will be used.
        ===============  ===============================================
        """
        if self.connected or self.connecting:
            raise RuntimeError("connect() called on active %r." % self)

        if self._closed or self._closing:
            raise RuntimeError("connect() called on closed %r." % self)

        self.connecting = True

        address, family = self._format_address(address)
        if native_resolve:
            self._do_connect(address, family)
        else:
            self._resolve_addr(address, family, self._do_connect)

        return self

    def close(self, flush=False):
        """
        Close the channel.
        """
        if self._closed:
            return

        if flush and self._send_buffer:
            self._closing = True
            return

        self.read_delimiter = None
        self._recv_buffer = ""
        self._send_buffer = []

        self.connected = False
        self.connecting = False

        self.ssl_enabled = False
        self._ssl_enabling = False
        self._ssl_socket_wrapped = False
        self._ssl_handshake_done = False
        self._ssl_call_on_connect = False

        self._safely_call(self.on_close)

        self._remote_address = None
        self._local_address = None

        _Channel.close(self)

        self._closing = False

    ##### I/O Methods #########################################################

    def write(self, data, flush=False):
        """
        Write data to the channel.

        Data will not be written immediately, but will be buffered
        internally until it can be sent without blocking the process.

        Calling :meth:`write()` on a closed or disconnected channel will
        raise a :exc:`RuntimeError`.

        ==========  ===================================================
        Arguments   Description
        ==========  ===================================================
        data        A string of data to write to the channel.
        flush       *Optional.* If True, flush the internal write
                    buffer. See :meth:`~pants.stream.Stream.flush` for
                    details.
        ==========  ===================================================
        """
        if self._closed or self._closing:
            raise RuntimeError("write() called on closed %r." % self)

        if not self.connected:
            raise RuntimeError("write() called on disconnected %r." % self)

        if self._send_buffer and self._send_buffer[-1][0] == Stream.SEND_STRING:
            data_type, existing_data = self._send_buffer.pop(-1)
            data = existing_data + data

        self._send_buffer.append((Stream.SEND_STRING, data))

        if flush:
            self._process_send_buffer()
        else:
            self._start_waiting_for_write_event()

    def write_file(self, sfile, nbytes=0, offset=0, flush=False):
        """
        Write a file to the channel.

        The file will not be written immediately, but will be buffered
        internally until it can be sent without blocking the process.

        Calling :meth:`write_file()` on a closed or disconnected channel
        will raise a :exc:`RuntimeError`.

        ==========  ====================================================
        Arguments   Description
        ==========  ====================================================
        sfile       A file object to write to the channel.
        nbytes      *Optional.* The number of bytes of the file to
                    write. If 0, all bytes will be written.
        offset      *Optional.* The number of bytes to offset writing
                    by.
        flush       *Optional.* If True, flush the internal write
                    buffer. See :meth:`~pants.stream.Stream.flush` for
                    details.
        ==========  ====================================================
        """
        if self._closed or self._closing:
            raise RuntimeError("write_file() called on closed %r." % self)

        if not self.connected:
            raise RuntimeError("write_file() called on disconnected %r." % self)

        self._send_buffer.append((Stream.SEND_FILE, (sfile, offset, nbytes)))

        if flush:
            self._process_send_buffer()
        else:
            self._start_waiting_for_write_event()

    def flush(self):
        """
        Attempt to immediately write any internally buffered data to the
        channel without waiting for a write event.

        This method can be fairly expensive to call and should be used
        sparingly.

        Calling :meth:`flush()` on a closed or disconnected channel will
        raise a :exc:`RuntimeError`.
        """
        if self._closed or self._closing:
            raise RuntimeError("flush() called on closed %r." % self)

        if not self.connected:
            raise RuntimeError("flush() called on disconnected %r." % self)

        if not self._send_buffer:
            return

        self._stop_waiting_for_write_event()
        self._process_send_buffer()

    ##### Public Event Handlers ###############################################

    def on_ssl_handshake(self):
        """
        Placeholder. Called after the channel has finished its SSL
        handshake.
        """
        pass

    ##### Public Error Handlers ###############################################

    def on_ssl_handshake_error(self, exception):
        """
        Placeholder. Called when an error occurs during the SSL
        handshake.

        By default, logs the exception and closes the channel.

        ==========  ============
        Argument    Description
        ==========  ============
        exception   The exception that was raised.
        ==========  ============
        """
        log.exception(exception)
        self.close()

    def on_ssl_error(self, exception):
        """
        Placeholder. Called when an error occurs in the underlying SSL
        implementation.

        By default, logs the exception and closes the channel.

        ==========  ============
        Argument    Description
        ==========  ============
        exception   The exception that was raised.
        ==========  ============
        """
        log.exception(exception)
        self.close()

    ##### Internal Methods ####################################################

    def _do_connect(self, address, family, error=None):
        """
        A callback method to be used with
        :meth:`~pants._channel._Channel._resolve_addr` - either connects
        immediately or notifies the user of an error.

        =========  =====================================================
        Argument   Description
        =========  =====================================================
        address    The address to connect to or None if address
                   resolution failed.
        family     The detected socket family or None if address
                   resolution failed.
        error      *Optional.* Error information or None if no error
                   occured.
        =========  =====================================================
        """
        if not address:
            self.connecting = False
            e = StreamConnectError(*error)
            self._safely_call(self.on_connect_error, e)
            return

        if self._socket:
            if self._socket.family != family:
                self.engine.remove_channel(self)
                self._socket_close()
                self._closed = False

        sock = socket.socket(family, socket.SOCK_STREAM)
        self._socket_set(sock)
        self.engine.add_channel(self)

        try:
            connected = self._socket_connect(address)
        except socket.error, err:
            self.close()
            e = StreamConnectError(err.errno, err.strerror)
            self._safely_call(self.on_connect_error, e)
            return

        if connected:
            self._handle_connect_event()

    ##### Internal Event Handler Methods ######################################

    def _handle_read_event(self):
        """
        Handle a read event raised on the channel.
        """
        if self.ssl_enabled and not self._ssl_handshake_done:
            self._ssl_do_handshake()
            return

        while True:
            try:
                data = self._socket_recv()
            except socket.error, err:
                self._safely_call(self.on_read_error, err)
                return

            if data is None:
                self.close()
                return
            elif len(data) == 0:
                break
            else:
                self._recv_buffer += data

                if len(self._recv_buffer) > self._recv_buffer_size_limit:
                    # Try processing the buffer to reduce its length.
                    self._process_recv_buffer()

                    # If the buffer's still too long, overflow error.
                    if len(self._recv_buffer) > self._recv_buffer_size_limit:
                        e = StreamBufferOverflow("Buffer length exceeded upper limit on %r." % self)
                        self._safely_call(self.on_overflow_error, e)
                        return

        self._process_recv_buffer()

    def _handle_write_event(self):
        """
        Handle a write event raised on the channel.
        """
        if self.ssl_enabled and not self._ssl_handshake_done:
            self._ssl_do_handshake()
            return

        if not self.connected:
            self._handle_connect_event()

        if not self._send_buffer:
            return

        self._process_send_buffer()
    
    def _handle_error_event(self):
        """
        Handle an error event raised on the channel.
        """
        if self.connecting:
            # That's no moon...
            self._handle_connect_event()
        else:
            _Channel._handle_error_event(self)

    def _handle_connect_event(self):
        """
        Handle a connect event raised on the channel.
        """
        self.connecting = False
        err, errstr = self._get_socket_error()
        if err == 0:
            self.connected = True
            if self._ssl_enabling:
                self._ssl_call_on_connect = True
                self._process_send_buffer()
            else:
                self._safely_call(self.on_connect)
        else:
            # ... it's a space station!
            e = StreamConnectError(err, errstr)
            self._safely_call(self.on_connect_error, e)

    ##### Internal Processing Methods #########################################

    def _process_recv_buffer(self):
        """
        Process the :attr:`~pants.stream.Stream._recv_buffer`, passing
        chunks of data to :meth:`~pants.stream.Stream.on_read`.
        """
        while self._recv_buffer:
            delimiter = self.read_delimiter

            if delimiter is None:
                data = self._recv_buffer
                self._recv_buffer = ""
                self._safely_call(self.on_read, data)

            elif isinstance(delimiter, (int, long)):
                if len(self._recv_buffer) < delimiter:
                    break
                data = self._recv_buffer[:delimiter]
                self._recv_buffer = self._recv_buffer[delimiter:]
                self._safely_call(self.on_read, data)

            elif isinstance(delimiter, basestring):
                mark = self._recv_buffer.find(delimiter)
                if mark == -1:
                    break
                data = self._recv_buffer[:mark]
                self._recv_buffer = self._recv_buffer[mark + len(delimiter):]
                self._safely_call(self.on_read, data)

            else:
                # The safeguards in the read delimiter property should
                # prevent this from happening unless people start
                # getting too crafty for their own good.
                err = InvalidReadDelimiterError("Invalid read delimiter on %r." % self)
                self._safely_call(self.on_error, err)
                break

            if self._closed or not self.connected:
                break

    def _process_send_buffer(self):
        """
        Process the :attr:`~pants.stream.Stream._send_buffer`, passing
        outgoing data to :meth:`~pants._channel._Channel._socket_send`
        or :meth:`~pants._channel._Channel._socket_sendfile` and calling
        :meth:`~pants.stream.Stream.on_write` when sending has finished.
        """
        while self._send_buffer:
            data_type, data = self._send_buffer.pop(0)

            if data_type == Stream.SEND_STRING:
                bytes_sent = self._process_send_string(data)
            elif data_type == Stream.SEND_FILE:
                bytes_sent = self._process_send_file(*data)
            elif data_type == Stream.SEND_SSL_HANDSHAKE:
                bytes_sent = self._process_send_ssl_handshake(data)

            if bytes_sent == 0:
                break

        if not self._closed and not self._send_buffer:
            self._safely_call(self.on_write)

            if self._closing:
                self.close()

    def _process_send_string(self, data):
        """
        Send data from a string to the remote socket.
        """
        try:
            bytes_sent = self._socket_send(data)
        except socket.error, err:
            self._safely_call(self.on_write_error, err)
            return 0

        if len(data) > bytes_sent:
            self._send_buffer.insert(0, (Stream.SEND_STRING, data[bytes_sent:]))

        return bytes_sent

    def _process_send_file(self, sfile, offset, nbytes):
        """
        Send data from a file to the remote socket.
        """
        try:
            bytes_sent = self._socket_sendfile(sfile, offset, nbytes)
        except socket.error, err:
            self._safely_call(self.on_write_error, err)
            return 0

        offset += bytes_sent

        if nbytes > 0:
            if nbytes - bytes_sent > 0:
                nbytes -= bytes_sent
            else:
                # Reached the end of the segment.
                return bytes_sent

        # TODO This is awful. Find a better way.
        if os.fstat(sfile.fileno()).st_size - offset <= 0:
            # Reached the end of the file.
            return bytes_sent

        self._send_buffer.insert(0, (Stream.SEND_FILE, (sfile, offset, nbytes)))

        return bytes_sent

    def _process_send_ssl_handshake(self, ssl_options):
        """
        Enable SSL and begin the handshake.
        """
        self._ssl_enabling = False

        if not self._ssl_socket_wrapped:
            try:
                self._socket = ssl.wrap_socket(self._socket, **ssl_options)
            except ssl.SSLError, e:
                self._ssl_enabling = True
                self._safely_call(self.on_ssl_error, e)
                return 0
            else:
                self._ssl_socket_wrapped = True

        self.ssl_enabled = True

        try:
            bytes_sent = self._ssl_do_handshake()
        except Exception, err:
            self._safely_call(self.on_ssl_handshake_error, err)
        
        # Unlike strings and files, the SSL handshake is not re-added to
        # the queue. This is because the stream's state has been
        # modified and the handshake will continue until it's complete.
        return bytes_sent

    ##### SSL Implementation ##################################################

    def _socket_recv(self):
        """
        Receive data from the socket.

        Returns a string of data read from the socket. The data is None if
        the socket has been closed.

        Overrides :meth:`pants._channel._Channel._socket_recv` to handle
        SSL-specific behaviour.
        """
        try:
            return _Channel._socket_recv(self)
        except ssl.SSLError, err:
            if err[0] == ssl.SSL_ERROR_WANT_READ:
                return ''
            else:
                raise

    def _socket_send(self, data):
        """
        Send data to the socket.

        Returns the number of bytes that were sent to the socket.

        Overrides :meth:`pants._channel._Channel._socket_send` to handle
        SSL-specific behaviour.

        =========  ============
        Argument   Description
        =========  ============
        data       The string of data to send.
        =========  ============
        """
        try:
            bytes_sent = _Channel._socket_send(self, data)
        except ssl.SSLError, err:
            if err[0] == ssl.SSL_ERROR_WANT_WRITE:
                self._start_waiting_for_write_event()
                return 0
            else:
                raise
        
        # SSLSocket.send() can return 0 rather than raise an exception
        # if it needs a write event.
        if self.ssl_enabled and bytes_sent == 0:
            self._start_waiting_for_write_event()
        return bytes_sent

    def _socket_sendfile(self, sfile, offset, nbytes):
        """
        Send data from a file to a remote socket.

        Returns the number of bytes that were sent to the socket.

        Overrides :meth:`pants._channel._Channel._socket_sendfile` to
        handle SSL-specific behaviour.

        =========  ============
        Argument   Description
        =========  ============
        sfile      The file to send.
        offset     The number of bytes to offset writing by.
        nbytes     The number of bytes of the file to write. If 0, all bytes will be written.
        =========  ============
        """
        return _Channel._socket_sendfile(self, sfile, offset, nbytes, self.ssl_enabled)

    def _ssl_do_handshake(self):
        """
        Perform an asynchronous SSL handshake.
        """
        try:
            self._socket.do_handshake()
        except ssl.SSLError, err:
            if err[0] == ssl.SSL_ERROR_WANT_READ:
                return 0
            elif err[0] == ssl.SSL_ERROR_WANT_WRITE:
                self._start_waiting_for_write_event()
                return 0
            elif err[0] in (ssl.SSL_ERROR_EOF, ssl.SSL_ERROR_ZERO_RETURN):
                self.close()
                return 0
            elif err[0] == ssl.SSL_ERROR_SSL:
                self._safely_call(self.on_ssl_handshake_error, err)
                return 0
            else:
                raise
        except socket.error, err:
            if err[0] in (errno.ECONNRESET, errno.EPIPE):
                self.close()
                return 0
            else:
                raise
        else:
            self._ssl_handshake_done = True
            self._safely_call(self.on_ssl_handshake)
            if self._ssl_call_on_connect:
                self._safely_call(self.on_connect)
            return None


###############################################################################
# Exceptions
###############################################################################

class StreamBufferOverflow(Exception):
    """
    Raised when a stream's internal buffer has exceeded its maximum
    allowed size.
    """
    pass

class StreamConnectError(Exception):
    """
    Raised when an error has occured during an attempt to connect a
    stream to a remote host.
    """
    pass

class InvalidReadDelimiterError(Exception):
    """
    Raised when a channel tries to process incoming data with an
    invalid read delimiter.
    """
    pass
