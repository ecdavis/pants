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
Low-level implementations of stream-oriented channels.
"""

###############################################################################
# Imports
###############################################################################

import errno
import functools
import os
import socket
import ssl

from pants._channel import _Channel
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
    A stream-oriented, connecting channel.

    ==================  ============
    Keyword Arguments   Description
    ==================  ============
    socket              *Optional.* A pre-existing socket to wrap.
    ==================  ============
    """
    DATA_STRING = 0
    DATA_FILE = 1
    WORK_SSL_ENABLE = 2

    def __init__(self, **kwargs):
        sock = kwargs.get("socket", None)
        if sock and sock.type != socket.SOCK_STREAM:
            raise TypeError("Cannot create a %s with a type other than SOCK_STREAM."
                    % self.__class__.__name__)

        _Channel.__init__(self, **kwargs)

        # Socket
        self.remote_addr = None
        self.local_addr = None

        # I/O attributes
        self.read_delimiter = None
        self._recv_buffer = ""
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
    def read_delimiter(self):
        """ TODO: Document this! """
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
            raise TypeError(
                    "read_delimiter must be None, a string, an int, or a long"
                    )

    _buffer_size = 2 ** 16  # 64kb

    @property
    def buffer_size(self):
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
        Enable SSL on the channel and perform a handshake.

        For best results, this method should be called before
        :meth:`~pants.stream.Stream.connect`.

        This method will raise a :exc:`RuntimeError` if you provide a
        value other than False for the *do_handshake_on_connect* SSL
        option.

        ============ ============
        Arguments    Description
        ============ ============
        ssl_options  *Optional.* SSL keyword arguments. See :func:`ssl.wrap_socket` for a description of the available SSL options.
        ============ ============
        """
        if self.ssl_enabled or self._ssl_enabling:
            raise RuntimeError("startSSL() called on SSL-enabled %r" % self)

        if self._closed or self._closing:
            raise RuntimeError("startSSL() called on closed %r" % self)

        if ssl_options.setdefault("do_handshake_on_connect", False) is not False:
            raise RuntimeError("SSL option 'do_handshake_on_connect' must be False.")

        self._ssl_enabling = True
        self._send_buffer.append((Stream.WORK_SSL_ENABLE, ssl_options))
        if self.connected:
            self._process_send_buffer()

    def connect(self, addr, native_resolve=True):
        """
        Connect the channel to a remote socket.

        Returns the channel.

        ===============  ============
        Arguments        Description
        ===============  ============
        addr             The remote address to connect to.
        native_resolve   *Optional.* If True, use Python's builtin address resolution. Otherwise, Pants' non-blocking address resolution will be used.
        ===============  ============
        """
        if self.connected or self.connecting:
            raise RuntimeError("connect() called on active %r." % self)

        if self._closed or self._closing:
            raise RuntimeError("connect() called on closed %r." % self)

        self.connecting = True

        # Identify the type of address.
        self._resolve_addr(addr, native_resolve, self._do_connect)

        return self

    def _do_connect(self, addr, family, error=None):
        """
        A callback method to be used with
        :meth:`~pants._channel._Channel._resolve_addr` - either connects
        immediately or notifies the user of an error.

        =========  ============
        Argument   Description
        =========  ============
        addr       The address to connect to or None if address resolution failed.
        family     The detected socket family or None if address resolution failed.
        error      *Optional.* Error information or None if no error occured.
        =========  ============
        """
        if not addr:
            self.connecting = False
            e = StreamConnectError(*error)
            self._safely_call(self.on_connect_error, e)
            return

        # If we already have a socket, we shouldn't. Toss it!
        if self._socket:
            if self._socket.family != family:
                self.engine.remove_channel(self)
                self._socket_close()
                self._closed = False

        # Create our socket.
        sock = socket.socket(family, socket.SOCK_STREAM)
        self._socket_set(sock)
        self.engine.add_channel(self)

        # Now, connect!
        try:
            connected = self._socket_connect(addr)
        except socket.error, err:
            self.close()
            e = StreamConnectError(err.errno, err.strerror)
            self._safely_call(self.on_connect_error, e)
            return

        if connected:
            self._handle_connect_event()

    def close(self):
        """
        Close the channel.
        """
        if self._closed:
            return

        self.read_delimiter = None
        self._recv_buffer = ""
        self._send_buffer = []

        self.connected = False
        self.connecting = False
        self._closing = False

        self.ssl_enabled = False
        self._ssl_enabling = False
        self._ssl_socket_wrapped = False
        self._ssl_handshake_done = False
        self._ssl_call_on_connect = False

        self._update_addr()

        _Channel.close(self)

    def end(self):
        """
        Close the channel after writing is finished.
        """
        if self._closed or self._closing:
            return

        if not self._send_buffer:
            self.close()
        else:
            self._closing = True

    ##### I/O Methods #########################################################

    def write(self, data, flush=False):
        """
        Write data to the channel.

        ==========  ============
        Arguments   Description
        ==========  ============
        data        A string of data to write to the channel.
        flush       *Optional.* If True, flush the internal write buffer.
        ==========  ============
        """
        if self._closed or self._closing:
            log.warning("Attempted to write to closed %r." % self)
            return

        if not self.connected:
            log.warning("Attempted to write to disconnected %r." % self)
            return

        if self._send_buffer and self._send_buffer[-1][0] == Stream.DATA_STRING:
            data_type, existing_data = self._send_buffer.pop(-1)
            data = existing_data + data

        self._send_buffer.append((Stream.DATA_STRING, data))

        if flush:
            self._process_send_buffer()
        else:
            self._start_waiting_for_write_event()

    def write_file(self, sfile, nbytes=0, offset=0, flush=False):
        """
        Write a file to the channel.

        ==========  ============
        Arguments   Description
        ==========  ============
        sfile       A file object to write to the channel.
        nbytes      *Optional.* The number of bytes of the file to write. If 0, all bytes will be written.
        offset      *Optional.* The number of bytes to offset writing by.
        flush       *Optional.* If True, flush the internal write buffer.
        ==========  ============
        """
        if self._closed or self._closing:
            log.warning("Attempted to write file to closed %r." % self)
            return

        if not self.connected:
            log.warning("Attempted to write file to disconnected %r." % self)
            return

        self._send_buffer.append((Stream.DATA_FILE, (sfile, offset, nbytes)))

        if flush:
            self._process_send_buffer()
        else:
            self._start_waiting_for_write_event()

    def flush(self):
        """
        Attempt to immediately write any internally buffered data to the
        channel.
        """
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

    def _update_addr(self):
        """
        Update the channel's :attr:`~pants.stream.Stream.remote_addr`
        and :attr:`~pants.stream.Stream.local_addr` attributes.
        """
        if self.connected:
            self.remote_addr = self._socket.getpeername()
            self.local_addr = self._socket.getsockname()
        else:
            self.remote_addr = None
            self.local_addr = None

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
            except socket.error:
                log.exception("Exception raised by recv() on %r." % self)
                self.close()
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
                        e = StreamBufferOverflow(
                                "Buffer length exceeded upper limit on %r." %
                                    self
                            )
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

    def _handle_connect_event(self):
        """
        Handle a connect event raised on the channel.
        """
        self.connecting = False
        err, errstr = self._get_socket_error()
        if err == 0:
            self.connected = True
            self._update_addr()
            if self._ssl_enabling:
                self._ssl_call_on_connect = True
                self._process_send_buffer()
            else:
                self._safely_call(self.on_connect)
        else:
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
                log.warning("Invalid read_delimiter on %r." % self)
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

            if data_type == Stream.DATA_STRING:
                bytes_sent = self._process_send_data_string(data)
            elif data_type == Stream.DATA_FILE:
                bytes_sent = self._process_send_data_file(*data)
            elif data_type == Stream.WORK_SSL_ENABLE:
                bytes_sent = self._process_do_work_ssl_enable(data)

            if bytes_sent == 0:
                break

        if not self._send_buffer:
            self._safely_call(self.on_write)

            if self._closing:
                self.close()

    def _process_send_data_string(self, data):
        """
        Send data from a string to the remote socket.
        """
        try:
            bytes_sent = self._socket_send(data)
        except socket.error:
            log.exception("Exception raised in send() on %r." % self)
            self.close()
            return 0

        if len(data) > bytes_sent:
            self._send_buffer.insert(0, (Stream.DATA_STRING, data[bytes_sent:]))

        return bytes_sent

    def _process_send_data_file(self, sfile, offset, nbytes):
        """
        Send data from a file to the remote socket.
        """
        try:
            bytes_sent = self._socket_sendfile(sfile, offset, nbytes)
        except socket.error:
            log.exception("Exception raised in sendfile() on %r." % self)
            self.close()
            return 0

        offset += bytes_sent

        if nbytes > 0:
            if nbytes - bytes_sent > 0:
                nbytes -= bytes_sent
            else:
                # Reached the end of the segment.
                return bytes_sent

        if os.fstat(sfile.fileno()).st_size - offset <= 0:
            # Reached the end of the file.
            return bytes_sent

        self._send_buffer.insert(0, (Stream.DATA_FILE, (sfile, offset, nbytes)))

        return bytes_sent

    def _process_do_work_ssl_enable(self, ssl_options):
        """
        Enable SSL and begin the handshake.
        """
        self._ssl_enabling = False

        if not self._ssl_socket_wrapped:
            try:
                self._socket = ssl.wrap_socket(self._socket,
                        do_handshake_on_connect=False, **ssl_options)
            except ssl.SSLError, e:
                self._ssl_enabling = True
                self._safely_call(self.on_ssl_error)
                return 0
            else:
                self._ssl_socket_wrapped = True

        self.ssl_enabled = True

        try:
            bytes_sent = self._ssl_do_handshake()
        except Exception, err:
            self._safely_call(self.on_ssl_handshake_error, err)

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
        if not self.ssl_enabled:
            return _Channel._socket_recv(self)

        try:
            data = self._socket.read(self._recv_amount)
        except ssl.SSLError, err:
            if err[0] == ssl.SSL_ERROR_WANT_READ:
                return ''
            else:
                raise
        except socket.error, err:
            if err[0] in (errno.EAGAIN, errno.EWOULDBLOCK):
                return ''
            elif err[0] == errno.ECONNRESET:
                return None
            else:
                raise

        if not data:
            return None
        else:
            return data

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
        if not self.ssl_enabled:
            return _Channel._socket_send(self, data)

        try:
            bytes_sent = self._socket.send(data)
        except ssl.SSLError, err:
            if err[0] == ssl.SSL_ERROR_WANT_WRITE:
                self._start_waiting_for_write_event()
                return 0
            else:
                raise
        except Exception, err:
            if err[0] in (errno.EAGAIN, errno.EWOULDBLOCK):
                self._start_waiting_for_write_event()
                return 0
            elif err[0] == errno.EPIPE:
                self.close()
                return 0
            else:
                raise

        # SSLSocket.send() can return 0 rather than raise an exception
        # if it needs a write event.
        if bytes_sent == 0:
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
                log.debug("SSL error during handshake on %r" % self,
                    exc_info=err)
                self.close()
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
# StreamServer Class
###############################################################################

class StreamServer(_Channel):
    """
    A stream-oriented, listening channel.
    """
    def __init__(self, **kwargs):
        sock = kwargs.get("socket", None)
        if sock and sock.type != socket.SOCK_STREAM:
            raise TypeError("Cannot create a %s with a type other than SOCK_STREAM."
                    % self.__class__.__name__)

        _Channel.__init__(self, **kwargs)

        # Socket
        self.remote_addr = None
        self.local_addr = None

        self._slave = None

        # Channel state
        self.listening = False

        # SSL state
        self.ssl_enabled = False
        self._ssl_options = None
        if kwargs.get("ssl_options", None) is not None:
            self.startSSL(kwargs["ssl_options"])

    ##### Control Methods #####################################################

    def startSSL(self, ssl_options={}):
        """
        Enable SSL on the channel.

        For best results, this method should be called before
        :meth:`~pants.stream.StreamServer.listen`.

        This method will raise a :exc:`RuntimeError` if you provide a
        value other than True for the *server_side* SSL option or a
        value other than False for the *do_handshake_on_connect* SSL
        option.

        ============ ============
        Arguments    Description
        ============ ============
        ssl_options  *Optional.* SSL keyword arguments. See :func:`ssl.wrap_socket` for a description of the available SSL options.
        ============ ============
        """
        if self.ssl_enabled:
            raise RuntimeError("startSSL() called on SSL-enabled %r." % self)

        if self._closed:
            raise RuntimeError("startSSL() called on closed %r." % self)

        if ssl_options.setdefault("server_side", True) is not True:
            raise RuntimeError("SSL option 'server_side' must be True.")

        if ssl_options.setdefault("do_handshake_on_connect", False) is not False:
            raise RuntimeError("SSL option 'do_handshake_on_connect' must be False.")

        self.ssl_enabled = True
        self._ssl_options = ssl_options

    def listen(self, addr, backlog=1024, native_resolve=True, slave=True):
        """
        Begin listening for connections made to the channel.

        Returns the channel.

        ===============  ============
        Arguments        Description
        ===============  ============
        addr             The local address to listen for connections on.
        backlog          *Optional.* The maximum size of the connection queue.
        native_resolve   *Optional.* If True, use Python's builtin address resolution. Otherwise, Pants' non-blocking address resolution will be used.
        slave            *Optional.* If True, this will cause a StreamServer listening on IPv6 INADDR_ANY to create a slave StreamServer that listens on the IPv4 INADDR_ANY.
        ===============  ============
        """
        if self.listening:
            raise RuntimeError("listen() called on active %r." % self)

        if self._closed:
            raise RuntimeError("listen() called on closed %r." % self)

        # Resolve our address.
        self._resolve_addr(addr, native_resolve, functools.partial(self._do_listen, backlog, slave))

        return self

    def _do_listen(self, backlog, slave, addr, family, error=None):
        """
        A callback method to be used with
        :meth:`~pants._channel._Channel._resolve_addr` - either listens
        immediately or notifies the user of an error.

        =========  ============
        Argument   Description
        =========  ============
        backlog    The maximum size of the connection queue.
        slave      If True, this will cause a StreamServer listening on IPv6 INADDR_ANY to create a slave StreamServer that listens on the IPv4 INADDR_ANY.
        addr       The address to listen on or None if address resolution failed.
        family     The detected socket family or None if address resolution failed.
        error      *Optional.* Error information or None if no error occured.
        =========  ============
        """
        if not addr:
            err, errstr = error
            log.error("Error listening on %r: %s (%d)" % (self, errstr, err))
            return

        # If we already have a socket, we shouldn't. Toss it!
        if self._socket:
            if self._socket.family != family:
                self.engine.remove_channel(self)
                self._socket_close()
                self._closed = False

        # Create our socket.
        sock = socket.socket(family, socket.SOCK_STREAM)
        self._socket_set(sock)
        self.engine.add_channel(self)

        try:
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass

        if hasattr(socket, "IPPROTO_IPV6") and hasattr(socket, "IPV6_V6ONLY")\
                and family == socket.AF_INET6:
            self._socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            slave = False

        try:
            self._socket_bind(addr)
            self._socket_listen(backlog)
        except socket.error, err:
            self.close()
            raise

        self.listening = True
        self._update_addr()
        self._safely_call(self.on_listen)

        # Should we make a slave?
        if slave and not isinstance(addr, str) and addr[0] == '' and socket.has_ipv6:
            self._slave = StreamServerSlave(self.engine, self, addr, backlog)

    def close(self):
        """
        Close the channel.
        """
        if self._closed:
            return

        self.listening = False

        self.ssl_enabled = False

        self._update_addr()

        if self._slave:
            self._slave.close()

        _Channel.close(self)

    ##### Internal Methods ####################################################

    def _update_addr(self):
        """
        Update the channel's
        :attr:`~pants.stream.StreamServer.remote_addr` and
        :attr:`~pants.stream.StreamServer.local_addr` attributes.
        """
        if self.listening:
            self.remote_addr = None
            self.local_addr = self._socket.getsockname()
        else:
            self.remote_addr = None
            self.local_addr = None

    ##### Internal Event Handler Methods ######################################

    def _handle_read_event(self):
        """
        Handle a read event raised on the channel.
        """
        while True:
            try:
                sock, addr = self._socket_accept()
            except socket.error:
                log.exception("Exception raised by accept() on %r." % self)
                try:
                    sock.close()
                except socket.error:
                    pass
                return

            if sock is None:
                return

            if self.ssl_enabled:
                try:
                    sock.setblocking(False)
                    sock = ssl.wrap_socket(sock, **self._ssl_options)
                except ssl.SSLError:
                    log.exception("Exception raised while SSL-wrapping socket on %r." % self)
                    try:
                        sock.close()
                    except socket.error:
                        pass
                    continue

            self._safely_call(self.on_accept, sock, addr)

    def _handle_write_event(self):
        """
        Handle a write event raised on the channel.
        """
        log.warning("Received write event for %r." % self)


###############################################################################
# StreamServerSlave Class
###############################################################################

class StreamServerSlave(StreamServer):
    """
    A slave for a StreamServer to allow listening on multiple address
    familes.
    """
    def __init__(self, engine, server, addr, backlog):
        StreamServer.__init__(self, engine=engine)
        self.server = server

        # Now, listen our way.
        if server._socket.family == socket.AF_INET6:
            family = socket.AF_INET
        else:
            family = socket.AF_INET6

        sock = socket.socket(family, socket.SOCK_STREAM)
        self._socket_set(sock)
        self.engine.add_channel(self)

        try:
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass

        try:
            self._socket_bind(addr)
            self._socket_listen(backlog)
        except socket.error, err:
            self.close()
            raise

        self.listening = True
        self._update_addr()

        self.on_accept = self.server.on_accept

    def on_close(self):
        if self.server._slave == self:
            self.server._slave = None


###############################################################################
# StreamBufferOverflow Exception
###############################################################################

class StreamBufferOverflow(Exception):
    """
    Raised when a Stream's internal buffer has exceeded its maximum
    allowed size.
    """
    def __init__(self, errstr):
        self.errstr = errstr

    def __repr__(self):
        return self.errstr


###############################################################################
# StreamConnectError Exception
###############################################################################

class StreamConnectError(Exception):
    """
    Raised when an error has occured during an attempt to connect a
    Stream to a remote host.
    """
    def __init__(self, err, errstr):
        self.err = err
        self.errstr = errstr

    def __repr__(self):
        return self.errstr
