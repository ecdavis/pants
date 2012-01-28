###############################################################################
#
# Copyright 2011 Pants Developers (see AUTHORS.txt)
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
    DATA_SSL_ENABLE = 2

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
        if isinstance(kwargs.get("socket", None), ssl.SSLSocket):
            self._ssl_socket_wrapped = True
            self.startTLS()

    ##### Control Methods #####################################################

    def startTLS(self, flush=True, **ssl_options):
        """
        Enable TLS/SSL on the channel and perform a handshake.

        See :func:`ssl.wrap_socket` for a description of the keyword
        arguments accepted by this method.

        ============ ============
        Arguments    Description
        ============ ============
        flush        If True, flush the internal write buffer.
        ssl_options  SSL keyword arguments.
        ============ ============
        """
        if self.ssl_enabled or self._ssl_enabling:
            raise RuntimeError("startTLS() called on SSL-enabled %r" % self)

        if self._socket is None or self._closing:
            raise RuntimeError("startTLS() called on closed %r" % self)

        self._ssl_enabling = True
        self._send_buffer.append((Stream.DATA_SSL_ENABLE, ssl_options))

        if flush:
            self._process_send_buffer()
        else:
            self._start_waiting_for_write_event()

    def connect(self, addr, native_resolve=True):
        """
        Connect the channel to a remote socket.

        Returns the channel.

        ===============  ============
        Arguments        Description
        ===============  ============
        addr             The remote address to connect to.
        native_resolve   *Optional.* If this is set to True, Pants will not attempt to resolve the given address name itself.
        ===============  ============
        """
        if self.connected or self.connecting:
            raise RuntimeError("connect() called on active %s #%d."
                    % (self.__class__.__name__, self.fileno))

        if self._closed or self._closing:
            raise RuntimeError("connect() called on closed %s."
                    % self.__class__.__name__)

        self.connecting = True

        # Identify the type of address.
        self._resolve_addr(addr, native_resolve, self._do_connect)

        return self

    def _do_connect(self, addr, family, error=None):
        """
        Actually connect, now that we know what sort of address we've got. Or,
        if addr is None, connection failed and error information is available.
        """
        if not addr:
            self.connecting = False
            e = StreamConnectError(*error)
            self._safely_call(self.on_connect_error, e)
            return

        # If we already have a socket, we shouldn't. Toss it!
        if self._socket:
            if self._socket.family != family:
                Engine.instance().remove_channel(self)
                self._socket_close()
                self._closed = False

        # Create our socket.
        if self._socket is None:
            sock = socket.socket(family, socket.SOCK_STREAM)
            self._socket_set(sock)
            Engine.instance().add_channel(self)

        # Now, connect!
        try:
            connected = self._socket_connect(addr)
        except socket.error, err:
            self.close()
            e = StreamConnectError(err.strerror, err.errno)
            self._safely_call(self.on_connect_error, e)
            return

        if connected:
            self._handle_connect_event()

    def close(self):
        """
        Close the channel.
        """
        if self._socket is None:
            return

        self.read_delimiter = None
        self._recv_buffer = ""
        self._send_buffer = []

        self.connected = False
        self.connecting = False
        self._closing = False

        self.ssl_enabled = False
        self._ssl_enabling = False
        self._ssl_handshake_done = False

        self._update_addr()

        _Channel.close(self)

    def end(self):
        """
        Close the channel after writing is finished.
        """
        if self._socket is None or self._closing:
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
        flush       If True, flush the internal write buffer.
        ==========  ============
        """
        if self._socket is None or self._closing:
            log.warning("Attempted to write to closed %s #%d." %
                    (self.__class__.__name__, self.fileno))
            return

        if not self.connected:
            log.warning("Attempted to write to disconnected %s #%d." %
                    (self.__class__.__name__, self.fileno))
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
        nbytes      The number of bytes of the file to write. If 0, all bytes will be written.
        offset      The number of bytes to offset writing by.
        flush       If True, flush the internal write buffer.
        ==========  ============
        """
        if self._socket is None or self._closing:
            log.warning("Attempted to write file to closed %s #%d." %
                    (self.__class__.__name__, self.fileno))
            return

        if not self.connected:
            log.warning("Attempted to write file to disconnected %s #%d." %
                    (self.__class__.__name__, self.fileno))
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

    def on_ssl_handshake_complete(self):
        """
        Placeholder. Called after the channel has finished its SSL
        handshake.
        """
        pass

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
                log.exception("Exception raised by recv() on %s #%d." %
                        (self.__class__.__name__, self.fileno))
                # TODO Close this Stream here?
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
                    e = StreamBufferOverflow(
                            "Buffer length exceeded upper limit on %s #%d." %
                            (self.__class__.__name___, self.fileno)
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
            self._safely_call(self.on_connect)
        else:
            e = StreamConnectError(errstr, err)
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
                log.warning("Invalid read_delimiter on %s #%d." %
                        (self.__class__.__name__, self.fileno))
                break

            if self._socket is None or not self.connected:
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
            elif data_type == Stream.DATA_SSL_ENABLE:
                bytes_sent = self._process_send_data_ssl_enable(data)

            if bytes_sent == 0:
                break

        if not self._send_buffer:
            self._safely_call(self.on_write)

            if self._closing:
                self.close()

    def _process_send_data_string(self, data):
        try:
            bytes_sent = self._socket_send(data)
        except socket.error:
            log.exception("Exception raised in send() on %s #%d." %
                    (self.__class__.__name__, self.fileno))
            self.close()
            return 0

        if len(data) > bytes_sent:
            self._send_buffer.insert(0, (Stream.DATA_STRING, data[bytes_sent:]))

        return bytes_sent

    def _process_send_data_file(self, sfile, offset, nbytes):
        try:
            bytes_sent = self._socket_sendfile(sfile, offset, nbytes)
        except socket.error:
            log.exception("Exception raised in sendfile() on %s #%d." %
                    (self.__class__.__name__, self.fileno))
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

    def _process_send_data_ssl_enable(self, ssl_options):
        self._ssl_enabling = False

        if not self._ssl_socket_wrapped:
            self._socket = ssl.wrap_socket(self._socket, do_handshake_on_connect=False, **ssl_options)
            self._ssl_socket_wrapped = True

        self.ssl_enabled = True

        bytes_sent = self._ssl_do_handshake()

        if self._ssl_handshake_done:
            self._safely_call(self.on_ssl_handshake_complete)
        else:
            self._send_buffer.insert(0, (Stream.DATA_SSL_ENABLE, ssl_options))

        return bytes_sent

    ##### SSL Implementation ##################################################

    def _socket_recv(self):
        """
        Receive data from the socket.

        Returns a string of data read from the socket. The data is None if
        the socket has been closed.
        """
        if not self.ssl_enabled:
            return _Channel._socket_recv(self)

        try:
            data = self._socket.recv(self._recv_amount)
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

        =========  ============
        Argument   Description
        =========  ============
        data       The string of data to send.
        =========  ============
        """
        if not self.ssl_enabled:
            return _Channel._socket_send(self, data)

        try:
            return self._socket.send(data)
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
                log.warning("SSL error on %s #%d" % (self.__class__.__name__, self.fileno))
                self.close()
                return 0
            else:
                raise
        else:
            self._ssl_handshake_done = True
            # TODO notify user code here
            return None


###############################################################################
# StreamServer Class
###############################################################################

class StreamServer(_Channel):
    """
    A stream-oriented, listening channel.

    ==================  ============
    Keyword Arguments   Description
    ==================  ============
    family              *Optional.* A supported socket family. By default, is :const:`socket.AF_INET`.
    socket              *Optional.* A pre-existing socket to wrap.
    ==================  ============
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

    ##### Control Methods #####################################################

    def startTLS(self, **ssl_options):
        if self.ssl_enabled:
            raise RuntimeError("startTLS() called on TLS-enabled %r" % self)

        if self._socket is None:
            raise RuntimeError("startTLS() called on closed %r" % self)

        self._socket = ssl.wrap_socket(self._socket, **ssl_options)
        self.ssl_enabled = True

    def listen(self, addr, backlog=1024, native_resolve=True, slave=True):
        """
        Begin listening for connections made to the channel.

        Returns the channel.

        ===============  ============
        Arguments        Description
        ===============  ============
        addr             The local address to listen for connections on.
        backlog          *Optional.* The size of the connection queue. By default, is 1024.
        native_resolve   *Optional.* If this is set to True, Pants will not attempt to resolve the given address name itself.
        slave            *Optional.* When True, this will cause a StreamServer listening on IPv6 INADDR_ANY to create a slave StreamServer that listens on the IPv4 INADDR_ANY.
        ===============  ============
        """
        if self.listening:
            raise RuntimeError("listen() called on active %s #%d."
                    % (self.__class__.__name__, self.fileno))

        if self._closed:
            raise RuntimeError("listen() called on closed %s."
                    % self.__class__.__name__)

        # Resolve our address.
        self._resolve_addr(addr, native_resolve, functools.partial(self._do_listen, backlog, slave))

        return self

    def _do_listen(self, backlog, slave, addr, family, error=None):
        """
        Actually start to listen, now that we know what sort of address we've
        got. Or, if addr is None, it's a bad address, so do an error thing.
        """
        if not addr:
            log.error("Error listening on %s #%d" %
                        (self.__class__.__name__, self.fileno))
            return

        # If we already have a socket, we shouldn't. Toss it!
        if self._socket:
            if self._socket.family != family:
                Engine.instance().remove_channel(self)
                self._socket_close()
                self._closed = False

        # Create our socket.
        if self._socket is None:
            sock = socket.socket(family, socket.SOCK_STREAM)
            self._socket_set(sock)
            Engine.instance().add_channel(self)

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
            self._slave = StreamServerSlave(self, addr, backlog)

    def close(self):
        """
        Close the channel.
        """
        if self._socket is None:
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
                log.exception("Exception raised by accept() on %s #%d." %
                        (self.__class__.__name__, self.fileno))
                try:
                    sock.close()
                except socket.error:
                    # TODO What do we do here?
                    pass
                # TODO Close this Stream here?
                return

            if sock is None:
                return

            self._safely_call(self.on_accept, sock, addr)

    def _handle_write_event(self):
        """
        Handle a write event raised on the channel.
        """
        log.warning("Received write event for %s #%d." %
                    (self.__class__.__name__, self.fileno))


###############################################################################
# StreamServerSlave Class
###############################################################################

class StreamServerSlave(StreamServer):
    """
    A slave for a StreamServer to allow listening on multiple address familes.
    """
    def __init__(self, server, addr, backlog):
        StreamServer.__init__(self)
        self.server = server

        # Now, listen our way.
        if server._socket.family == socket.AF_INET6:
            family = socket.AF_INET
        else:
            family = socket.AF_INET6

        sock = socket.socket(family, socket.SOCK_STREAM)
        self._socket_set(sock)
        Engine.instance().add_channel(self)

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
    def __init__(self, errstr):
        self.errstr = errstr

    def __repr__(self):
        return self.errstr


###############################################################################
# StreamConnectError Exception
###############################################################################

class StreamConnectError(Exception):
    def __init__(self, errstr, err):
        self.errstr = errstr
        self.err = err

    def __repr__(self):
        return self.errstr
