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
Streaming server channel.
"""

###############################################################################
# Imports
###############################################################################

import socket
import ssl
import weakref

from pants._channel import _Channel, HAS_IPV6
from pants.stream import Stream


###############################################################################
# Logging
###############################################################################

import logging
log = logging.getLogger("pants")


###############################################################################
# Server Class
###############################################################################

class Server(_Channel):
    """
    A stream-oriented server channel.

    A :class:`~pants.stream.Server` instance represents a local server
    capable of listening for connections from remote hosts over a
    connection-oriented protocol such as TCP/IP.

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
                       :meth:`~pants.stream.Server.startSSL` will be
                       called with these options once the server is
                       ready. By default, SSL will not be enabled.
    =================  ================================================
    """
    ConnectionClass = Stream

    def __init__(self, ConnectionClass=None, **kwargs):
        sock = kwargs.get("socket", None)
        if sock and sock.type != socket.SOCK_STREAM:
            raise TypeError("Cannot create a %s with a socket type other than SOCK_STREAM."
                    % self.__class__.__name__)

        _Channel.__init__(self, **kwargs)

        # Socket
        self._remote_address = None
        self._local_address = None

        self._slave = None

        # Channel state
        self.listening = False

        # SSL state
        self.ssl_enabled = False
        self._ssl_options = None
        if kwargs.get("ssl_options", None) is not None:
            self.startSSL(kwargs["ssl_options"])

        # Connection class
        if ConnectionClass is not None:
            self.ConnectionClass = ConnectionClass
        self.channels = weakref.WeakValueDictionary()

    ##### Properties ##########################################################

    @property
    def remote_address(self):
        """
        """
        return self._remote_address or self._socket.getpeername()

    @remote_address.setter
    def remote_address(self, val):
        self._remote_address = val

    @property
    def local_address(self):
        """
        """
        return self._local_address or self._socket.getsockname()

    @local_address.setter
    def local_address(self, val):
        self._local_address = val

    ##### Control Methods #####################################################

    def startSSL(self, ssl_options={}):
        """
        Enable SSL on the channel.

        Enabling SSL on a server channel will cause any new connections
        accepted by the server to be automatically wrapped in an SSL
        context before being passed to
        :meth:`~pants.stream.Server.on_accept`. If an error occurs while
        a new connection is being wrapped,
        :meth:`~pants.stream.Server.on_ssl_wrap_error` is called.

        SSL is enabled immediately. Typically, this method is called
        before :meth:`~pants.stream.Server.listen`. If it is called
        afterwards, any connections made in the meantime will not have
        been wrapped in SSL contexts.

        The SSL options argument will be passed through to each
        invocation of :func:`ssl.wrap_socket` as keyword arguments - see
        the :mod:`ssl` documentation for further information. You will
        typically want to provide the ``keyfile``, ``certfile`` and
        ``ca_certs`` options. The ``do_handshake_on_connect`` option
        **must** be ``False`` and the ``server_side`` option **must** be
        true, or a :exc:`ValueError` will be raised.

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
        if self.ssl_enabled:
            raise RuntimeError("startSSL() called on SSL-enabled %r." % self)

        if self._closed:
            raise RuntimeError("startSSL() called on closed %r." % self)

        if ssl_options.setdefault("server_side", True) is not True:
            raise ValueError("SSL option 'server_side' must be True.")

        if ssl_options.setdefault("do_handshake_on_connect", False) is not False:
            raise ValueError("SSL option 'do_handshake_on_connect' must be False.")

        self.ssl_enabled = True
        self._ssl_options = ssl_options

        return self

    def listen(self, address, backlog=1024, slave=True):
        """
        Begin listening for connections made to the channel.

        The given ``address`` is resolved, the channel is bound to the
        address and then begins listening for connections. Once the
        channel has begun listening,
        :meth:`~pants.stream.Server.on_listen` will be called.

        Addresses can be represented in a number of different ways. A
        single string is treated as a UNIX address. A single integer is
        treated as a port and converted to a 2-tuple of the form
        ``('', port)``. A 2-tuple is treated as an IPv4 address and a
        4-tuple is treated as an IPv6 address. See the :mod:`socket`
        documentation for further information on socket addresses.

        If no socket exists on the channel, one will be created with a
        socket family appropriate for the given address.

        An error will occur if the given address is not of a valid
        format or of an inappropriate format for the socket (e.g. if an
        IP address is given to a UNIX socket).

        Calling :meth:`listen()` on a closed channel or a channel that
        is already listening will raise a :exc:`RuntimeError`.

        Returns the channel.

        ===============  ================================================
        Arguments        Description
        ===============  ================================================
        address          The local address to listen for connections on.
        backlog          *Optional.* The maximum size of the
                         connection queue.
        slave            *Optional.* If True, this will cause a
                         Server listening on IPv6 INADDR_ANY to
                         create a slave Server that listens on the
                         IPv4 INADDR_ANY.
        ===============  ================================================
        """
        if self.listening:
            raise RuntimeError("listen() called on active %r." % self)

        if self._closed:
            raise RuntimeError("listen() called on closed %r." % self)

        address, family = self._format_address(address)
        self._do_listen(address, family, backlog, slave)

        return self

    def close(self):
        """
        Close the channel.

        The channel will be closed immediately and will cease to accept
        new connections. Any connections accepted by this channel will
        remain open and will need to be closed separately. If this
        channel has an IPv4 slave (see
        :meth:`~pants.stream.Server.listen`) it will be closed.

        Once closed, a channel cannot be re-opened.
        """
        if self._closed:
            return

        self.listening = False

        self.ssl_enabled = False

        if self._slave:
            self._slave.close()

        _Channel.close(self)

    ##### Public Event Handlers ###############################################

    def on_accept(self, socket, addr):
        """
        Called after the channel has accepted a new connection.

        Create a new instance of
        :attr:`~pants.basic.Server.ConnectonClass` to wrap the socket
        and add it to the server.

        =========  ============
        Argument   Description
        =========  ============
        sock       The newly connected socket object.
        addr       The new socket's address.
        =========  ============
        """
        connection = self.ConnectionClass(engine=self.engine, socket=socket)
        connection.server = self
        self.channels[connection.fileno] = connection
        connection._handle_connect_event()

    def on_close(self):
        """
        Called after the channel has finished closing.

        Close all active connections to the server.
        """
        for channel in self.channels.values():
            channel.close(flush=False)

    ##### Public Error Handlers ###############################################

    def on_ssl_wrap_error(self, sock, addr, exception):
        """
        Placeholder. Called when an error occurs while wrapping a new
        connection with an SSL context.

        By default, logs the exception and closes the new connection.

        ==========  ============
        Argument    Description
        ==========  ============
        sock        The newly connected socket object.
        addr        The new socket's address.
        exception   The exception that was raised.
        ==========  ============
        """
        log.exception(exception)
        try:
            sock.close()
        except socket.error:
            pass

    ##### Internal Methods ####################################################

    def _do_listen(self, addr, family, backlog, slave):
        """
        A callback method to be used with
        :meth:`~pants._channel._Channel._resolve_addr` - either listens
        immediately or notifies the user of an error.

        =========  =====================================================
        Argument   Description
        =========  =====================================================
        backlog    The maximum size of the connection queue.
        slave      If True, this will cause a Server listening on
                   IPv6 INADDR_ANY to create a slave Server that
                   listens on the IPv4 INADDR_ANY.
        addr       The address to listen on or None if address
                   resolution failed.
        family     The detected socket family or None if address
                   resolution failed.
        error      *Optional.* Error information or None if no error
                   occured.
        =========  =====================================================
        """
        if self._socket:
            if self._socket.family != family:
                self.engine.remove_channel(self)
                self._socket_close()
                self._closed = False

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
        except socket.error as err:
            self.close()
            raise

        self.listening = True
        self._safely_call(self.on_listen)

        if slave and not isinstance(addr, str) and addr[0] == '' and HAS_IPV6:
            # Silently fail if we can't make a slave.
            try:
                self._slave = _SlaveServer(self.engine, self, addr, backlog)
            except Exception:
                self._slave = None

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
                except ssl.SSLError as e:
                    self._safely_call(self.on_ssl_wrap_error, sock, addr, e)
                    continue

            self._safely_call(self.on_accept, sock, addr)

    def _handle_write_event(self):
        """
        Handle a write event raised on the channel.
        """
        log.warning("Received write event for %r." % self)


###############################################################################
# _SlaveServer Class
###############################################################################

class _SlaveServer(Server):
    """
    A slave for a StreamServer to allow listening on multiple address
    familes.
    """
    def __init__(self, engine, server, addr, backlog):
        Server.__init__(self, engine=engine)
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
        except socket.error as err:
            self.close()
            raise

        self._remote_address = None
        self._local_address = None

        self.listening = True

        self.on_accept = self.server.on_accept

    def on_close(self):
        if self.server._slave == self:
            self.server._slave = None
