###############################################################################
#
# Copyright 2011 Chris Davis
# Copyright 2011 Stendec <stendec365@gmail.com>
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

from __future__ import absolute_import

import functools
import logging
import socket

try:
    import ssl
    CERT_NONE = ssl.CERT_NONE
    
except ImportError:
    ssl = None
    CERT_NONE = None

from pants.channel import Channel
from pants.engine import Engine
from pants.network import Server

###############################################################################
# Logging
###############################################################################

log = logging.getLogger('pants')

###############################################################################
# The startTLS Function
###############################################################################

def is_secure(self):
    return hasattr(self, '_ssl_handshake_done')
Channel.is_secure = is_secure

def startTLS(self, keyfile=None, certfile=None, server_side=False,
                cert_reqs=CERT_NONE, ca_certs=None, suppress_ragged_eofs=True,
                ciphers=None):
    """
    Modify an instance of pants.channel.Channel to support transport layer
    security and begin the SSL handshake immediately, if the socket is already
    connected.
    
    If the socket is not currently connected, the handshake will be performed
    immediately upon connection.
    
    For more information on this function's arguments, please see:
    ssl.wrap_socket
    """
    
    if ssl is None:
        raise ImportError("No module named ssl")
    
    # Internal State
    self._ssl_handshake_done = False
    self._connect_on_ssl_done = False
    
    # Modify the Channel
    self._handle_connect_event = functools.partial(_handle_connect_event, self)
    self._handle_read_event = functools.partial(_handle_read_event, self)
    self._handle_write_event = functools.partial(_handle_write_event, self)
    self._socket_recv = functools.partial(_socket_recv, self)
    self._wrapped_close_immediately = self.close_immediately
    self.close_immediately = functools.partial(wrapped_close, self)
    
    self.ssl_keyfile = keyfile
    self.ssl_certfile = certfile
    self.ssl_server_side = server_side
    self.ssl_cert_reqs = cert_reqs
    self.ssl_ca_certs = ca_certs
    self.ssl_suppress_ragged_eofs = suppress_ragged_eofs
    
    # Are we connected? If so, wrap and handshake immediately.
    if self._connected:
        self._ssl_wrap()
        self._ssl_handshake()

Channel.startTLS = startTLS

def endTLS(self):
    if not isinstance(self._socket, ssl.SSLSocket):
        return
    
    # Modify the channel.
    for func in ('_handle_connect_event', '_handle_read_event',
                 '_handle_write_event', '_socket_recv', 'close_immediately'):
        setattr(self, func, functools.partial(getattr(Channel, func), self))
    
    del self.ssl_keyfile
    del self.ssl_certfile
    del self.ssl_server_side
    del self.ssl_cert_reqs
    del self.ssl_ca_certs
    del self.ssl_suppress_ragged_eofs
    del self._ssl_handshake_done
    del self._connect_on_ssl_done
    
    self._socket = self._socket.unwrap()

Channel.endTLS = endTLS

###############################################################################
# The Socket Wrapper and Cleanup
###############################################################################

def wrapped_close(self):
    self.close_immediately = self._wrapped_close_immediately
    self.close_immediately()
    
    # Cleanup so we don't hold back GC.
    for func in ('_handle_connect_event', '_handle_read_event',
                 '_handle_write_event', '_socket_recv', 'close_immediately'):
        delattr(self, func)
    
    del self.ssl_keyfile
    del self.ssl_certfile
    del self.ssl_server_side
    del self.ssl_cert_reqs
    del self.ssl_ca_certs
    del self.ssl_suppress_ragged_eofs
    del self._ssl_handshake_done
    del self._connect_on_ssl_done

def _ssl_wrap(self):
    if not isinstance(self._socket, ssl.SSLSocket):
        self._socket = ssl.wrap_socket(
            self._socket,
            keyfile=self.ssl_keyfile,
            certfile=self.ssl_certfile,
            server_side=self.ssl_server_side,
            cert_reqs=self.ssl_cert_reqs,
            ca_certs=self.ssl_ca_certs,
            do_handshake_on_connect=False,
            suppress_ragged_eofs=self.ssl_suppress_ragged_eofs,
            )

Channel._ssl_wrap = _ssl_wrap

###############################################################################
# Channel._ssl_handshake
###############################################################################

def _ssl_handshake(self):
    try:
        self._socket.do_handshake()
    
    except ssl.SSLError, err:
        if err[0] == ssl.SSL_ERROR_WANT_READ:
            self._add_event(Engine.READ)
        elif err[0] == ssl.SSL_ERROR_WANT_WRITE:
            self._add_event(Engine.WRITE)
        elif err[0] in (ssl.SSL_ERROR_EOF, ssl.SSL_ERROR_ZERO_RETURN):
            self.close_immediately()
        elif err[0] == ssl.SSL_ERROR_SSL:
            log.exception("SSL error on channel %d." % self.fileno)
            self.close_immediately()
        else:
            raise
        return
    
    except socket.error, err:
        if err[0] == errno.ECONNABORTED:
            self.close()
        return
    
    self._ssl_handshake_done = True
    self._safely_call(self.handle_connect)

Channel._ssl_handshake = _ssl_handshake

###############################################################################
# Socket Operations
###############################################################################

def _socket_recv(self):
    try:
        data = self._socket.read(self._read_amount)
    except ssl.SSLError, err:
        if err[0] == ssl.SSL_ERROR_WANT_READ:
            return ''
        else:
            raise
    except socket.error, e:
        if err[0] in (errno.EWOULDBLOCK, errno.EAGAIN):
            return ''
        elif err[0] in (errno.ECONNABORTED, errno.ECONNRESET, errno.ENOTCONN,
                        errno.ESHUTDOWN):
            self.close_immediately()
            return ''
        else:
            raise
    
    if not data:
        self.close_immediately()
        return ''
    else:
        return data

###############################################################################
# Event Handling
###############################################################################

def _handle_connect_event(self):
    self._connected = True
    self._connecting = False
    
    if not self._ssl_handshake_done:
        self._connect_on_ssl_done = True
        
        self._ssl_wrap()
        self._ssl_handshake()
        return
    
    self._safely_call(self.handle_connect)

def _handle_read_event(self):
    if not self._ssl_handshake_done:
        self._ssl_handshake()
        return
    
    Channel._handle_read_event(self)

def _handle_write_event(self):
    if not self._ssl_handshake_done:
        self._ssl_handshake()
        return
    
    Channel._handle_write_event(self)

###############################################################################
# SSLServer Class
###############################################################################

class SSLServer(Server):
    """
    An extension of the basic Server class that uses SSL for every connection.
    """
    
    def __init__(self, ConnectionClass=None, ssl_options=None):
        Server.__init__(self, ConnectionClass)
        self.ssl_options = ssl_options
        
        if self.ssl_options:
            assert ssl, "Python 2.6+ is required for SSL."
            
            if not 'server_side' in self.ssl_options:
                self.ssl_options['server_side'] = True
    
    def handle_accept(self, socket, addr):
        """
        Called when a new connection has been made to the channel. This is
        modified to start TLS handshaking for every new connection.
        
        Args:
            socket: The newly-connected socket object.
            addr: The socket's address.
        """
        connection = self.ConnectionClass(socket, self)
        if self.ssl_options and isinstance(connection, Channel):
            connection.startTLS(**self.ssl_options)
        
        self.channels[connection.fileno] = connection
        connection._handle_connect_event()
