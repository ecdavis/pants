###############################################################################
#
# Copyright 2011 Chris Davis
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
import ssl

from pants.channel import Channel
from pants.network import Client, Connection, Server
from pants.shared import log


###############################################################################
# _SSLChannel Class
###############################################################################

class _SSLChannel(Channel):
    def __init__(self):
        # Craftiness happens here. This method must be called after
        # Channel.__init__() has been called, but it cannot call
        # Channel.__init__() itself/
        self._ssl_handshake_done = False
        if not isinstance(self._socket, ssl.SSLSocket):
            self._ssl_wrap(**ssl_kwargs)
    
    def _ssl_wrap(self):
        self._socket = ssl.wrap_socket(self._socket)
    
    def _ssl_do_handshake(self):
        try:
            self._socket.do_handshake()
        except ssl.SSLError, err:
            if err[0] == ssl.SSL_ERROR_WANT_READ:
                self._add_event(self._reactor.READ)
            elif err[0] == ssl.SSL_ERROR_WANT_WRITE:
                self._add_event(self._reactor.WRITE)
            elif err[0] in (ssl.SSL_ERROR_EOF, ssl.SSL_ERROR_ZERO_RETURN):
                self.close()
            elif err[0] == ssl.SSL_ERROR_SSL:
                log.exception("SSL error on channel %d." % self.fileno)
                self.close()
            else:
                raise
        except socket.error, err:
            if err[0] == errno.ECONNABORTED:
                self.close()
        else:
            self._ssl_handshake_done = True
    
    def _socket_recv(self):
        try:
            return Channel._socket_recv(self)
        except ssl.SSLError, err:
            if err[0] == ssl.SSL_ERROR_WANT_READ:
                return ''
            else:
                raise
    
    def _handle_read_event(self):
        if not self._ssl_handshake_done:
            self._ssl_do_handshake()
            return
        
        Channel._handle_read_event(self)
    
    def _handle_write_event(self):
        if not self._ssl_handshake_done:
            self._ssl_do_handshake()
            return
        
        Channel._handle_write_event(self)


###############################################################################
# SSLChannel Class
###############################################################################

class SSLChannel(_SSLChannel):
    def __init__(self, socket=None, parent=None):
        Channel.__init__(self, socket, parent)


###############################################################################
# SSLConnection Class
###############################################################################

class SSLConnection(_SSLChannel, Connection):
    def __init__(self, *args, **kwargs):
        Connection.__init__(self, *args, **kwargs)
        _SSLChannel.__init__()


###############################################################################
# SSLServer Class
###############################################################################

class SSLServer(_SSLChannel, Server):
    ConnectionClass = SSLConnection
    
    def __init__(self, *args, **kwargs):
        Server.__init__(self, *args, **kwargs)
        _SSLChannel.__init__(self)
