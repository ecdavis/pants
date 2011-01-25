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

import weakref

from pants.channel import Channel
from pants.shared import log


###############################################################################
# Client Class
###############################################################################

class Client(Channel):
    """
    A basic implementation of a client.
    """
    def __init__(self, host, port):
        """
        Initialises the client and connects to the remote host.
        
        :param host: The hostname to connect to.
        :type host: str
        :param port: The port to connect to the host on.
        :type port: int
        """
        Channel.__init__(self)
        
        self.connect(host, port)


###############################################################################
# Connection Class
###############################################################################

class Connection(Channel):
    """
    A basic implementation of a connection to a server.
    """
    def __init__(self, server, socket):
        """
        Initialises the connection.
        
        :param server: The server to which this channel is connected.
        :type server: :class:`pants.network.Server`
        :param socket: The raw socket which this channel wraps.
        :type socket: :class:`socket.socket`
        """
        Channel.__init__(self, socket)
        
        #: The server to which this channel is connected.
        self.server = server
        self._connected = True


###############################################################################
# Server Class
###############################################################################

class Server(Channel):
    """
    A basic implementation of a server.
    """
    #: The class to use to wrap newly connected sockets.
    ConnectionClass = Connection
    
    def __init__(self, ConnectionClass=None):
        """
        Initialises the server.
        
        :param ConnectionClass: The class to use to wrap newly connected
            sockets. Optional.
        :type ConnectionClass: :class:`pants.network.Connection`
        """
        Channel.__init__(self)
        
        # Sets instance attribute, NOT class attribute.
        if ConnectionClass:
            self.ConnectionClass = ConnectionClass
        
        #: A dictionary mapping file descriptors to instances of
        #: :class:`pants.channel.Channel`.
        self.channels = weakref.WeakValueDictionary()
    
    ##### General Methods #####################################################
    
    def writable(self):
        """
        Servers are never writable.
        
        :returns: False
        """
        return False
    
    ##### Public Event Handlers ###############################################
    
    def handle_accept(self, sock, addr):
        """
        Called when a new connection has been made to the channel.
        
        Creates a new instance of the server's ConnectionClass and adds
        it to the server.
        
        :param sock: The newly-connected raw socket.
        :type sock: :class:`socket.socket`
        :param addr: The address bound to the socket on the other end of the
            connection.
        :type addr: tuple
        """
        connection = self.ConnectionClass(self, sock)
        self.channels[connection.fileno] = connection
        connection._safely_call(connection.handle_connect)
    
    def handle_close(self):
        """
        Closes all active connections to the server.
        """
        for channel in self.channels.values():
            channel.close()
