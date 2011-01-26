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
        
        Args:
            host: The hostname to connect to.
            port: The port to connect to.
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
        
        Args:
            server: The server to which this channel is connected.
            sock: The raw socket which this channel wraps.
        """
        Channel.__init__(self, socket)
        
        self.server = server
        self._connected = True


###############################################################################
# Server Class
###############################################################################

class Server(Channel):
    """
    A basic implementation of a server.
    """
    # The class to use to wrap newly connected sockets.
    ConnectionClass = Connection
    
    def __init__(self, ConnectionClass=None):
        """
        Initialises the server.
        
        Args:
            ConnectionClass: The class to use to wrap newly connected
            sockets. Optional.
        """
        Channel.__init__(self)
        
        # Sets instance attribute, NOT class attribute.
        if ConnectionClass:
            self.ConnectionClass = ConnectionClass
        
        # A dictionary mapping file descriptors to channels.
        self.channels = weakref.WeakValueDictionary()
    
    ##### General Methods #####################################################
    
    def writable(self):
        """
        Servers are never writable.
        
        Returns:
            False.
        """
        return False
    
    ##### Public Event Handlers ###############################################
    
    def handle_accept(self, sock, addr):
        """
        Called when a new connection has been made to the channel.
        
        Creates a new instance of the server's ConnectionClass and adds
        it to the server.
        
        Args:
            sock: The newly-connected socket object.
            addr: The socket's address.
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
