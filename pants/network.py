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
    # NOTE This class exists because I may, in the future, implement
    # some sort of client-specific functionality. Maybe.
    pass


###############################################################################
# Connection Class
###############################################################################

class Connection(Channel):
    """
    A basic implementation of a connection to a server.
    """
    def __init__(self, socket, parent, server):
        """
        Initialises the connection.
        
        Args:
            socket: A pre-existing socket that this channel should wrap.
            parent: The reactor that this channel should be attached to.
            server: The server to which this channel is connected.
        
        Note:
            socket and parent arguments are non-optional because they
            are determined by the server.
        """
        Channel.__init__(self, socket, parent)
        # TODO This is really hacky.
        self._Connection_init(server)
    
    def _Connection_init(self, server): 
        """
        Separate connection initialisation method so that
        Channel.__init__() does not get called twice by SSLConnection.
        
        TODO This is really hacky.
        """
        self.server = server


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
        # TODO This is really hacky.
        self._Server_init(ConnectionClass)
    
    def _Server_init(self, ConnectionClass):
        """
        Separate server initialisation method so that Channel.__init__()
        does not get called twice by SSLServer.
        
        TODO This is really hacky.
        """
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
    
    def handle_accept(self, socket, addr):
        """
        Called when a new connection has been made to the channel.
        
        Creates a new instance of the server's ConnectionClass and adds
        it to the server.
        
        Args:
            socket: The newly-connected socket object.
            addr: The socket's address.
        """
        connection = self.ConnectionClass(self, socket, self._reactor)
        self.channels[connection.fileno] = connection
        connection._handle_connect_event()
    
    def handle_close(self):
        """
        Closes all active connections to the server.
        """
        for channel in self.channels.values():
            channel.close()
