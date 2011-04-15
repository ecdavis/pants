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

from pants.stream import Stream


###############################################################################
# Client Class
###############################################################################

class Client(Stream):
    """
    A basic implementation of a client.
    """
    # NOTE This class exists because I may, in the future, implement
    # some sort of client-specific functionality. Maybe.
    pass


###############################################################################
# Connection Class
###############################################################################

class Connection(Stream):
    """
    A basic implementation of a connection to a server.
    """
    def __init__(self, socket, server):
        """
        Initialises the connection.
        
        Args:
            socket: A pre-existing socket that this channel should wrap.
            server: The server to which this channel is connected.
        
        Note:
            socket and parent arguments are non-optional because they
            are determined by the server.
        """
        Stream.__init__(self, socket=socket)
        
        self.server = server


###############################################################################
# Server Class
###############################################################################

class Server(Stream):
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
        Stream.__init__(self)
        
        # Sets instance attribute, NOT class attribute.
        if ConnectionClass:
            self.ConnectionClass = ConnectionClass
        
        self.channels = weakref.WeakValueDictionary() # fd : channel
    
    ##### Public Event Handlers ###############################################
    
    def on_accept(self, socket, addr):
        """
        Called when a new connection has been made to the channel.
        
        Creates a new instance of the server's ConnectionClass and adds
        it to the server.
        
        Args:
            socket: The newly-connected socket object.
            addr: The socket's address.
        """
        connection = self.ConnectionClass(socket, self)
        self.channels[connection.fileno] = connection
        connection._handle_connect_event()
    
    def on_close(self):
        """
        Closes all active connections to the server.
        """
        for channel in self.channels.values():
            channel.close()
