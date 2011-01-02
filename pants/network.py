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
    A very basic implementation of a client.
    """
    
    def __init__(self, host, port):
        """
        Initialises the client and connects to the remote host.
        
        Parameters:
            host - A string hostname to connect to.
            port - An integer port to connect to the host on.
        """
        Channel.__init__(self)
        
        self.connect(host, port)
    
    ##### Interface Methods ###################################################
    
    def send(self, data):
        """
        Sends data to the socket.
        
        Parameters:
            data - A string containing the data to be sent to the
                socket.
        """
        self.write(data)


###############################################################################
# Connection Class
###############################################################################

class Connection(Channel):
    """
    A basic implementation of a connection to a server.
    """
    def __init__(self, server, socket):
        Channel.__init__(self, socket)
        
        self.server = server
        self.connected = True
    
    ##### Interface Methods ###################################################
    
    def send(self, data):
        """
        Sends data to the socket.
        
        Parameters:
            data - A string containing the data to be sent to the
                socket.
        """
        self.write(data)


###############################################################################
# Server Class
###############################################################################

class Server(Channel):
    """
    A basic implementation of a server.
    
    Most protocol implementation will be done using Connection
    subclasses - you should subclass Server and define the
    ConnectionClass class attribute on said subclass so that the correct
    Connection subclass can be instantiated when new sockets connect.
    """
    ConnectionClass = Connection
    
    def __init__(self, ConnectionClass=None):
        """
        Initialises the server.
        """
        Channel.__init__(self, socket=None)
        
        # Sets instance attribute, NOT class attribute.
        if ConnectionClass:
            self.ConnectionClass = ConnectionClass
        
        self.channels = weakref.WeakValueDictionary()
    
    ##### General Methods #####################################################
    
    def writable(self):
        """
        Returns False - servers are never writable.
        """
        return False
    
    ##### Public Event Handlers ###############################################
    
    def handle_accept(self, sock, addr):
        """
        Accepts new connections to the server.
        
        Creates a new instance of the server's ConnectionClass and adds
        it to the server.
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
