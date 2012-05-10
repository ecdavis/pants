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
A convenient collection of high-level streaming channels.
"""

###############################################################################
# Imports
###############################################################################

import socket
import weakref

from pants.engine import Engine
from pants.stream import Stream, StreamServer


###############################################################################
# Client Class
###############################################################################

class Client(Stream):
    """
    A simple streaming client.

    ============  ======================================================
    Argument      Description
    ============  ======================================================
    ssl_options   *Optional.* If provided,
                  :meth:`~pants.stream.Stream.startSSL` will be called
                  with these options once the channel is ready.
    engine        *Optional.* The engine to which the channel should be
                  added.
    ============  ======================================================
    """
    def __init__(self, ssl_options=None, engine=Engine.instance()):
        # This dummy method prevents keyword arguments from finding
        # their way up to the Stream/_Channel constructors.
        Stream.__init__(self, ssl_options=ssl_options, engine=engine)


###############################################################################
# Connection Class
###############################################################################

class Connection(Stream):
    """
    A simple streaming connection to a server.

    =========  ============
    Argument   Description
    =========  ============
    engine     The engine to which the channel should be added.
    server     The server to which the channel is connected.
    socket     The pre-existing socket that the channel should wrap.
    =========  ============
    """
    def __init__(self, engine, server, socket):
        Stream.__init__(self, socket=socket, engine=engine)

        self.server = server


###############################################################################
# Server Class
###############################################################################

class Server(StreamServer):
    """
    A simple streaming server.

    ================  ===================================================
    Argument          Description
    ================  ===================================================
    ConnectionClass   *Optional.* A :obj:`pants.basic.Connection`
                      subclass with which to wrap newly connected
                      sockets.
    ssl_options       *Optional.* If provided,
                      :meth:`~pants.stream.StreamServer.startSSL` will
                      be called with these options once the channel is
                      ready.
    engine            *Optional.* The engine to which the channel should
                      be added.
    ================  ===================================================
    """
    #: A :obj:`pants.basic.Connection` subclass with which to wrap newly connected sockets.
    ConnectionClass = Connection

    def __init__(self, ConnectionClass=None, ssl_options=None,
            engine=Engine.instance()):
        StreamServer.__init__(self, ssl_options=ssl_options, engine=engine)

        # Sets instance attribute, NOT class attribute.
        if ConnectionClass:
            self.ConnectionClass = ConnectionClass

        self.channels = weakref.WeakValueDictionary()  # fd : channel

    ##### Control Methods #####################################################

    def listen(self, addr=('', 8080), backlog=1024):
        """
        Begin listening for connections made to the channel.

        Returns the channel.

        ==========  ==============================================
        Arguments   Description
        ==========  ==============================================
        addr        *Optional.* The local address to listen for
                    connections on.
        backlog     *Optional.* The size of the connection queue.
        ==========  ==============================================
        """
        return StreamServer.listen(self, addr, backlog)

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
        connection = self.ConnectionClass(self.engine, self, socket)
        self.channels[connection.fileno] = connection
        connection._handle_connect_event()

    def on_close(self):
        """
        Called after the channel has finished closing.

        Close all active connections to the server.
        """
        for channel in self.channels.values():
            channel.close()
