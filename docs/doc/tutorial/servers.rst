Servers
*******
Servers in Pants make use of two classes - ``Server`` and ``Connection``.
An instance of the ``Server`` class represents an actual server - a socket
listening for connections. An instance of the ``Connection`` class represents
a connection from a remote host to a ``Server`` instance in the application.
It's easy to create a server::

    from pants import Server
    
    Server().listen()

By default, a server will bind to any available host on port 8080. It's easy to
specify the port::

    Server().listen(8080)

And also the host::

    Server().listen(8080, '')

**Note:** The host and port arguments are reversed from their normal positions
because it is far more common to need to specify the port than the host.

Connections
===========
In order to have your server do something interesting you will generally need
to subclass ``Connection`` and tell your server to use your custom class to
represent connections. Here is a ``Connection`` subclass that sends any data
that it recieves back to the remote host::

    from pants import Connection
    
    class EchoConnection(Connection):
        def handle_read(self, data):
            self.send(data)

Servers
=======
Creating a server that uses your custom connection is easy::

    Server(EchoConnection).listen()

Passing a ``Connection`` class to a ``Server`` will tell the server to use that
class to represent connections. This is a convenient feature when you do not
need to subclass ``Server`` yourself (in most situations, the default
``Server`` class will suit your needs). Sometimes you will subclass ``Server``,
however::

    class EchoServer(Server):
        ConnectionClass = EchoConnection

In these cases you can define the default ``Connection`` class as a class
attribute on your ``Server`` subclass.

Putting Them Together
=====================
Here's an example of a simple server that sends data received on a connection
to every connection::

    from pants import Connection, Server
    
    class EchoConnection(Connection):
        def handle_read(self, data):
            self.server.send(data)
    
    class EchoServer(Server):
        ConnectionClass = EchoConnection
        
        def send(self, data):
            for channel in self.channels.itervalues():
                channel.send(data)

    EchoServer().listen()

As illustrated in the above example, connections retain a reference to the
server they are "on". Similarly, servers retain a dictionary containing all the
connections that are "on" them as values.
