Using Channels
**************

Pants applications centre around the use of **channels** to perform
non-blocking I/O on :obj:`sockets <socket.socket>`. A channel is simply an
object that wraps a socket and provides a clean, safe interface with which to
interact with that socket. Pants provides a number of
:ref:`channel classes <channelclasses>` that cover most use-cases.


Channel Basics
==============

Channels are created by simply instantiating one of Pants' channel classes::

    channel = Client()

The above code, for instance, will create a new :class:`~pants.basic.Client`
channel.

Channel classes have a number of methods - specified in their APIs - that
allow you to do things like connect to remote servers or start listening for
incoming packets::

    channel.connect(('example.com', 80))

Once you've finished working with a channel, you should make sure it is closed
properly, to ensure that it is cleaned up and removed from the engine::

    channel.close()


Callbacks
---------

Custom channel behaviour is defined on channels using callbacks. A callback is
a method that is invoked when a particular event occurs on the channel - for
instance, when data is read or a new client connects to the socket.

When you want to define custom behaviour for a channel, you should subclass
one of the existing channel classes and define one or more callback methods on
it. There are six core callback methods used in Pants:

* :meth:`on_read` - Called when data is read from the channel.
* :meth:`on_write` - Called after the channel has finished writing data.
* :meth:`on_connect` - Called after the channel has connected to a remote socket.
* :meth:`on_listen` - Called when the channel begins listening for new connections or packets.
* :meth:`on_accept` - Called after the channel has accepted a new connection.
* :meth:`on_close` - Called after the channel has finished closing.

There are also several error-handling callbacks. These callbacks are invoked
when errors occur on the channel, allowing you to handle those errors in the
manner most suited to your use case. The basic error callbacks are:

* :meth:`on_connect_error` - Called when the channel has failed to connect to a remote socket.
* :meth:`on_overflow_error` - Called when an internal buffer on the channel has exceeded its size limit.
* :meth:`on_error` - Called when an error occurs and no specific error-handling callback exists.

Some channel classes will define custom callback methods used in more specific
situations (SSL-enabled channels, for instance). Most channel classes do not
use all available callbacks - server channels do not read or write data, for
instance, and packet-oriented channels do not open or accept connections. The
callbacks used by a particular channel class are documented in their
respective APIs.

After you've defined a callback method on your channel subclass, it will be
invoked whenever the relevant event occurs on your channel. For instance, here
is a :class:`~pants.basic.Connection` that prints any data it receives::

    class Printer(Connection):
        def on_read(self, data):
            print data


Handling Incoming Data
----------------------

One of the most common things you'll want to do when writing channel code is
buffer incoming data and divide it into meaningful chunks. Pants channels
allow you to do this through the use of a ``read_delimiter`` attribute.
Channels will buffer incoming data internally and pass it to the
:meth:`on_read` callback periodically, depending on the value of the read
delimiter.

The read delimiter can be set at runtime to either ``None`` (the default), a
string, or an integer. Once the read delimiter has been set, the channel will
continue to read data in the specified manner until the value of the read
delimiter is changed.

When the value is ``None``, data will not be buffered and will be passed
immediately to :meth:`on_read` upon being read.

When the value is a string, data will be read and buffered internally
until that string is encountered, at which point the data will be passed
to :meth:`on_read`.

When the value is an integer, that number of bytes will be read into the
internal buffer before being passed to :meth:`on_read`.

Using the read delimiter effectively can make implementing protocols
significantly simpler. Here is a line-oriented protocol::

    class LineOriented(Connection):
        def on_connect(self):
            self.read_delimiter = '\r\n'

        def on_read(self, line):
            print line


.. _channelclasses:

Channel Classes
===============

Pants provides a number of channel classes that range in their level of
abstraction from low to high. The lower-level channel classes are
:class:`~pants.stream.Stream`, :class:`~pants.stream.StreamServer` and
:class:`~pants.datagram.Datagram`. The higher-level channel classes are
:class:`~pants.basic.Client`, :class:`~pants.basic.Connection`, and
:class:`~pants.basic.Server`. The different channel classes all have different
use-cases, and you should select the one most suitable for your application.


Types & Families
----------------

Channels have a type and a family that determines their behaviour. Pants
supports the most commonly used socket types and families. The lower-level
channel classes implement functionality for different socket types, while the
higher-level channel classes subclass the lower-level ones and implement
family-specific functionality.

Pants supports the two main families of socket - network
(:const:`~socket.AF_INET` and :const:`~socket.AF_INET6`) and Unix
(:const:`~socket.AF_UNIX`). Network channels - as the name implies - are used
for communication over a network such as the Internet. Unix channels, on the
other hand, are used for inter-process communication between Unix processes.
Unix channels are only supported on certain platforms.

When it comes to types, Pants supports stream-oriented
(:const:`~socket.SOCK_STREAM`) and packet-oriented
(:const:`~socket.SOCK_DGRAM`)
channels. These are explained in further detail below.


Stream-Oriented
---------------

Stream-oriented channels are connection-based - they may represent local
servers, remote connections to local servers and local connections to remote
servers. At the lower level, the :class:`~pants.stream.Stream` and
:class:`~pants.stream.StreamServer` classes are used to represent streaming
channels. There are higher-level classes to represent clients, servers and
connections of the network and Unix families.

Packet-Oriented
---------------

Packet-oriented channels are connectionless. Channels represented by
:class:`~pants.datagram.Datagram` are used to send and receive packets to and
from remote packet-oriented sockets. Typically, only one packet-oriented
channel is required for each protocol you intend to implement.

Clients
^^^^^^^

Client channels represent connections from the application to a remote host.
The :class:`~pants.basic.Client` class represents a client. You will need to
subclass :class:`~pants.basic.Client` in order to implement your client's
functionality.

Servers
^^^^^^^

Server channels represent local sockets listening for new connections. The
:class:`~pants.basic.Server` class represents a server. When a remote client
connects to a server channel, a new instance of a specified
:ref:`connection <connections>` class will be automatically created to
represent that remote connection. It is often not necessary to subclass
:class:`~pants.basic.Server` - it is possible to specify a connection class
for the server to use simply by passing it as an argument to the server's
constructor.

.. _connections:

Connections
^^^^^^^^^^^

Connection channels represent connections from a remote host to a server
running in the application. The :class:`~pants.basic.Connection` class
represents a socket connection. Connection channels can be used in much the
same as client channels can, with the simple exception that you do not need to
tell them to connect to a remote host - they are already connected when they
are created.

Using a Stream
^^^^^^^^^^^^^^

Once created, a streaming channel can be used to connect to remote hosts::

    stream.connect(('example.com', 80)) # On a network stream, connect to example.com on port 80.

Data in the form of a string or a file can be written to the stream::

    stream.write("foo") # Write the string "foo" to the stream.
    stream.write_file(bar) # Write the contents of the 'bar' file to the stream.

And the stream can be closed - either after any remaining data is written or
immediately::

    stream.close(True) # Wait for any remaining data to be written, then close.
    stream.close() # Close immediately.

A streaming server can be told to listen for new connections::

    stream_server.listen(('', 8080)) # Listen for connections to any host on port 8080.

When new connections are made, the new socket and its remote address will be
passed to :meth:`on_accept` - the core classes implement :meth:`on_accept` to
automatically wrap the new socket with a channel class.

Finally, streaming servers can - of course - be closed::

    stream_server.close()


Using a Packet Channel
^^^^^^^^^^^^^^^^^^^^^^

Once created, a packet channel can be told to for incoming packets::

    datagram.listen(('', 8080)) # Listen for packets sent to any host on port 8080.

Packets can be send to remote hosts::

    datagram.write("foo", ('example.com', 80)) # Send the string "foo" to example.com on port 80.

And, as with streams, the packet channel can be closed either immediately or
after it has finished writing data::

    datagram.end()
    datagram.close()
