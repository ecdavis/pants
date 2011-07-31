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

The above code, for instance, will create a new :class:`~pants.network.Client`
channel.

Channel classes have a number of methods - specified in their APIs - that
allow you to do things like connect to remote servers or start listening for
incoming packets::

    channel.connect('example.com', 80)

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
it. There are seven callback methods used in Pants:

* :meth:`on_read` - Called when data is read from the channel.
* :meth:`on_write` - Called after the channel has finished writing data.
* :meth:`on_connect` - Called after the channel has connected to a remote socket.
* :meth:`on_connect_error` - Called when the channel has failed to connect to a remote socket.
* :meth:`on_listen` - Called when the channel begins listening for new connections or packets. 
* :meth:`on_accept` - Called after the channel has accepted a new connection.
* :meth:`on_close` - Called after the channel has finished closing.

Most channel classes do not use all seven callbacks - server channels do not
read or write data, for instance, and packet-oriented channels do not create
or accept connections. The callbacks used by a particular channel class are
documented in their respective APIs.

After you've defined a callback method on your channel subclass, it will be
invoked whenever the relevant event occurs on your channel. For instance, here
is a :class:`~pants.network.Connection` that prints any data it receives::

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
:class:`~pants.network.Client`, :class:`~pants.network.Connection`,
:class:`~pants.network.Server`, :class:`~pants.unix.UnixClient`,
:class:`~pants.unix.UnixConnection` and :class:`~pants.unix.UnixServer`. The
different channel classes all have different use-cases, and you should select
the one most suitable for your application.

Channels have a :ref:`type <types>` and a :ref:`family <families>` that
determines their behaviour. Pants supports the most commonly used socket types
and families. The lower-level channel classes implement functionality for
different socket types, while the higher-level channel classes subclass the
lower-level ones and implement family-specific functionality.


.. _types:

Types
-----

Pants currently supports two types of channels: stream-oriented and
packet-oriented.


Stream-Oriented
^^^^^^^^^^^^^^^

Stream-oriented channels are connection-based. :class:`~pants.stream.Stream`
is used to represent local connections to remote servers and remote
connections to local servers. :class:`~pants.stream.StreamServer` is used to
represent local servers themselves. Stream-oriented channels are the most
common, and it is these two classes that the higher-level channel classes
inherit from.

Once created, an instance of :class:`~pants.stream.Stream` can be used to
connect to remote hosts::

    stream.connect(('example.com', 80)) # On a network stream, connect to example.com on port 80.

Data in the form of a string or a file can be written to the stream::

    stream.write("foo") # Write the string "foo" to the stream.
    stream.write_file(bar) # Write the contents of the 'bar' file to the stream.

And the stream can be closed - either after any remaining data is written or
immediately::

    stream.end() # Wait for any remaining data to be written, then close.
    stream.close() # Close immediately.

An instance of :class:`~pants.stream.StreamServer` can be told to listen for
new connections::

    stream_server.listen(('', 8080)) # Listen for connections to any host on port 8080.

When new connections are made, the raw socket and remote address will be
passed to :meth:`~pants.stream.StreamServer.on_accept`. Finally, stream
servers can, of course, be closed::

    stream_server.close()


Packet-Oriented
^^^^^^^^^^^^^^^

Packet-oriented channels, on the other hand, are connectionless. Channels
represented by :class:`~pants.datagram.Datagram` are used to send and receive
packets to and from remote packet-oriented sockets. Typically, only one
packet-oriented channel is required for each protocol you intend to implement.

Once created, an instance of :class:`~pants.datagram.Datagram` can be told to
listen for incoming packets::

    datagram.listen(('', 8080)) # Listen for packets sent to any host on port 8080.

Packets can be send to remote hosts::

    datagram.write("foo", ('example.com', 80)) # Send the string "foo" to example.com on port 80.

And, as with streams, the datagram channel can be closed either immediately or
after it has finished writing data::

    datagram.end()
    datagram.close()


.. _families:

Families
--------

Pants currently supports two channel families: network and Unix.
