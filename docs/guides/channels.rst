Using Channels
**************

Pants applications centre around the use of **channels** to perform
non-blocking I/O on :obj:`sockets <socket.socket>`. A channel is simply an
object that wraps a socket and provides a clean, safe interface with which to
interact with that socket. Pants provides a number of channel classes that
cover most use-cases.

Channels have a :ref:`type <types>` and a :ref:`family <families>` that
determines their behaviour. Pants supports the most commonly used socket types
and families.


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
one of the existing :ref:`channel classes <channelclasses>` and define one or
more callback methods on it. There are seven callback methods used in Pants:

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
allow you to do this through the use of a **read delimiter** attribute.
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

And here is a slightly more complex example which reads variable length
messages preceded by an unsigned short containing the message length::

    class MessageOriented(Connection):
        def on_connect(self):
            self.read_delimiter = 2
            self.on_read = self.on_read_header
        
        def on_read_header(self, header):
            message_length = struct.unpack("!H", header)
            
            self.read_delimiter = message_length
            self.on_read = self.on_read_message
        
        def on_read_message(self, message):
            print message
            
            self.read_delimiter = 2
            self.on_read = self.on_read_header

As you can see, it is possible to be fairly inventive when combining the read
delimiter with the ability to replace callback methods at runtime.


.. _channelclasses:

Channel Classes
===============


.. _types:

Types
-----

Pants currently supports two types of channels: stream-oriented and
packet-oriented.


.. _families:

Families
--------

Pants currently supports two channel families: network and Unix.
