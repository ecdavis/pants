Channels
********
The ``Channel`` class is a high-level wrapper for raw socket objects.
``Channel`` is *not* part of the basic API, but the ``Client``,
``Server`` and ``Connection`` classes all directly subclass ``Channel``, and it
is therefore covered in this tutorial.

The ``Channel`` class has a simple API that is used in most Pants
applications. Let's look at it now. A channel can be connected to a remote
host::

    channel.connect("example.com", 8080)

Or it can be told to listen for incoming connections::

    channel.listen(host='', port=8080)

**Note:** Both ``connect()`` and ``listen()`` return the ``Channel`` instance -
convenient, no?

Once connected and/or listening, a channel's remote or local address can be
retreived::

    host, port = channel.remote_addr
    host, port = channel.local_addr

You can check whether a channel is active (either connected to a remote host or
listening for connections)::

    channel.active() # Returns True or False

Or whether it is ready to read or write data::

    channel.readable() # Returns True or False
    channel.writable() # Returns True or False

You can write data to a channel::

    channel.write("foobar")

A ``send()`` method also exists, which is simply a wrapper for the ``write()``
method. If you need to change the way data is written (by encoding it
beforehand, for instance) you should override the ``send()`` method and have it
call ``write()``::

    def send(self, data):
        self.write(data + '\r\n') # Add a newline.

Once you get bored of a channel you can close it, ensuring that any pending
data is sent before it closes::

    channel.close()

Or if you need it closed right now, you can do that too::

    channel.close_immediately()

It's up to you.

When certain events occur (like a new connection being made or data arriving)
particular methods are called on the channel. These are just placeholder
functions, ready to be overridden by your subclasses::

    from pants.channel import Channel
    
    class MyChannel(Channel):
        def handle_read(self, data):
            # Called when data arrives from the other end of the
            # channel - said data is passed to this method in the data
            # argument. This method is not called on channels that are
            # listening.
            pass
        
        def handle_write(self):
            # Called right before the channel starts writing data to the
            # other end.
            pass
        
        def handle_accept(self, sock, addr):
            # Called when a new connection has been made to the channel.
            # The raw socket object and the connection's address is
            # passed to this method in the sock and addr arguments. This
            # method is only called on channels that are listening.
            pass
        
        def handle_connect(self):
            # Called after the channel has connected to a remote host.
            pass
        
        def handle_close(self):
            # Called when the channel is about to close.
            pass

In most cases it is unnecessary to subclass ``Channel`` directly - the
``Client``, ``Server`` and ``Connection`` classes will be more than
enough.

Handling Incoming Data
======================
By default, Channel instances will simply read incoming data and pass it to
``handle_read()`` immediately. In many cases, however, you'll be interested in
reading data in chunks. You can do this by setting the ``read_delimiter``
attribute::

    channel.read_delimiter = 100

In the above example, the channel will begin passing data to ``handle_read()``
in chunks of 100 bytes. ``read_delimiter`` can also be a string::

    channel.read_delimiter = '\r\n'

In the above example, the channel will wait until it encounters ``\r\n`` in the
incoming data, at which point it will pass all data receieved up until that
point to ``handle_read()``.

**Note:** ``read_delimiter`` can either be an integer, a string or ``None``.
While ``read_delimiter`` is ``None``, data will be passed to ``handle_read()``
as soon as it arrives.
