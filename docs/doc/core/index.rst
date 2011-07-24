Core
****

The Pants core is an asynchronous, non-blocking network programming
framework designed with speed, simplicity and size in mind. It provides
an asynchronous :obj:`~pants.engine.Engine` to power your application as
well as several layers of abstraction around :obj:`~socket.socket` objects
to make network programming significantly simpler.

Applications
============

A basic Pants application consists of some number of :class:`~pants.channel.Channel`
objects being continuously updated by a single, central
:obj:`~pants.engine.Engine` object. :class:`~pants.channel.Channel`
subclasses may represent a local server (:class:`~pants.network.Server`),
a connection to a local server (:class:`~pants.network.Connection`) or a
connection to a remote server (:class:`~pants.network.Client`).

Asynchronous
------------

Pants is asynchronous, meaning that rather than starting to read or write
data and then doing nothing until that operation is complete, it instead
performs I/O in the background as it becomes possible to do so. This makes
Pants fast and able to handle a large number of concurrent connections.

However, because Pants is asynchronous, it is very important that none of
the code in your application `blocks <http://en.wikipedia.org/wiki/Blocking_(computing)>`_
the process. Any blocking code will cause the entire process to wait until
the blocking operation is complete, preventing any :class:`~pants.channel.Channel`
objects from being updated.

Callback-Oriented
-----------------

To eliminate the need for blocking code, Pants uses a callback-oriented
design. Blocking operations like reading or writing to a :class:`~pants.channel.Channel`
are performed in the background. When these operations complete, a
callback method is invoked to notify the :class:`~pants.channel.Channel`.
Most of the code in a Pants application will hook into these callbacks to
implement functionality.

Example: Echo
=============

::

    from pants import Connection, engine, Server
    
    class Echo(Connection):
        def on_read(self, data):
            self.write(data)
    
    Server(Echo).listen(4000)
    engine.start()

The above code is an example of a very simple Pants application. A
:obj:`~pants.network.Connection` subclass is defined with a single
callback. A :obj:`~pants.network.Server` is then created and told to
use the :class:`Echo` class for new connections. The server is told to
listen on port 4000 and the :obj:`~pants.engine.Engine` is started.

When a new connection is made to the server on port 4000, an instance of
the :class:`Echo` class will be created to wrap that connection. When
data arrives on the connection it will be read automatically and passed
to the :meth:`on_read` method, which will then pass it to the
:meth:`~pants.network.Connection.write` method, causing the data to be
sent back to the end user.

You can try this out yourself - run this script in a terminal window and,
in another window, use the ``telnet localhost 4000`` command to connect to
the server. Anything you type into the window will be sent back to your
client and echoed in your terminal.

API
===

.. toctree::
    :maxdepth: 2
    
    engine
    channel
    stream
    datagram
    network
    dns
