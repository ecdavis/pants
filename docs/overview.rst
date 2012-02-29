Overview
********

Pants is an asynchronous, non-blocking network programming framework designed
with speed, simplicity and size in mind. It provides an asynchronous
:ref:`engine <engine>` to power your application as well as abstractions
around sockets to make network programming significantly simpler.

.. toctree::


Applications
============

A basic Pants application consists of some number of :ref:`channel <channels>`
and  :ref:`timer <timers>` objects being continuously updated by a single,
central :ref:`engine <engine>` object. The primary purpose of a Pants
application is to perform I/O on sockets, allowing you to build fast, simple
network applications.

Pants is asynchronous, meaning that rather than starting to read or write data
and then doing nothing until that operation is complete, it instead performs
I/O in the background as it becomes possible to do so. This makes Pants fast
and able to handle a large number of concurrent connections.

However, because Pants is asynchronous, it is very important that none of the
code in your application `blocks
<http://en.wikipedia.org/wiki/Blocking_(computing)>`_ the process. Any
blocking code will cause the entire process to wait until the blocking
operation is complete, preventing any channel objects from being updated.

To eliminate the need for blocking code, Pants uses a callback-oriented
design. Blocking operations like reading or writing to a
:ref:`channel <channels>` are performed in the background. When these
operations complete, a callback method is invoked to notify the
:ref:`channel <channels>`. Most of the code in a Pants application will hook
into these callbacks to implement functionality.


.. _engine:

Engine
======

The engine is the core object of any Pants application. It keeps track of
every active :ref:`channel <channels>` and continuously checks them for new
events, raising them when they occur. The engine also provides the
:ref:`timer <timers>` functionality which allows functions to be executed
after some delay without blocking the process.

**Further information:** :doc:`guides/using_the_engine`


.. _channels:

Channels
========

Channels in Pants are objects that wrap a non-blocking :obj:`~socket.socket`
and provide a simple, convenient interface with which to interact with that
socket.

Channels may represent local servers, remote connections to local servers or
local connections to remote servers. Channels may use either network sockets
or Unix sockets and can be stream-oriented (TCP) or packet-oriented (UDP).

**Further information:** :doc:`guides/using_channels`


.. _timers:

Timers
======

Timers are function calls that are delayed until some point in the future.
They can be one-off or repeating and can be scheduled to execute in sync with
Pants' main event loop or after an arbitrary amount of time. Naturally, timers
will not block the process, which is particularly useful given Pants'
asynchronous nature.

**Further information:** :doc:`guides/using_timers`


Example: Echo
=============

::

    from pants import Connection, engine, Server

    class Echo(Connection):
        def on_read(self, data):
            self.write(data)

    Server(Echo).listen(4040)
    engine.start()

The above code is an example of a very simple Pants application. A
:class:`~pants.basic.Connection` subclass called :class:`Echo` is defined with
a single callback (:func:`on_read`). A :class:`~pants.basic.Server` is then
created and told to use the :class:`Echo` class for new connections. The
server is told to start listening for connections on port 4040 and the
:obj:`~pants.engine.Engine` is started.

When a new connection is made to the server on port 4040, an instance of
the :class:`Echo` class will be created to wrap that connection. When
data arrives on the connection it will be read automatically and passed
to the :meth:`~pants.basic.Connection.on_read` method, which will then pass it
to the :meth:`~pants.basic.Connection.write` method, causing the data to be
sent back to the end user.

You can try this out yourself - run this script in a terminal window and,
in another window, use the ``telnet localhost 4040`` command to connect to
the server. Anything you type into the window will be sent back to your
client and echoed in your terminal.
