Overview
********

The Pants core is an asynchronous, non-blocking network programming
framework designed with speed, simplicity and size in mind. It provides
an asynchronous :obj:`~pants.engine.Engine` to power your application as
well as simple abstractions of :obj:`~socket.socket` objects to make network
programming significantly simpler.

.. toctree::
    

Applications
============

A basic Pants application consists of some number of :ref:`channel <channels>`
and  :ref:`timer <timers>` objects being continuously updated by a single, 
central :ref:`engine <engine>` object. The primary purpose of a Pants
application is to perform I/O on :obj:`~socket.socket` objects, allowing
you to build fast, simple network applications.

Pants is asynchronous, meaning that rather than starting to read or write
data and then doing nothing until that operation is complete, it instead
performs I/O in the background as it becomes possible to do so. This makes
Pants fast and able to handle a large number of concurrent connections.

However, because Pants is asynchronous, it is very important that none of
the code in your application `blocks <http://en.wikipedia.org/wiki/Blocking_(computing)>`_
the process. Any blocking code will cause the entire process to wait until
the blocking operation is complete, preventing any channel objects from being
updated.

To eliminate the need for blocking code, Pants uses a callback-oriented
design. Blocking operations like reading or writing to a
:ref:`channel <channels>` are performed in the background. When these
operations complete, a callback method is invoked to notify the
:ref:`channel <channels>`. Most of the code in a Pants application will hook
into these callbacks to implement functionality.


.. _channels:

Channels
========

Channels in Pants are objects that wrap a non-blocking :obj:`~socket.socket`
and provide a simple, convenient interface with which to interact with that
:obj:`~socket.socket`.

Channels may represent local servers, remote connections to local servers or 
local connections to remote servers. Channels may use either network sockets
or Unix sockets and can be stream-oriented (TCP) or packet-oriented (UDP).

Network Channels
----------------

Unix Channels
-------------

Stream-Oriented Channels
------------------------

Packet-Oriented Channels
------------------------


.. _timers:

Timers
======

Timers are function calls that are delayed until some point in the future.
There are four methods used for scheduling timers:
:meth:`Engine.callback() <pants.engine.Engine.callback>`,
:meth:`Engine.loop() <pants.engine.Engine.loop>`,
:meth:`Engine.defer() <pants.engine.Engine.defer>` and
:meth:`Engine.cycle() <pants.engine.Engine.cycle>`.
These methods all return a callable that can be used to cancel the timer
at any time::

    from pants import engine
    
    cancel_callback = engine.callback(callback)
    cancel_callback()

The timer methods can be passed any number of positional and keyword
arguments, which will then be passed through to the given function when
it is executed.

.. _engine:


Engine
======

The :obj:`~pants.engine.Engine` is the core object of any Pants
application. It keeps track of every active :class:`~pants.channel.Channel`
and continuously checks them for new events, raising them when they occur.
The :obj:`~pants.engine.Engine` also provides timer functionality which
allows functions to be executed after some delay without blocking the
process.

Applications
------------

The :obj:`~pants.engine.Engine` can be used in two different ways. It
can provide the main event loop for your application, or it can be
integrated into an existing event loop (one run by a GUI framework, for
instance).

If you choose to use Pants' event loop, you will need to start the
:obj:`~pants.engine.Engine` with the :meth:`~pants.engine.Engine.start`
method. This will cause the :obj:`~pants.engine.Engine` to call
:meth:`~pants.engine.Engine.poll` continuously until it is stopped
either by an uncaught :exc:`Exception` or the
:meth:`~pants.engine.Engine.stop` method. The :meth:`~pants.engine.Engine.start` method blocks the process until
:meth:`~pants.engine.Engine.stop` is called, so be sure to fully initialise
your application before you call it.

If you want to integrate Pants with an existing event loop, you will need
to call :meth:`~pants.engine.Engine.poll` on each iteration of that loop.
Ideally, :meth:`~pants.engine.Engine.poll` should be called many times
each second to ensure that Pants is as fast as it can be.

Accessing the Engine
--------------------

The :obj:`~pants.engine.Engine` can be accessed in one of two ways, by
importing it directly from the ``pants`` package::

    from pants import engine

Or by using the :meth:`~pants.engine.Engine.instance` classmethod::

    from pants.engine import Engine
    
    Engine.instance()

These two methods are equivalent.


Example: Echo
=============

::

    from pants.network import Connection, engine, Server
    
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
to the :meth:`~pants.network.Connection.on_read` method, which will then pass
it to the :meth:`~pants.network.Connection.write` method, causing the data to 
be sent back to the end user.

You can try this out yourself - run this script in a terminal window and,
in another window, use the ``telnet localhost 4000`` command to connect to
the server. Anything you type into the window will be sent back to your
client and echoed in your terminal.
