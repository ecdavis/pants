User Guide
**********

Pants is a network programming framework for Python. It is simple, fast and
elegant. Pants provides the programmer with the basic tools they need to write
responsive, high-throughput and highly-concurrent network applications. At its
core, Pants consists of three things:

 * **Engines**: efficient, asynchronous event loops.
 * **Channels**: non-blocking wrappers around socket objects.
 * **Timers**: non-blocking helpers for delayed execution of code.

Overview
========
All Pants applications share a similar architecture. Channels and timers are
added to an engine. The engine runs an event loop and manages timer scheduling.
As events are raised on sockets, the engine dispatches those events (read,
write, close, etc.) to the relevant channel to be handled by user code. Timers
are executed and possibly rescheduled by the engine as they expire. Writing a
Pants application consists of defining your event-handling logic on custom
channel classes, scheduling timers to be executed and starting the event loop.
Pants makes writing efficient network applications simple through the use of
elegant abstractions.

Pants is an asynchronous, callback-oriented framework. Being asynchronous, it
is important that your code does not block the main process. Blocking code
prevents Pants from efficiently polling for socket events, and has a
significant, negative effect on performance. To eliminate the need for blocking
code, Pants uses a callback-oriented design. Blocking operations like reading
and writing data to a socket are performed in the background. When these
operations complete, callback methods are invoked to notify user code. To get
a better example of how Pants applications work, take a look at a few
`examples <http://github.com/ecdavis/pants/tree/master/examples/>`_ or
read through the :ref:`tutorial <tutorial>`.

Getting Started
===============
Getting started with Pants is easy. Pants can be installed either from the
`Python Package Index <http://pypi.python.org/pypi/pants>`_ or from source.
Pants requires `Python <http://python.org/>`_ version 2.6 or 2.7.

You can install Pants using your favourite Python package manager::

	pip install pants

Or from source::

	wget https://github.com/ecdavis/pants/tarball/pants-1.0.0-beta.3
	tar xvfz pants-1.0.0-beta.3.tar.gz
	cd pants-1.0.0-beta.3
	python setup.py install

Using the development version
-----------------------------
Using the development version of Pants will give you access to the latest
features as well as the latest bugs. If you're interested in contributing code
to Pants, this is the version you should work with. Otherwise, it's suggested
that you stick to a release version. You can clone the repository like so::

	git clone git://github.com/ecdavis/pants

Many people also find it useful to add their repository directory to Python's
path, or to create a symbolic link from the repository directory to Python's
site-packages directory to allow them to import Pants in any Python script.

.. _tutorial:

Tutorial
========
What follows is a simple tutorial designed to introduce you to the core parts
of Pants' API and demonstrate how to write simple Pants applications. This
tutorial is by no means an exhaustive tour of Pants' many features, but should
serve as an excellent starting point for someone new to the framework or to
asynchronous network programming in general.

Writing a simple server
-----------------------
We're going to begin by writing an echo server. This is like the "Hello, World!"
of networking frameworks, but it's nonetheless a good place to start. Create a
file containing the following code:

.. literalinclude:: ../examples/tutorial1.py
    :language: python

Now run it and, in another terminal, connect to the server using telnet::

	telnet localhost 4040

Try entering some data and you'll find that it gets echoed right back to you.
To get a better idea of what's happening in this application, we'll run through
the code line by line:

.. literalinclude:: ../examples/tutorial1.py
	:language: python
	:lines: 3-5

We begin by defining a class, ``Echo``, which subclasses Pants'
:class:`~pants.stream.Stream` class. Instances of :class:`~pants.stream.Stream`
and its subclasses are what Pants calls 'channels.' They represent connections
from the local host to a remote host or vice-versa. Channels are basically just
wrappers around :py:obj:`~socket.socket` objects that deal with all the
nitty-gritty, low-level stuff so that you don't have to. You implement most of
your application's logic by defining callback methods on your channel classes.
``on_read`` is one such method. As the name suggests, ``on_read`` will get
called any time data is read from the channel. The incoming data is passed to
the callback for use by your application. In this case, we've chosen to
immediately write it back to the channel, thereby implementing the echo
protocol.

Having defined our application logic, we now need to get the server up and
running:

.. literalinclude:: ../examples/tutorial1.py
	:language: python
	:lines: 7-9

We create a new instance of Pants' :class:`~pants.server.Server` class and pass
it our :class:`~pants.stream.Stream` subclass, ``Echo``.
:class:`~pants.server.Server` instances are channels which represent sockets
that are listening for new connections to the local host. When a new connection
is made, the :class:`~pants.server.Server` will automatically wrap that
connection with an instance of its ``ConnectionClass``. In this case, new
connections will be wrapped with instances of our ``Echo`` class.

After creating the server, we tell it to listen for new connections on port
4040 and then we start the global engine. All Pants applications have an
engine at their core - it's responsible for running a powerful event loop that
listens for new events on sockets and dispatches those events to the
appropriate channels.

We've only written 7 lines of code, but we've already covered a great deal of
Pants' core functionality. Before moving on, try messing around with the code a
little bit and see what happens:

 * Delete the ``ConnectionClass`` parameter in the :class:`~pants.server.Server` constructor.
 * Comment out the :meth:`~pants.server.Server.listen` call.
 * Comment out the :meth:`~pants.engine.Engine.start` call.

Kicking it up a notch
---------------------
Now that we've covered the basics we can move on to something a little more
interesting.

.. literalinclude:: ../examples/tutorial2.py
	:language: python

The ``on_read`` method is basically the same as before, we've just added a
newline to the end of the data before writing it. We've also added a new event
handler method: ``on_connect``. As the name suggests, this gets called when the
channel's connection is first established. In ``on_connect`` we set the value
of the channel's :attr:`~pants.stream.Stream.read_delimiter` attribute, and
this is where things get neat. The :attr:`~pants.stream.Stream.read_delimiter`
changes the way Pants passes data to ``on_read``. Instead of being passed on as
soon as it arrives, data is internally buffered and passed to ``on_read`` in
blocks of 8 bytes. See what happens when you run this application and connect
to it as you did before. It's a simple idea, but the
:attr:`~pants.stream.Stream.read_delimiter` is one of Pants' most powerful
features.

The :attr:`~pants.stream.Stream.read_delimiter` isn't limited to being a number
of bytes, either. Here are some experiments for you to try:

 * Set the :attr:`~pants.stream.Stream.read_delimiter` to a short string.
 * Set the :attr:`~pants.stream.Stream.read_delimiter` to a compiled regex object.
 * Set the :attr:`~pants.stream.Stream.read_delimiter` to ``None``.

Taking it to another level
--------------------------
Up until now we've been using Pants' regular :class:`~pants.server.Server`
class and it's suited our needs perfectly. There are times, however, where you
may need to define custom behaviour on your server channels. This is achieved
by subclassing :class:`~pants.server.Server`:

.. literalinclude:: ../examples/tutorial3.py
	:language: python
	:lines: 14-20

All very straight-forward. We defined a new method on the server that writes
data to all connected channels. We also overrode the default
``ConnectionClass`` attribute, meaning that we'll no longer need to pass in our
connection class to the constructor. Starting the server now looks like this:

.. literalinclude:: ../examples/tutorial3.py
	:language: python
	:lines: 22-23

For the sake of completeness, here's the ``EchoLineToAll`` connection class
used by the above server:

.. literalinclude:: ../examples/tutorial3.py
	:language: python
	:lines: 3-12

As you can see, channels retain a reference to the server that they belong to.
In this case, we're also using the :attr:`~pants.stream.Stream.remote_address`
property as a channel-specific identifier.

That's it for the basic tutorial, but there's plenty more you can do here:

 * Experiment with different :attr:`~pants.stream.Stream.read_delimiter` values
   to change the way connections process data. You might try implementing a
   packet-oriented protocol.
 * Write a client for your server using Pants. You basically know how already,
   just take a look at :meth:`~pants.stream.Stream.connect` and you'll be good
   to go.
 * We can't have people communicating through unencrypted channels like this.
   Secure your chat server using Pants' SSL support. Take a look at
   :meth:`~pants.server.Server.startSSL` to get started.
