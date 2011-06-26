Channel
*******

The :class:`~pants.channel.Channel` class is Pants' non-blocking
:obj:`~socket.socket` wrapper. It can be used to create new
:obj:`~socket.socket` objects or to wrap existing ones.
:class:`~pants.channel.Channel` wraps most :mod:`socket` methods,
handling common errors and sanitising return values. It is tightly
integrated with the :obj:`~pants.engine.Engine` and ensures that all
:class:`~pants.channel.Channel` objects are added to and removed from the
:obj:`~pants.engine.Engine` when required.

Subclassing
===========

:class:`~pants.channel.Channel` defines a basic interface (see
:ref:`below <API>`) that should be adhered to - where applicable - by its
subclasses. It is unlikely that you will ever need to subclass
:class:`~pants.channel.Channel` directly. Instead, use one of its two main
subclasses: :class:`~pants.stream.Stream` or :class:`~pants.datagram.Datagram`.

Using Channels
==============

The purpose of the :class:`~pants.channel.Channel` class is to provide a
common interface that allows all channels to be used in a similar way.
In order to understand how to properly use a channel, you should not only
be familiar with the API, but with the use of callbacks and the read
delimiter.

There are also a number of :ref:`examples` of how to use channels in
various ways.

Callbacks
---------

A callback is a method which is invoked when a particular event occurs on
the channel. The :class:`~pants.channel.Channel` defines five callbacks:
:meth:`~pants.channel.Channel.on_read`, :meth:`~pants.channel.Channel.on_write`,
:meth:`~pants.channel.Channel.on_connect`, :meth:`~pants.channel.Channel.on_accept`
and :meth:`~pants.channel.Channel.on_close`. Subclasses should invoke these
methods when the relevant event occurs (which may be never, in some cases).
When using a :class:`~pants.channel.Channel` subclass, you should assume
that these callbacks will be invoked when appropriate.

Callback methods can be replaced at runtime, which makes it exceedingly
simple to change channel behaviour based on state.

Read Delimiter
--------------

The :class:`~pants.channel.Channel` interface requires subclasses to
implement a :attr:`read_delimiter` attribute that is used to control the
way in which data is read from the channel. The read delimiter can be set
at runtime to either :obj:`None` (the default), a string, or an integer.
Once the read delimiter has been set, the channel will continue to read
data in the specified manner until the value of the read delimiter is
changed.

When the value is :obj:`None`, data will not be buffered internally, and
will be passed to :meth:`~pants.channel.Channel.on_read` immediately upon
being read.

When the value is a string, data will be read and buffered internally
until that string is encountered, at which point the data will be passed
to :meth:`~pants.channel.Channel.on_read`.

::

    self.read_delimiter = '\r\n' # Read until a newline is encountered.

When the value is an integer, that number of bytes will be read into the
internal buffer before being passed to :meth:`~pants.channel.Channel.on_read`.

::

    self.read_delimiter = 1024 # Read 1024 bytes.


.. _API:

API
===

.. autoclass:: pants.channel.Channel
    :members: read_delimiter, connect, listen, close, end, write, _handle_read_event, _handle_write_event, on_read, on_write, on_connect, on_accept, on_close
