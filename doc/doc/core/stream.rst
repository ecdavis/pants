Stream
******

The :class:`~pants.stream.Stream` class wraps `steam sockets 
<http://en.wikipedia.org/wiki/Stream_Sockets>`_. It implements the
:class:`~pants.channel.Channel` interface. :class:`~pants.stream.Stream`
can be used directly, however for Internet channels it is recommended
that you make use of the classes provided in the :mod:`pants.network`
module.

Connections
===========

:class:`~pants.stream.Stream` objects are connection-based, meaning that
they need to be connected to a remote socket or listening for incoming
connections before they can be used.

The :meth:`~pants.stream.Stream.connect` method is used to connect to a
remote socket at the given host, listening on the given port. When the
channel has connected, :meth:`~pants.stream.Stream.on_connect` is called.

The :meth:`~pants.stream.Stream.listen` method is used to begin listening
for new connections to the local host on the given address and port. When
a new connection is made, :meth:`~pants.stream.Stream.on_accept` is called.

API
===

.. autoclass:: pants.stream.Stream
    :members: connect, listen, close, end, write, on_read, on_write, on_connect, on_accept, on_close
