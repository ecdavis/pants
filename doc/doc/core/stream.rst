Stream
******

The :class:`~pants.stream.Stream` class wraps `steam sockets 
<http://en.wikipedia.org/wiki/Stream_Sockets>`_. It implements the
:class:`~pants.channel.Channel` interface. :class:`~pants.stream.Stream`
can be used directly, however for Internet channels it is recommended
that you make use of the classes provided in the :mod:`pants.network`
module.

API
===

.. autoclass:: pants.stream.Stream
    :members: connect, listen, close, end, write, on_read, on_write, on_connect, on_accept, on_close
