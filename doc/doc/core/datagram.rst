Datagram
********

The :class:`~pants.datagram.Datagram` class wraps `datagram sockets 
<http://en.wikipedia.org/wiki/Datagram_Sockets>`_. It implements the
:class:`~pants.channel.Channel` interface.

API
===

.. autofunction:: pants.datagram.sendto

.. autoclass:: pants.datagram.Datagram
    :members: listen, close, end, write, on_read, on_write, on_close
