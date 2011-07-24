Datagram
********

The :class:`~pants.datagram.Datagram` class wraps `datagram sockets 
<http://en.wikipedia.org/wiki/Datagram_Sockets>`_. It implements the
:class:`~pants.channel.Channel` interface.

Packets
=======

:class:`~pants.datagram.Datagram` objects are connectionless, meaning
that they can send and receive packets to and from any remote socket.

The :meth:`~pants.datagram.Datagram.write` method is used to write data
to remote sockets. When writing data to a :class:`~pants.datagram.Datagram`
object, the remote address must be specified. If it is not specified, the
:class:`~pants.datagram.Datagram` will attempt to send the packet to the
address that was used most recently.

The :meth:`~pants.datagram.Datagram.listen` method is used to begin
listening for packets from remote sockets. While a
:class:`~pants.datagram.Datagram` object is listening for packets it
cannot send any.

API
===

.. autofunction:: pants.datagram.sendto

.. autoclass:: pants.datagram.Datagram
    :members: listen, close, end, write, on_read, on_write, on_close
