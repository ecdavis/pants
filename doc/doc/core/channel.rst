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

.. _API:

API
===

.. autoclass:: pants.channel.Channel
    :members: closed, connect, listen, close, end, write, _handle_read_event, _handle_write_event
