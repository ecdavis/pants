Channel
*******

The :obj:`pants.channel.Channel` class is Pants' main non-blocking socket
wrapper. It provides basic functionality and defines a simple interface
which is adhered to by its higher-level subclasses
:obj:`pants.stream.Stream` and :obj:`pants.datagram.Datagram`.

API
===

.. autoclass:: pants.channel.Channel
    :members: closed, connect, listen, close, end, write, _handle_read_event, _handle_write_event
