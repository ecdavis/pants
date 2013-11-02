``pants.http.websocket``
************************

.. automodule:: pants.http.websocket

``WebSocket``
=============

.. autoclass:: WebSocket
    :members: write, write_file, write_packed, ping, close, read_delimiter, buffer_size, remote_address, local_address, on_handshake, on_connect, on_pong, on_read, on_write, on_close, on_overflow_error

    .. attribute:: is_secure

        Whether or not the underlying HTTP connection is secured.

``EntireMessage``
=================

.. attribute:: EntireMessage

    ``EntireMessage`` is a unique Python object that, when set as the
    :attr:`~WebSocket.read_delimiter` for a :class:`WebSocket` instance, will
    cause entire messages to be passed to the :meth:`~WebSocket.on_read` event
    handler at once.
