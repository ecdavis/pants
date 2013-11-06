``pants.http.websocket``
************************

.. automodule:: pants.http.websocket

``WebSocket``
=============

.. autoclass:: WebSocket
    :members: write, write_file, write_packed, ping, close, read_delimiter, buffer_size, remote_address, local_address, on_handshake, on_connect, on_pong, on_read, on_write, on_close, on_overflow_error

    .. attribute:: is_secure

        Whether or not the underlying HTTP connection is secured.

    .. attribute:: allow_old_handshake

        Whether or not to allow clients using the old
        `draft-76 <http://tools.ietf.org/html/draft-hixie-thewebsocketprotocol-76>`_
        protocol to connect. By default, this is set to False.

        Due to the primitive design of the draft-76 version of the WebSocket
        protocol, there is significantly reduced functionality when it is
        being used.

            1.  Binary data cannot be transmitted. All communications between
                the :class:`WebSocket` instance and the remote end-point must
                take place using unicode strings.

            2.  Connections are closed immediately with no concept of close
                reasons. When you use :meth:`close` on a draft-76 WebSocket,
                it will flush the buffer and then, once the buffer empties,
                close the connection immediately.

            3.  There are no control frames, such as the PING frames created
                when you invoke :meth:`ping`.

        There are other missing features as well, such as extensions and the
        ability to fragment long messages, but Pants does not currently
        provide support for those features at this time.


``EntireMessage``
=================

.. attribute:: EntireMessage

    ``EntireMessage`` is a unique Python object that, when set as the
    :attr:`~WebSocket.read_delimiter` for a :class:`WebSocket` instance, will
    cause entire messages to be passed to the :meth:`~WebSocket.on_read` event
    handler at once.
