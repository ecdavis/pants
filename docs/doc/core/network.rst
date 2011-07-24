Network
*******


Server
======

.. autoclass:: pants.network.Server
    :members: ConnectionClass, listen, close, on_accept, on_close

Connection
==========

.. autoclass:: pants.network.Connection
    :members: write, close, end, on_read, on_write, on_connect, on_close

Client
======

.. autoclass:: pants.network.Client
    :members: connect, write, close, end, on_read, on_write, on_connect, on_close
