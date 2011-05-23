Network
*******

API
===

.. autoclass:: pants.network.Client
    :members: connect, write, close, end, on_read, on_write, on_connect, on_close

.. autoclass:: pants.network.Connection
    :members: write, close, end, on_read, on_write, on_connect, on_close

.. autoclass:: pants.network.Server
    :members: ConnectionClass, listen, close, end, on_accept, on_close
