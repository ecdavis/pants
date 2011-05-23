Network
*******

API
===

.. autoclass:: pants.network.Client
    :members: on_read, on_write, on_connect, on_close

.. autoclass:: pants.network.Connection
    :members: on_read, on_write, on_connect, on_close

.. autoclass:: pants.network.Server
    :members: ConnectionClass, on_accept, on_close
