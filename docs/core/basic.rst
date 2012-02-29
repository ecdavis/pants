``pants.basic``
***************

.. automodule:: pants.basic


``Client``
==========

.. autoclass:: Client
    :members: connect, close, end, write, write_file, on_read, on_write, on_connect, on_connect_error, on_close


``Connection``
==============

.. autoclass:: Connection
    :members: close, end, write, write_file, on_read, on_write, on_connect, on_close


``Server``
==========

.. autoclass:: Server
    :members: listen, close, on_listen, on_accept, on_close
