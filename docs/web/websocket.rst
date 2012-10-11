``pants.http.websocket``
************************

.. automodule:: pants.http.websocket


Constants
=========

:``CLOSE_REASONS`` Dictionary:
    =====  ======
    Key    Value
    =====  ======
    1000   ``'Normal Closure'``
    1001   ``'Server Going Away'``
    1002   ``'Protocol Error'``
    1003   ``'Unacceptable Data Type'``
    1004   ``'Frame Too Large'``
    1005   ``'No Status Code'``
    1006   ``'Abnormal Close'``
    1007   ``'Invalid UTF-8 Data'``
    =====  ======

:Frame Opcodes:
    ===================   ======
    Constant              Value
    ===================   ======
    FRAME_CONTINUATION    ``0``
    FRAME_TEXT            ``1``
    FRAME_BINARY          ``2``
    FRAME_CLOSE           ``8``
    FRAME_PING            ``9``
    FRAME_PONG            ``10``
    ===================   ======

:Other Constants:
    ===================   ======
    Constant              Value
    ===================   ======
    WEBSOCKET_KEY         ``'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'``
    ===================   ======


WebSocket
=========

.. autoclass:: WebSocket
    :members: close, end, write, on_read, on_write, on_connect, on_close
