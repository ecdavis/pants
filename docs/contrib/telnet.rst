``pants.contrib.telnet``
************************

.. automodule:: pants.contrib.telnet


Constants
=========

:Telnet Commands:
    =========   ======
    Constant    Value
    =========   ======
    IAC         ``'\xFF'``
    DONT        ``'\xFE'``
    DO          ``'\xFD'``
    WONT        ``'\xFC'``
    WILL        ``'\xFB'``
    SB          ``'\xFA'``
    SE          ``'\xF0'``
    =========   ======


TelnetConnection
================

.. autoclass:: TelnetConnection
    :members: close, end, write, write_file, on_command, on_option, on_subnegotiation, on_read, on_write, on_connect, on_close

TelnetServer
============

.. autoclass:: TelnetServer
