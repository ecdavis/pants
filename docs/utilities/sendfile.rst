``pants.util.sendfile``
***********************

.. automodule:: pants.util.sendfile


Sendfile
========

.. py:function:: sendfile(sfile, channel, offset, nbytes)
    
    Provides access to or implements the ``sendfile()`` system call in
    Python.
    
    This function is replaced at runtime by one of the implementations
    listed below.

    =========  ============
    Argument   Description
    =========  ============
    sfile      The file to send.
    channel    The channel to write to.
    offset     The number of bytes to offset writing by.
    nbytes     The number of bytes of the file to write. If 0, all bytes will be written.
    =========  ============


Implementations
===============

.. autofunction:: sendfile_fallback

.. autofunction:: sendfile_linux

.. autofunction:: sendfile_darwin

.. autofunction:: sendfile_bsd
