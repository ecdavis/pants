``pants.web.application``
*************************

.. automodule:: pants.web.application


Helper Functions
================

.. autofunction:: abort

.. autofunction:: all_or_404

.. autofunction:: error

.. autofunction:: redirect

.. autofunction:: register_converter

.. autofunction:: url_for


``Application``
===============

.. autoclass:: Application
    :members: run


``Module``
==========

.. autoclass:: Module
    :members: add, basic_route, route, request_started, request_finished, request_teardown


``Converter``
=============

.. autoclass:: Converter
    :members: configure, decode, encode

    .. attribute:: default

        A string provided with the variable declaration to be used as a default
        value if no value is provided by the client.

        This value will also be placed in urls generated via the method
        :func:`~pants.web.application.url_for` if no other value is provided.


Exceptions
==========

.. autoclass:: HTTPException

.. autoclass:: HTTPTransparentRedirect
