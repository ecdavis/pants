``pants.web.application``
*************************

.. automodule:: pants.web.application


Route Variable Converters
=========================

.. autoclass:: Converter
    :members: configure, convert

    .. attribute:: default

        A string provided with the variable declaration to be used as a default
        value if no value is provided by the client.

        This is never used externally, and may be modified as appropriate.

    .. attribute:: namegen

        A Converter's ``namegen`` string is used when building a URI with
        :func:`url_for`.

        See :ref:`python:string-formatting` for fun.



Applications
============

.. autoclass:: Application
    :members: run, basic_route, route

.. autoclass:: Module
    :members: basic_route, route


Helper Functions
================

.. autofunction:: abort

.. autofunction:: all_or_404

.. autofunction:: error

.. autofunction:: redirect

.. autofunction:: url_for


Exceptions
==========

.. autoclass:: HTTPException

.. autoclass:: HTTPTransparentRedirect
