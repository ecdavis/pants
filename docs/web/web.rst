``pants.contrib.web``
*********************

.. automodule:: pants.contrib.web


Applications
============

.. autoclass:: Application
    :members: run, basic_route, route

.. autoclass:: FileServer
    :members: attach


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
