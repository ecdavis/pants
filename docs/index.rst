Pants
*****

Pants is a lightweight framework for writing asynchronous network applications
in Python. Pants is simple, fast and elegant.

Pants is available under the
`Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0.html>`_

**An incomplete feature list**:
 * Single-threaded, asynchronous, callback-oriented.
 * TCP networking - clients and servers!
 * IPv4, IPv6 and UNIX socket families.
 * SSL/TLS support for all that security stuff.
 * Basic scheduling and timers.
 * A speedy HTTP server with a handy WebSockets implementation.
 * A simple web framework and support for WSGI.

And it's all so, so easy to use. Check it out:

.. literalinclude:: ../examples/echo.py
	:language: python

Here's a web example for good measure:

.. literalinclude:: ../examples/hello_web.py
	:language: python

And here's how you get Pants::

	pip install pants

Want to get started? There's plenty to do:
 * Fork `ecdavis/pants <https://github.com/ecdavis/pants>`_ on GitHub.
 * Join the IRC channel, `#pantspowered <http://webchat.freenode.net/?channels=pantspowered>`_ on Freenode.
 * Read this documentation!

Documentation
=============

.. toctree::
    :maxdepth: 2

    user_guide
    core/index
    web/index
    contrib/index

