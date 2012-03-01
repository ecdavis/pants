Web
***


Hello, World!
=============

An HTTP server running a web application that will display a very simple
Hello World to any connecting clients::

    from pants.http import HTTPServer
    from pants.web import Application
    from pants import engine

    app = Application()

    @app.route("/")
    def hello_world():
        return "Hello, World!"

    HTTPServer(app).listen()
    engine.start()

It's often more convenient to just use the
:meth:`~pants.web.Application.run` method::

    from pants.web import *

    app = Application()

    @app.route("/")
    def hello_world():
        return "Hello, World!"

    app.run()


Go Away, World!
===============

HTTP errors are easy with Application. For example, an HTTP ``404 Not Found``
response::

    from pants.web import *

    app = Application()

    @app.route("/")
    def go_away():
        return "Go Away, World!", 404

    app.run()


Hello, `JSON <http://en.wikipedia.org/wiki/JSON>`_!
===================================================

The Application framework makes it easy to send JSON documents to clients by
simply returning a dictionary as the response body::

    from pants.web import *

    app = Application()

    @app.route("/")
    def hello_json():
        return {"hello": "world"}

    app.run()


Static Files
============

The :class:`~pants.web.FileServer` class provides an easy way to serve static
files to clients, with support for headers that allow for intelligent
caching and support for the ``sendfile`` system call where available.

.. code-block:: python

    from pants.web import *

    app = Application()

    FileServer('/path/to/files').attach(app)

    app.run()

FileServer instances can also be used as request handlers directly with 
:class:`~pants.http.HTTPServer`.
