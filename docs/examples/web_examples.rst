Web
***


Hello, World!
=============

An HTTP server running a web application that will display a very simple
Hello World to any connecting clients::

    from pants.contrib.http import HTTPServer
    from pants.contrib.web import Application
    from pants import engine

    app = Application()

    @app.route('/')
    def hello_world():
        return "Hello, World!"

    HTTPServer(app).listen()
    engine.start()

It's often more convenient to just use the
:meth:`~pants.contrib.web.Application.run` method::

    from pants.contrib.web import *

    app = Application()

    @app.route('/')
    def hello_world():
        return "Hello, World!"

    app.run()
