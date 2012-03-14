WSGI
****


Hello, World!
=============

An HTTP server running a WSGI application that will display a very simple
Hello World to any connecting clients::

    from pants.http import HTTPServer
    from pants.web import WSGIConnector
    from pants import engine

    def application(environ, start_response):
        status = '200 OK'
        output = 'Hello, World!'

        response_headers = [('Content-type', 'text/plain'),
                            ('Content-Length', str(len(output)))]
        start_response(status, response_headers)
        return [output]

    HTTPServer(WSGIConnector(application)).listen()
    engine.start()
