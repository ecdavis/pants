HTTP
****


Server
======


Hello, World!
-------------

An HTTP server that will display a very simple Hello World to any connecting
clients::

    from pants.http import HTTPServer
    from pants import engine

    def on_request(request):
        response = ''.join([
            '<!DOCTYPE html>',
            '<title>Hello, World!</title>',
            '<h1>Hello, World!</h1>',
            '<p>Your request was for <code>%s</code>.</p>' % request.uri
        ])

        request.send_status(200)
        request.send_headers({
            'Content-Type': 'text/html',
            'Content-Length': len(response)
            })
        request.send(response)
        request.finish()

    server = HTTPServer(on_request)
    server.listen(80)

    engine.start()


Client
======


Basic ``GET``
-------------

An HTTP client that will fetch and display a URL, and then exit::

    import sys

    from pants.http import HTTPClient
    from pants import engine

    def on_response(response):
        sys.stdout.write(response.content)
        engine.stop()

    def on_error(response, exception):
        sys.stderr.write(exception)
        engine.stop()

    client = HTTPClient()
    client.get("http://httpbin.org/ip")
    engine.start()
