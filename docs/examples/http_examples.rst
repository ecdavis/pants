HTTP
****


Hello, World!
=============

An HTTP server that will display a very simple Hello World to any connecting
clients::

    from pants.contrib.http import HTTPServer
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
