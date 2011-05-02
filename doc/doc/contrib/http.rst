HTTP
****

Server
======

``pants.contrib.http`` provides an acceptably fast, non-blocking implementation
of an `HTTP <http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol>`_
server, built on top of Pants.

Features
--------

* HTTP/1.1 with Keep Alive
* Portability (Tested on Linux 2.6, OS X, and Windows XP/7)
* TLS and SSL
* Support for request bodies using ``application/x-www-form-urlencoded`` and
  ``multipart/form-data``.

Hello World
-----------

It's easy to implement a basic Hello World application, even with just the raw
HTTP server::

    from pants.contrib.http import HTTPServer
    from pants import engine
    
    def request_handler(request):
        request.send(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 13\r\n"
            "\r\n"
            "Hello, World!"
            )
        request.finish()
    
    HTTPServer(request_handler).listen(80)
    engine.start()

Not Features
------------

The HTTP server does *not* supply template functionality, string localization,
or user authentication.

This basic HTTP server also does not supply request routing functionality.
However, that is available from :class:`pants.contrib.web.Application`.

Client
======

``pants.contrib.http`` also provides a non-blocking implementation of an HTTP
client.

Features
--------

* HTTP/1.1 with Keep Alive
* Automatic Unicode Decoding
* Support for 301 and 302 HTTP Redirects
* Support for ``gzip`` and ``deflate`` Content-Encoding
* Support for ``chunked`` Transfer-Encoding

The HTTP client is still a work in progress, and is expected to in the future
support WWW authentication, cookies that persist between requests, and more.

Hello World
-----------

The following example requests ``http://www.google.com/`` and prints it out::

    from pants.contrib.http import HTTPClient
    
    def response_handler(response):
        print response.body
    
    client = HTTPClient(response_handler)
    client.get('http://www.google.com')
    client.process()

API
===

Server
------

.. automodule:: pants.contrib.http
   :members: HTTPServer, HTTPConnection, HTTPRequest

Client
------

.. automodule:: pants.contrib.http
   :members: HTTPClient, ClientHelper, HTTPResponse

Functions
---------

.. automodule:: pants.contrib.http
   :members: encode_multipart, parse_multipart, read_headers
