Using the HTTP Client
*********************

Pants includes a powerful, asynchronous
`HTTP <http://en.wikipedia.org/wiki/HTTP>`_ client with support for keep-alive,
SSL verification, sessions, cookie persistence, basic authentication,
automatic decompression, file uploads, and timeouts. It intelligently reads
large responses in chunks and creates progress events to keep user interfaces
updated and memory usage low. File uploads even use sendfile when supported by
the operating system.

The Basic ``GET`` Request Example
=================================

Making a request is simple. Let's start by fetching Google's homepage. Assume
that you've already made a function called ``response_handler`` earlier, and
that you've imported :class:`~pants.http.client.HTTPClient`. Let's assume the
Pants :doc:`engine <using_the_engine>` is already running as well to keep
things as simple as possible::

    client = HTTPClient(response_handler)
    client.get("http://www.google.com/")
    engine.start()

It's not as easy as `requests <www.python-requests.org>`_, admittedly, but
that's a small price to pay for a completely asynchronous HTTP client. Now, the
response.

The Basic Response Handler
==========================

In our previous example, we relied on a function called ``response_handler`` to
handle the response to our request for Google's homepage. That function goes
something like this::

    def response_handler(response):
        if response.status_code != 200:
            # It's not a valid response, so freak out or something.
            raise Exception("We didn't get our page!")

        # We *did* get our page if we're here.
        print response.headers
        print response.content

The ``response`` is an instance of :class:`~pants.http.client.HTTPResponse`
with the response body, and all the associated headers and cookies.

Cookies, and Headers, and Authentication! Oh, my!
=================================================

So, you want something a bit more from your HTTP client? That's when the
:class:`~pants.http.client.Session` come into play. A Session lets you set
a specific timeout period, the maximum number of times a request can be
redirected, whether or not persistent connections should be used, authorization
credentials, shared headers, cookies, and SSL options. Those values are used
for all the requests made in a session, and cookies are shared between all the
requests in a session as well. For example::

    with client.session(headers={"X-Pizza": "Pepperoni"}):
        client.get("http://httpbin.org/headers")

That's a very basic session that'll send a ``X-Pizza`` header along with its
single request. For something a bit more involved::

    with client.session():
        client.get("http://httpbin.org/cookies/set/pizza/pepperoni")
        client.get("http://httpbin.org/cookies")
    client.get("http://httpbin.org/cookies")

The first request will result in a cookie named ``"pizza"`` being set to the
string ``"pepperoni"``, and that cookie will be sent with the second request
and listed in the result for that request.

However, it won't be in the third request which was made outside of
that session. Authentication works the same way as cookies and headers::

    with client.session(auth=("myname", "password")):
        client.get("http://httpbin.org/basic-auth/myname/password")

``auth`` should be either a tuple of ``(username, password)``, or an instance
of :class:`pants.http.auth.AuthBase`. If auth is a tuple, it will not be sent
automatically. Instead, the client will wait for a ``401 Unauthorized``
response and, after checking to see whether Basic or Digest authentication is
required, it will use the appropriate authentication type. AuthBase instances
will be used immediately.

.. warning::

    Only Basic authentication is supported at this time. Digest authentication
    will be supported in a future version.

``POST`` Something
==================

The HTTP client supports form data and file uploads. While it *technically*
supports these for all request methods, they're most generally used with the
``POST`` method. Here's a simple example::

    client.post("http://httpbin.org/post", {
        "field1": "some value",
        "field2": "something else"
        })

That will send your provided variables in the request body, formatted as
``application/x-www-form-urlencoded`` data. You may also send form data as
``multipart/form-data`` by setting the ``Content-Type`` header to
``multipart/form-data`` manually.

.. note::

    When there are files to upload, ``multipart/form-data`` will be used
    automatically and trying to set ``Content-Type`` to anything else will result
    in an error.

Now, an example on how to upload files::

    client.post("http://httpbin.org/post", files={
        "file_field": ("filename.py", open("/path/to/first/file")),
        "other_file": open("/path/to/second/file"),
        })

When specifying files, you may provide either a tuple of ``(filename, file)``,
or simply a file. If you don't provide a filename, the client will guess the
filename, or failing that, use the field name.

Progress!
=========

The HTTP client reads response bodies in chunks of, at most,
``pants.http.client.CHUNK_SIZE`` bytes. By default, ``CHUNK_SIZE`` is set to
``65536``.

Whenever a chunk has been read successfully, the ``on_progress`` method is
called with the ``response``, the ``received`` bytes, and the ``total`` size of
the response. If the total size isn't known, ``total`` will be ``0``. And now,
and example progress handler::

    def handle_progress(response, received, total):
        if total:
            percent = "%0.2f%% " % ((float(received)/total)*100)
        else:
            percent = ""
        print "%s(%d of %d) of %r received." % (percent, received, total,
                                                response)

    with client.session(on_progress=handle_progress):
        client.get("http://www.example.com/some/large/file")

Problems
========

Errors aren't as simple as raising an exception in an asynchronous framework,
unfortunately, so the HTTP client has two separate methods for handling errors.
The first method is named ``on_ssl_error`` and it's raised when verification of
the remote server's SSL certificate has failed. Returning ``True`` from the
method will override the exception and allow the connection to continue.
An example::

    def handle_ssl_error(response, certificate, exception):
        if response.url.hostname == 'mysite.com':
            return True

    with client.session(on_ssl_error=handle_ssl_error):
        client.get("https://somepage.com")
        client.get("https://mysite.com")

That will exempt requests to ``mysite.com`` from SSL verification, effectively.
``certificate`` is a dictionary, as returned by
:func:`ssl.SSLSocket.getpeercert`, and ``exception`` is an Exception instance
describing the exact problem. The exception will be an instance of
:class:`~pants.http.client.CertificateError` if the certificate doesn't match
the hostname of the request.

All other exceptions, including a timeout, pass to the simpler ``on_error``
method. Example::

    def handle_error(response, exception):
        print exception

    with client.session(on_error=handle_error):
        client.get("http://nonexistantdomain.nowhere/")

At a minimum, you should implement a response handler and an error handler when
creating an HTTP client.
