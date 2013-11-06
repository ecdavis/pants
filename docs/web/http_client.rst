``pants.http.client``
*********************

.. automodule:: pants.http.client


Exceptions
==========

.. autoclass:: CertificateError
.. autoclass:: HTTPClientException
.. autoclass:: MalformedResponse
.. autoclass:: RequestClosed
.. autoclass:: RequestTimedOut


HTTPClient
==========

.. autoclass:: HTTPClient
    :members: on_response, on_headers, on_progress, on_ssl_error, on_error, session, request, delete, get, head, options, patch, post, put, trace


HTTPRequest
===========

.. autoclass:: HTTPRequest

    .. attribute:: response

        The :class:`HTTPResponse` instance representing the response to this
        request.

    .. attribute:: session

        The :class:`Session` this request was made in.

    .. attribute:: method

        The HTTP method of this request, such as ``GET``, ``POST``, or
        ``HEAD``.

    .. attribute:: path

        The path of this request.

    .. attribute:: url

        A tuple containing the full URL of the request, as processed by
        :func:`urlparse.urlparse`.

    .. attribute:: headers

        A dictionary of headers sent with this request.

    .. attribute:: cookies

        A :class:`Cookie.SimpleCookie` instance of cookies sent with this
        request.

    .. attribute:: body

        A list of strings and files sent as this request's body.

    .. attribute:: timeout

        The time to wait, in seconds, of no activity to allow before timing out.

    .. attribute:: max_redirects

        The maximum remaining number of redirects before not automatically
        redirecting.

    .. attribute:: keep_alive

        Whether or not the connection should be reused after this request.

    .. attribute:: auth

        Either a tuple of ``(username, password)`` or an instance of
        :class:`AuthBase` responsible for authorizing this request with the
        server.


HTTPResponse
============

.. autoclass:: HTTPResponse
    :members: status, encoding, text, json, content, iter_content, iter_lines, file, handle_301, handle_401

    .. attribute:: length

        The length of the raw response.

    .. attribute:: http_version

        The HTTP version of the response.

    .. attribute:: status_code

        The HTTP status code of the response, such as ``200``.

    .. attribute:: status_text

        The human readable status text explaining the status code, such as
        ``Not Found``.

    .. attribute:: cookies

        A :class:`Cookie.SimpleCookie` instance of all the cookies received
        with the response.

    .. attribute:: headers

        A dictionary of all the headers received with the response.


Session
=======

.. autoclass:: Session
    :members: session, request, delete, get, head, options, patch, post, put, trace

    .. attribute:: client

        The :class:`HTTPClient` this Session is associated with.
