``pants.http.server``
*********************

.. automodule:: pants.http.server


``HTTPServer``
==============

.. autoclass:: HTTPServer
   :members: listen

   .. method:: startSSL(ssl_options={})

        Enable SSL on the server, creating an ``HTTPS`` server.

        When an HTTP server has been secured, the ``scheme`` of all
        :class:`HTTPRequest` instances is set to ``https``, otherwise it will
        be ``http``. Please note that the ``X-Forwarded-Proto`` may override
        ``scheme`` if ``xheaders`` is set to ``True``.

        .. seealso::

            See :func:`pants.server.Server.startSSL` for more information on
            how SSL is implemented within Pants.


``HTTPConnection``
==================

.. autoclass:: HTTPConnection
   :members: finish

   .. attribute:: current_request

        An instance of :class:`HTTPRequest` representing the active request
        on the connection. If there is no active request, this will be ``None``.


``HTTPRequest``
===============

.. autoclass:: HTTPRequest
   :members: cookies, cookies_out, full_url, is_secure, time, get_secure_cookie, set_secure_cookie, send_response, send_status, send_headers, send_cookies, send_file, send, finish

   .. attribute:: remote_ip

        The IP address of the client, represented as :class:`bytes`. If the
        underlying :class:`HTTPServer` is set to use ``xheaders``, this value
        may be loaded from the ``X-Real-Ip`` or ``X-Forwarded-For`` headers.

   .. attribute:: scheme

        The scheme through which the request was received. This will typically
        be ``http``. The scheme will be set to ``https`` when the connection
        the request was received across is secured. If the underlying
        :class:`HTTPServer` is set to use ``xheaders``, this value may be
        loaded from the ``X-Forwarded-Proto`` header.

   .. attribute:: protocol

        The protocol the request was received across. This is typically either
        ``HTTP/1.1`` or ``HTTP/1.0``.

   .. attribute:: method

        The HTTP request method, such as ``GET`` or ``POST``.

   .. attribute:: url

        The URL that has been requested.

   .. attribute:: path

        The path segment of the :attr:`url`. Note that Pants does not separate
        the path and parameters segments automatically to save time on each
        request as the parameters segment is not often utilized.

   .. attribute:: query

        The query segment of the :attr:`url`.

   .. attribute:: fragment

        The fragment segment of the :attr:`url`.

   .. attribute:: headers

        An instance of :class:`pants.http.utils.HTTPHeaders` containing the
        headers that were received with the request. HTTPHeaders is effectively
        a case-insensitive dictionary that normalizes header cases
        upon iteration.

   .. attribute:: host

        The host that the request was directed to. This is, effectively,
        the value of the request's ``Host`` header. If no such header exists,
        the value will be set to the bytes ``127.0.0.1``.

        Unlike the :attr:`hostname`, this value may contain a port number if
        the request was sent to a non-standard port.

   .. attribute:: hostname

        The hostname segment of the :attr:`host`. This value will always be
        lower-case.

   .. attribute:: get

        A dictionary of HTTP GET variables. The variables are parsed from the
        :attr:`query` using :func:`urlparse.parse_qsl` with
        ``keep_blank_values`` set to ``False``.

   .. attribute:: post

        A dictionary of HTTP POST variables. For security, this variable is
        *only* populated if the :attr:`method` is ``POST`` or ``PUT``.

        If the request's ``Content-Type`` header is set to
        ``application/x-www-form-urlencoded``, the variables will be parsed
        from the :attr:`body` using :func:`urlparse.parse_sql` with
        ``keep_blank_values`` set to ``False``.

        If the request's ``Content-Type`` header is set to
        ``multipart/form-data``, the :attr:`body` will be processed for both
        POST variables and :attr:`files`.

   .. attribute:: files

        A dictionary containing files received within the request body. For
        security, this variable is *only* populated if the :attr:`method` is
        ``POST`` or ``PUT``. At this time, Pants only knows how to receive
        files when the request body is formatted as ``multipart/form-data``.

        The form data variable names will be used for the dictionary keys. Each
        key will contain a list with one or more dictionaries representing the
        received files. A file's dictionary has the keys: ``filename``,
        ``body``, and ``content_type``.

        You might receive a file using::

            def my_handler(request):
                contents = request.files['my_field'][0]['body']

        .. note::

            Pants does a poor job of handling files at this time, keeping them
            entirely in memory while a request is being handled. It is
            recommended to use a proxy server with some way to receive files
            when writing applications.

            In the future, the Pants HTTP server will be modified so that
            large request bodies and received files are stored to disk as
            temporary files as they're received to reduce memory utilization.

   .. attribute:: body

        A :class:`bytes` instance containing the entire request body that has
        not been processed in any way.

   .. attribute:: connection

        The underlying :class:`HTTPConnection` instance that received
        this request. You shouldn't have need to use this in most situations.

