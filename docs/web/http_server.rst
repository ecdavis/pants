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
   :members: cookies, cookies_out, full_url, time, get_secure_cookie, set_secure_cookie, send_status, send_headers, send_cookies, send_file, send, finish
