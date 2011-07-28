``pants.contrib.http``
**********************

.. automodule:: pants.contrib.http

Server
======

.. autoclass:: HTTPServer
   :members: listen

.. autoclass:: HTTPConnection
   :members: finish

.. autoclass:: HTTPRequest
   :members: cookies, full_url, time, get_secure_cookie, set_secure_cookie, send, send_status, send_headers, send_cookies

Client
======

.. autoclass:: HTTPClient
   :members: on_response, get, post, process

.. autoclass:: ClientHelper
   :members: fetch

.. autoclass:: HTTPResponse
   :members: cookies, full_url

Functions
=========

.. autofunction:: encode_multipart

.. autofunction:: parse_multipart

.. autofunction:: read_headers
