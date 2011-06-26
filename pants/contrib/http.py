###############################################################################
#
# Copyright 2011 Pants (see AUTHORS.txt)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################

###############################################################################
# Imports
###############################################################################

import base64
import Cookie
import hashlib
import hmac
import logging
import mimetypes
import os
import pprint
import urllib
import urlparse
import zlib

if os.name == 'nt':
    from time import clock as time
else:
    from time import time

from time import time as curtime

from datetime import datetime
from pants import callback, Connection, Server, __version__ as pants_version
from pants.engine import Engine
from pants.stream import Stream
from pants.contrib.ssl import SSLServer

###############################################################################
# Logging
###############################################################################

log = logging.getLogger('http')

###############################################################################
# Constants
###############################################################################

SERVER      = 'HTTPants (pants/%s)' % pants_version
SERVER_URL  = 'http://www.pantsweb.org/'

USER_AGENT = "HTTPants/%s" % pants_version

COMMA_HEADERS = ('Accept', 'Accept-Charset', 'Accept-Encoding',
    'Accept-Language', 'Accept-Ranges', 'Allow', 'Cache-Control', 'Connection',
    'Content-Encoding', 'Content-Language', 'Expect', 'If-Match',
    'If-None-Match', 'Pragma', 'Proxy-Authenticate', 'TE', 'Trailer',
    'Transfer-Encoding', 'Upgrade', 'Vary', 'Via', 'Warning',
    'WWW-Authenticate')

CRLF = '\r\n'
DOUBLE_CRLF = CRLF + CRLF

HTTP = {
    200: 'OK',
    201: 'Created',
    202: 'Accepted',
    203: 'Non-Authorative Information',
    204: 'No Content',
    205: 'Reset Content',
    206: 'Partial Content',
    300: 'Multiple Choices',
    301: 'Moved Permanently',
    302: 'Found',
    303: 'See Other',
    304: 'Not Modified',
    305: 'Use Proxy',
    306: 'No Longer Used',
    307: 'Temporary Redirect',
    400: 'Bad Request',
    401: 'Not Authorised',
    402: 'Payment Required',
    403: 'Forbidden',
    404: 'Not Found',
    405: 'Method Not Allowed',
    406: 'Not Acceptable',
    407: 'Proxy Authentication Required',
    408: 'Request Timeout',
    409: 'Conflict',
    410: 'Gone',
    411: 'Length Required',
    412: 'Precondition Failed',
    413: 'Request Entity Too Large',
    414: 'Request URI Too Long',
    415: 'Unsupported Media Type',
    416: 'Requested Range Not Satisfiable',
    417: 'Expectation Failed',
    418: "I'm a teapot",
    500: 'Internal Server Error',
    501: 'Not Implemented',
    502: 'Bad Gateway',
    503: 'Service Unavailable',
    504: 'Gateway Timeout',
    505: 'HTTP Version Not Supported'
}

class BadRequest(Exception):
    def __init__(self, message, code='400 Bad Request'):
        Exception.__init__(self, message)
        self.code = code

###############################################################################
# HTTPClient Class
###############################################################################

class HTTPClient(object):
    """
    An HTTP client, capable of communicating with most, if not all, servers
    using an incomplete implementation of HTTP protocol version 1.1.

    The behavior of an instance of HTTPClient is determined by that instance's
    :func:`on_response` function. That function may be changed by subclassing
    HTTPClient, assigning it directly, or supplying a suitable callable as the
    first argument when creating an instance of HTTPClient.

    =================  ========  ============
    Argument           Default   Description
    =================  ========  ============
    response_handler   None      *Optional.* A callable that will handle any received responses.
    max_redirects      5         *Optional.* The number of times to follow a redirect issued by the server.
    keep_alive         True      *Optional.* Whether or not a single connection will be reused for multiple requests.
    unicode            True      *Optional.* Whether or not to attempt to convert the response body to unicode using the provided Content-Type header's encoding information.
    =================  ========  ============
    """
    def __init__(self, response_handler=None, max_redirects=5, keep_alive=True,
                unicode=True):
        if response_handler is not None:
            if not callable(response_handler):
                raise ValueError("response handler must be callable.")
            self.on_response = response_handler

        # Internal State
        self._stream = None
        self._processing = False
        self._requests = []
        self._server = None
        self._is_secure = False
        self._helper = None

        # External State
        self.keep_alive = keep_alive
        self.max_redirects = max_redirects
        self.unicode = unicode

    ##### General Methods #####################################################

    def get(self, url, timeout=30, headers=None, **kwargs):
        """
        Perform an HTTP GET request for the specified URL. Additional query
        parameters may be specified as keyword arguments. For example::

            client.get('http://www.google.com/search', q='test')

        Is equivalent to::

            client.get('http://www.google.com/search?q=test')

        =========  ========  ============
        Argument   Default   Description
        =========  ========  ============
        url                  The URL to request.
        timeout    30        *Optional.* The time, in seconds, to wait for a response before erroring.
        headers    None      *Optional.* A dictionary of headers to send with the request. If none are provided, basic headers are set.
        =========  ========  ============
        """
        helper = self._helper
        if helper is None:
            helper = ClientHelper(self)

        if kwargs:
            query, fragment = urlparse.urlparse(url)[4:6]
            if query:
                query = "%s&%s" % (query, urllib.urlencode(kwargs, True))
                url = "%s?%s" % (url.partition('?')[0], query)
                if fragment:
                    url = "%s#%s" % (url, fragment)

            else:
                query = urllib.urlencode(kwargs, True)
                if fragment:
                    url = "%s?%s#%s" % (url.partition('#')[0], query, fragment)
                else:
                    url = "%s?%s" % (url, query)

        helper.requests.append(self._add_request('GET', url, headers, None,
                                timeout))

        return helper

    def post(self, url, timeout=None, headers=None, files=None, **kwargs):
        """
        Perform an HTTP POST request for the specified URL.

        =========  ========  ============
        Argument   Default   Description
        =========  ========  ============
        url                  The URL to request.
        timeout    30        *Optional.* The time, in seconds, to wait for a response before erroring.
        headers    None      *Optional.* A dictionary of headers to send with the request. If none are provided, basic headers are set.
        files      None      *Optional.* A dictionary of files to send with the request. If this is provided, the dictionary keys should be equivalent to HTML form field names, and the values should be tuples of ``(filename, data)``.
        =========  ========  ============

        Any additional keyword arguments will be sent in the request body as
        POST variables.
        """
        helper = self._helper
        if helper is None:
            helper = ClientHelper(self)

        body = ''

        if headers is None:
            headers = {}

        if headers.get('Content-Type', '') == 'application/x-www-form-urlencoded' and files:
            raise ValueError("Cannot send files with Content-Type "
                             "'application/x-www-form-urlencoded'.")

        if files:
            headers['Content-Type'] = 'multipart/form-data'
        elif not 'Content-Type' in headers:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'

        if headers['Content-Type'] == 'multipart/form-data':
            boundary, body = encode_multipart(kwargs, files)

            headers['Content-Type'] = 'multipart/form-data; boundary=%s' % \
                boundary

        elif kwargs:
            body = urllib.urlencode(kwargs, True)

        helper.requests.append(self._add_request('POST', url, headers, body,
                                timeout))

        return helper

    def process(self):
        """
        Useful for testing, and other synchronous work, this function will
        start the Pants engine and block until all outstanding requests
        complete.
        """
        if not self._requests:
            return

        self._processing = True
        Engine.instance().start()

    ##### Public Event Handlers ###############################################

    def on_response(self, response):
        """
        Placeholder. Called when an HTTP response is received.

        =========  ============
        Argument   Description
        =========  ============
        response   The received HTTP response.
        =========  ============
        """
        pass

    ##### Private Methods #####################################################

    def _add_request(self, method, url, headers, body, timeout, append=True):
        u = url.lower()
        if not (u.startswith('http://') or u.startswith('https://')):
            raise ValueError("Can only make HTTP or HTTPS requests with HTTPClient.")

        parts = urlparse.urlparse(url)

        # Build our headers.
        if headers is None:
            headers = {}

        if not 'Accept-Encoding' in headers:
            headers['Accept-Encoding'] = 'deflate, gzip'

        if not 'Host' in headers:
            headers['Host'] = parts.netloc

        if not 'User-Agent' in headers:
            headers['User-Agent'] = USER_AGENT

        if body:
            headers['Content-Length'] = len(body)

        path = parts.path or '/'
        if parts.query:
            path = '%s?%s' % (path, parts.query)
        if parts.fragment:
            path = '%s#%s' % (path, parts.fragment)

        request = [method, url, parts, headers, body, timeout, None, time(),
                    path, 0]

        if append:
            self._requests.append(request)

            # If we're just starting, start to process.
            if len(self._requests) == 1:
                callback(self._process_request)

        return request

    def _process_request(self):
        """
        Starts processing the first request on the stack.
        """
        if not self._requests:
            if self._stream:
                self._stream.close()
                self._stream = None
            if self._processing:
                self._processing = False
                Engine.instance().stop()
            return

        request = self._requests[0]

        request.append(
            Engine.instance().defer(self._request_timeout, request[5], request))

        port = request[2].port
        if not port:
            if request[2].scheme.lower() == 'https':
                port = 443
            else:
                port = 80

        host = "%s:%d" % (request[2].hostname, port)

        if self._stream:
            if not self._server == host.lower() or not \
                    self._is_secure == (request[2].scheme.lower() == 'https'):
                self._stream.end()
                return

        if not self._stream:
            # Store the current server.
            self._server = host.lower()

            # Create a Stream, hook into it, and connect.
            self._stream = Stream()

            self._stream.on_close = self._on_close
            self._stream.on_connect = self._on_connect

            self._is_secure = request[2].scheme.lower() == 'https'
            if self._is_secure:
                self._stream.startTLS()

            self._stream.connect(request[2].hostname, port)
            return

        # If we got here, we're connected, and to the right server. Do stuff.
        self.write('%s %s HTTP/1.1%s' % (request[0], request[8], CRLF))
        for k, v in request[3].iteritems():
            self.write('%s: %s%s' % (k, v, CRLF))

        if request[4]:
            self.write('%s%s' % (CRLF, request[4]))
        else:
            self.write(CRLF)

        # Now, wait for a response.
        self._stream.on_read = self._read_headers
        self._stream.read_delimiter = DOUBLE_CRLF

    ##### Internal Event Handlers #############################################

    def _on_connect(self):
        if self._requests:
            self._process_request()
        else:
            self._stream.end()

    def _on_close(self):
        """
        In the event that the connection is closed, see if there's another
        request to process. If so, reconnect to the given host.
        """
        self._stream = None
        self._is_secure = False
        self._process_request()

    def _on_response(self):
        """
        Call the response handler.
        """
        request = self._requests.pop(0)
        try:
            request[-1].cancel()
            left = request[-1].end - Engine.instance().time
        except Exception:
            left = request[5]
            pass

        response = self.current_response

        close_after = response.headers.get('Connection', '') == 'close'
        close_after &= self.keep_alive

        # Is this a 100 Continue?
        if response.status == 100:
            self.current_response = None
            del response

            # Process the request.
            if close_after:
                if self._stream:
                    self._stream.close()
                    return

            self._process_request()
            return

        # Did we catch a redirect?
        if response.status in (301,302) and request[9] <= self.max_redirects:
            # Generate a new request, using the new URL.
            new_url = urlparse.urljoin(response.full_url,
                        response.headers['Location'])

            new_headers = request[3].copy()
            del new_headers['Host']

            new_req = self._add_request(request[0], new_url, new_headers,
                                        request[4], left, False)
            new_req[6] = request[6]
            new_req[7] = request[7]
            new_req[9] = request[9] + 1

            new_req.append(
                Engine.instance().defer(self._request_timeout, left, new_req))

            self._requests.insert(0, new_req)
            self.current_response = None
            del response

            # Process the request.
            if close_after:
                if self._stream:
                    self._stream.close()
                    return

            self._process_request()
            return

        # Try converting to unicode?
        if self.unicode:
            content_type = response.headers.get('Content-Type','')
            if 'charset=' in content_type:
                content_type, _, encoding = content_type.partition('charset=')
                try:
                    response.body = response.body.decode(encoding)
                except (LookupError, UnicodeDecodeError):
                    pass

        # Determine the handler function to use.
        if callable(request[6]):
            func = request[6]
        else:
            func = self.on_response

        # Call the handler function.
        try:
            func(0, response)
        except Exception:
            log.exception('Error in HTTP response handler.')

        # Process the next request.
        self.current_response = None

        if close_after:
            if self._stream:
                self._stream.close()
                return

        self._process_request()

    def _request_timeout(self, request):
        if not request in self._requests:
            return

        self._requests.remove(request)

        if callable(request[6]):
            func = request[6]
        else:
            func = self.on_response

        try:
            func(1, None)
        except Exception:
            log.exception('Error in HTTP response handler.')

    def _read_body(self, data):
        """
        Read the response body, decompress it if necessary, and then call the
        response handler.
        """
        resp = self.current_response
        if resp._decompressor:
            resp.body = resp._decompressor.decompress(data)
            resp.body += resp._decompressor.flush()
            del resp._decompressor
        else:
            resp.body = data
        self._on_response()

    def _read_additional_headers(self, data):
        resp = self.current_response

        if data:
            resp._additional_headers += '%s%s' % (data, CRLF)
            return

        headers = read_headers(resp._additional_headers)
        del resp._additional_headers

        # Did we get an additional header for Content-Encoding?
        enc = resp.headers.get('Content-Encoding', '')

        for k,v in headers.iteritems():
            if k in resp.headers:
                if not isinstance(resp.headers[k], list):
                    resp.headers[k] = [resp.headers[k]]
                if isinstance(v, list):
                    resp.headers[k].extend(v)
                else:
                    resp.headers[k].append(v)
            else:
                resp.headers[k] = v

        new_enc = resp.headers.get('Content-Encoding', '')
        if (new_enc == 'gzip' or new_enc == 'deflate') and enc == '':
            if new_enc == 'gzip':
                resp.body = zlib.decompress(resp.body, 16 + zlib.MAX_WBITS)
            elif new_enc == 'deflate':
                resp.body = zlib.decompress(resp.body, -zlib.MAX_WBITS)

        # Finally, handle it.
        self._on_response()

    def _read_chunk_head(self, data):
        """
        Read a chunk header.
        """
        if ';' in data:
            data, ext = data.split(';', 1)
        else:
            ext = ''

        length = int(data.strip(), 16)

        if length == 0:
            resp = self.current_response
            if resp._decompressor:
                resp.body += resp._decompressor.flush()
                del resp._decompressor

            self._stream.on_read = self._read_additional_headers
            resp._additional_headers = ''
            self._stream.read_delimiter = CRLF

        else:
            self._stream.on_read = self._read_chunk_body
            self._stream.read_delimiter = length + 2

    def _read_chunk_body(self, data):
        """
        Read a chunk body.
        """
        resp = self.current_response

        if resp._decompressor:
            resp.body += resp._decompressor.decompress(data[:-2])
        else:
            resp.body += data[:-2]

        self._stream.on_read = self._read_chunk_head
        self._stream.read_delimiter = CRLF

    def _read_headers(self, data):
        """
        Read the headers of an HTTP response from the socket, and the response
        body as well, into a new HTTPResponse instance. Then call the request
        handler.
        """
        do_close = False

        try:
            initial_line, data = data.split(CRLF, 1)
            try:
                try:
                    http_version, status, status_text = initial_line.split(' ', 2)
                    status = int(status)
                except ValueError:
                    http_version, status = initial_line.split(' ')
                    status = int(status)
                    status_text = HTTP.get(status, '')
            except ValueError:
                raise BadRequest('Invalid HTTP status line %r.' % initial_line)

            # Parse the headers.
            headers = read_headers(data)

            # Construct an HTTPResponse object.
            self.current_response = response = HTTPResponse(self,
                self._requests[0], http_version, status, status_text, headers)

            # Do we have a Content-Encoding header?
            if 'Content-Encoding' in headers:
                encoding = headers['Content-Encoding']
                if encoding == 'gzip':
                    response._decompressor = zlib.decompressobj(16+zlib.MAX_WBITS)
                elif encoding == 'deflate':
                    response._decompressor = zlib.decompressobj(-zlib.MAX_WBITS)

            # Do we have a Content-Length header?
            if 'Content-Length' in headers:
                self._stream.on_read = self._read_body
                self._stream.read_delimiter = int(headers['Content-Length'])

            elif 'Transfer-Encoding' in headers:
                if headers['Transfer-Encoding'] == 'chunked':
                    self._stream.on_read = self._read_chunk_head
                    self._stream.read_delimiter = CRLF
                else:
                    raise BadRequest("Unsupported Transfer-Encoding: %s" % headers['Transfer-Encoding'])

            # Is this a HEAD request? If so, then handle the request NOW.
            if response.method == 'HEAD':
                self._on_response()

        except BadRequest, e:
            log.info('Bad response from %r: %s',
                self._server, e)
            do_close = True

        except Exception:
            log.exception('Error handling HTTP response.')
            do_close = True

        # Clear the way for the next request.
        if do_close:
            self._requests.pop(0)
            self.current_response = None
            if self._stream:
                self._stream.close()
                self._stream = None

class ClientHelper(object):
    """
    An instance of this class is returned by calls to :func:`HTTPClient.get`
    and :func:`HTTPClient.post` to allow for a bit of decorator magic.

    For further information, please see the :class:`HTTPClient` documentation.
    """
    def __init__(self, parent):
        self.parent = parent
        self.requests = []
        self._responses = []

    def get(self, *a, **kw):
        self.parent._helper = self
        try:
            return self.parent.get(*a, **kw)
        finally:
            self.parent._helper = None

    def post(self, *a, **kw):
        self.parent._helper = self
        try:
            return self.parent.post(*a, **kw)
        finally:
            self.parent._helper = None

    def _collect(self, status, response):
        self._responses.append((status, response))

    def fetch(self):
        """
        Perform all the pending requests and return them. If there is more than
        one outstanding request, the results will be returned as a list of
        :class:`HTTPResponse` instances. Otherwise, a single HTTPResponse
        instance will be returned.
        """
        for req in self.requests:
            req[6] = self._collect

        self.process()

        out = self._responses
        self._responses = []

        if len(out) == 1:
            return out[0]
        return out

    def process(self):
        return self.parent.process()

    def __call__(self, func):
        for req in self.requests:
            req[6] = func
        return func

###############################################################################
# HTTPResponse Class
###############################################################################

class HTTPResponse(object):
    """
    Instances of this class represent singular HTTP responses that an instance
    of :class:`HTTPClient` has received. Such instances contain all the
    information needed to act upon a response.

    This class should, generally, not be used directly. Instead, allow the
    HTTPClient to create instances for you.

    =============  ============
    Argument       Description
    =============  ============
    client         The instance of :class:`HTTPClient` that received this response.
    request        The request list, containing all the information passed to the call that generated the request responsible for this response.
    http_version   The HTTP protocol version used in this response. This will almost always be one of: ``HTTP/1.0`` or ``HTTP/1.1``.
    status         The `HTTP status code <http://en.wikipedia.org/wiki/Http_status_codes>`_ received with this response.
    status_text    The human readable status message that goes with the received status code.
    headers        A dictionary of HTTP headers received with this response.
    =============  ============
    """

    def __init__(self, client, request, http_version, status, status_text,
                    headers):
        self.body = ''
        self.client = client
        self.headers = headers
        self.method = request[0]
        self.protocol = request[2].scheme
        self.request = request
        self.uri = request[8]
        self.version = http_version

        self.host = client._server
        if self.host.endswith(':80'):
            self.host = self.host[:-3]

        self.status = status
        self.status_text = status_text

        self._decompressor = None

        # Timing Information
        self._start = request[7]
        self._finish = time()
        self.time = self._finish - self._start

    ##### Properties ##########################################################

    @property
    def cookies(self):
        """
        An instance of :class:`Cookie.SimpleCookie` representing the cookies
        received with this response.
        """
        try:
            return self._cookies
        except AttributeError:
            self._cookies = cookies = Cookie.SimpleCookie()
            if 'Set-Cookie' in self.headers:
                raw = self.headers['Set-Cookie']
                if isinstance(raw, list):
                    for i in raw:
                        cookies.load(i)
                else:
                    cookies.load(raw)
            return self._cookies

    @property
    def full_url(self):
        """
        The full URL of the request that generated this response.
        """
        return "%s://%s%s" % (self.protocol, self.host, self.uri)

###############################################################################
# HTTPConnection Class
###############################################################################

class HTTPConnection(Connection):
    """
    Instances of this class represent connections received by an
    :class:`HTTPServer`, and perform all the actual logic of receiving and
    responding to an HTTP request.

    In order, this class is in charge of: reading HTTP request lines, reading
    the associated headers, reading any request body, and executing the
    appropriate request handler if the request is valid.
    """
    def __init__(self, *args):
        Connection.__init__(self, *args)

        # Request State Storage
        self.current_request = None
        self._finished = False

        # Read the initial request.
        self._await_request()

    ##### I/O Methods #########################################################

    def finish(self):
        """
        This function should be called when the response to the current
        request has been completed, in preparation for either closing the
        connection or attempting to read a new request from the connection.

        Failing to call this function (or the finish function of the request,
        which in turn calls this) will drastically reduce the performance of
        the HTTP server.
        """
        self._finished = True
        if not self._send_buffer:
            self._request_finished()

    ##### Public Event Handlers ###############################################

    def on_write(self, bytes_written=None):
        if self._finished:
            self._request_finished()

    ##### Internal Event Handlers #############################################

    def _await_request(self):
        """
        Sets the read handler and read delimiter to prepare to read an HTTP
        request from the socket.
        """
        self.on_read = self._read_header
        self.read_delimiter = DOUBLE_CRLF

    def _request_finished(self):
        """
        If keep-alive is supported, and the server configuration allows, then
        the connection will be prepared to read another request. Otherwise, the
        connection will be closed.
        """
        disconnect = True

        if self.server.keep_alive:
            headers = self.current_request.headers
            connection = headers.get('Connection','').lower()

            if self.current_request.version == 'HTTP/1.1':
                disconnect = connection == 'close'

            elif 'Content-Length' in headers or \
                    self.current_request.method in ('HEAD','GET'):
                disconnect = connection != 'keep-alive'

        self.current_request = None
        self._finished = False

        if disconnect:
            self.on_read = None
            self.end()
        else:
            self._await_request()

    def _read_header(self, data):
        """
        Read the headers of an HTTP request from the socket, and the request
        body if necessary, into a new HTTPRequest instance. Then, assuming that
        the headers are valid, call the server's request handler.
        """
        try:
            initial_line, data = data.split(CRLF, 1)
            try:
                method, uri, http_version = initial_line.split(' ')
                if not http_version.startswith('HTTP/'):
                    raise BadRequest(
                        'Invalid HTTP protocol version.',
                        code='505 HTTP Version Not Supported')
            except:
                raise BadRequest('Invalid HTTP request line.')

            # Parse the headers.
            headers = read_headers(data)

            protocol = 'http'

            if self.is_secure():
                protocol = 'https'

            # Construct an HTTPRequest object.
            self.current_request = request = HTTPRequest(self,
                method, uri, http_version, headers, protocol)

            # If we have a Content-Length header, read the request body.
            length = headers.get('Content-Length')
            if length:
                length = int(length)
                if length > self.server.max_request:
                    raise BadRequest((
                        'Provided Content-Length (%d) larger than server '
                        'limit %d.'
                        ) % (length, self.server.max_request),
                        code='413 Request Entity Too Large')

                if headers.get('Expect','').lower() == '100-continue':
                    self.write("%s 100 (Continue)%s" % (
                        http_version, DOUBLE_CRLF))

                # Await a request body.
                self.on_read = self._read_request_body
                self.read_delimiter = length
                return

            # Call the request handler.
            self.server.request_handler(request)

        except BadRequest, e:
            log.info('Bad request from %r: %s',
                self.remote_addr, e)
            self.write('HTTP/1.1 %s%s' % (e.code, CRLF))
            if e.body:
                self.write('Content-Type: text/html%s' % CRLF)
                self.write('Content-Length: %d%s' % (len(e.body), DOUBLE_CRLF))
                self.write(e.body)
            else:
                self.write(CRLF)
            self.end()

        except Exception:
            log.exception('Error handling HTTP request.')
            self.write('HTTP/1.1 500 Internal Server Error%s' % DOUBLE_CRLF)
            self.end()

    def _read_request_body(self, data):
        """
        Read a request body from the socket, parse it, and then call the
        request handler for the current request.
        """
        request = self.current_request
        request.body = data

        try:
            content_type = request.headers.get('Content-Type', '')
            if request.method in ('POST','PUT'):
                if content_type.startswith('application/x-www-form-urlencoded'):
                    for key, val in urlparse.parse_qs(data, False).iteritems():
                        request.post[key] = val

                elif content_type.startswith('multipart/form-data'):
                    for field in content_type.split(';'):
                        key, sep, value = field.strip().partition('=')
                        if key == 'boundary' and value:
                            parse_multipart(request, value, data)
                            break
                    else:
                        log.warning('Invalid multipart/form-data.')

            self.server.request_handler(request)

        except BadRequest, e:
            log.info('Bad request from %r: %s',
                self.remote_addr, e)
            self.write('HTTP/1.1 %s%s' % (e.code, CRLF))
            if e.body:
                self.write('Content-Type: text/html%s' % CRLF)
                self.write('Content-Length: %d%s' % (len(e.body), DOUBLE_CRLF))
                self.write(e.body)
            else:
                self.write(CRLF)
            self.end()

        except Exception:
            log.exception('Error handling HTTP request.')
            self.write('HTTP/1.1 500 Internal Server Error%s' % DOUBLE_CRLF)
            self.end()

###############################################################################
# HTTPRequest Class
###############################################################################

class HTTPRequest(object):
    """
    Instances of this class represent single HTTP requests that an
    :class:`HTTPServer` has received. Such instances contain all the
    information needed to respond to the request, as well as the functions used
    to actually send a response.

    This class should, generally, not be used directly. Instead, allow the
    HTTPServer to create instances for you.

    =============  ============
    Argument       Description
    =============  ============
    connection     The instance of :class:`HTTPConnection` that received this request.
    method         The HTTP method used to send this request. This will almost always be one of: ``GET``, ``HEAD``, or ``POST``.
    uri            The path part of the URI requested.
    http_version   The HTTP protocol version used for this request. This will almost always be one of: ``HTTP/1.0`` or ``HTTP/1.1``.
    headers        *Optional.* A dictionary of HTTP headers received with this request.
    protocol       *Optional.* Either the string ``http`` or ``https``, depending on the security of the connection this request was received upon.
    =============  ============
    """

    def __init__(self, connection, method, uri, http_version, headers=None,
                 protocol='http'):
        self.body       = ''
        self.connection = connection
        self.headers    = headers or {}
        self.method     = method
        self.uri        = uri
        self.version    = http_version

        # X-Headers
        if connection.server.xheaders:
            remote_ip = self.headers.get('X-Real-IP')
            if remote_ip is None:
                remote_ip = self.headers.get('X-Forwarded-For')
                if remote_ip is None:
                    remote_ip = connection.remote_addr[0]
                else:
                    remote_ip = remote_ip.split(',')[0].strip()

            self.remote_ip = remote_ip
            self.protocol = self.headers.get('X-Forwarded-Proto', protocol)
        else:
            self.remote_ip  = connection.remote_addr[0]
            self.protocol   = protocol

        # Calculated Variables
        self.host       = self.headers.get('Host', '127.0.0.1')

        # Timing Information
        self._start     = time()
        self._finish    = None

        # Request Variables
        self.post       = {}
        self.files      = {}

        # Split the URI into usable information.
        self._parse_uri()

    def __repr__(self):
        attr = ('version','method','protocol','host','uri','path','time')
        attr = u', '.join(u'%s=%r' % (k,getattr(self,k)) for k in attr)
        return u'%s(%s, headers=%r)' % (
            self.__class__.__name__, attr, self.headers)

    def __html__(self):
        attr = ('version','method','remote_ip','protocol','host','uri','path',
                'time')
        attr = u'\n    '.join(u'%-8s = %r' % (k,getattr(self,k)) for k in attr)

        out = u'<pre>%s(\n    %s\n\n' % (self.__class__.__name__, attr)

        for i in ('headers','get','post'):
            if getattr(self,i):
                out += u'    %-8s = {\n %s\n        }\n\n' % (
                    i, pprint.pformat(getattr(self, i), 8, 80)[1:-1])
            else:
                out += u'    %-8s = {}\n\n' % i

        if hasattr(self, '_cookies') and self.cookies:
            out += u'    cookies  = {\n'
            keys = list(self.cookies.__iter__())
            for k in self.cookies:
                out += u'        %r: %r\n' % (k, self.cookies[k].value)
            out += u'        }\n\n'
        else:
            out += u'    cookies  = {}\n\n'

        out += u'    files    = %s\n)</pre>' % \
            pprint.pformat(self.files.keys(), 0, 80)
        return out

    ##### Properties ##########################################################

    @property
    def cookies(self):
        """
        An instance of :class:`Cookie.SimpleCookie` representing the cookies
        received with this request. Cookies may also be written by adding them
        to the SimpleCookie instance, and then using the :func:`send_cookies`
        function.
        """
        try:
            return self._cookies
        except AttributeError:
            self._cookies = cookies = Cookie.SimpleCookie()
            if 'Cookie' in self.headers:
                raw = self.headers['Cookie']
                if isinstance(raw, list):
                    for i in raw:
                        cookies.load(i)
                else:
                    cookies.load(raw)
            return self._cookies

    @property
    def full_url(self):
        """
        The full URL used to generate the request.
        """
        return '%s://%s%s' % (self.protocol, self.host, self.uri)

    @property
    def time(self):
        """
        The amount of time that has elapsed since the request was received, or
        the total processing time if the request has already been finished.
        """
        if self._finish is None:
            return time() - self._start
        return self._finish - self._start

    ##### Secure Cookies ######################################################

    def set_secure_cookie(self, name, value, expires=30*86400, **kwargs):
        """
        Set a timestamp on a cookie and sign it, ensuring that it can't be
        altered by the client. To use this, the :class:`HTTPServer` *must* have
        a ``cookie_secret`` set.

        Cookies set with this function may be read with
        :func:`HTTPServer.get_secure_cookie`.

        =========  ============
        Argument   Description
        =========  ============
        name       The name of the cookie to set.
        value      The value of the cookie.
        expires    *Optional.* How long, in seconds, the cookie should last before expiring. By default, this is 30 days.
        =========  ============

        Additional arguments, such as ``path`` and ``httponly`` may be set by
        providing them as keyword arguments.
        """
        ts = str(int(curtime()))
        v = base64.b64encode(str(value))
        signature = generate_signature(
                        self.connection.server.cookie_secret, expires, ts, v)

        value = "%s|%d|%s|%s" % (value, expires, ts, signature)

        self.cookies[name] = value
        m = self.cookies[name]

        if kwargs:
            for k,v in kwargs.iteritems():
                m[k] = v
        m['expires'] = expires

    def get_secure_cookie(self, name):
        """
        Return the signed cookie with the key ``name``, if it exists and has a
        valid signature. Otherwise, return None.
        """
        try:
            value, expires, ts, signature = self.cookies[name].value.split('|')
            expires = int(expires)
            ts = int(ts)
        except AttributeError, ValueError:
            print 'boo'
            return None

        v = base64.b64encode(str(value))
        sig = generate_signature(self.connection.server.cookie_secret, expires, ts, v)

        if signature != sig or ts < curtime() - expires or ts > curtime() + expires:
            return None

        return value

    ##### I/O Methods #########################################################

    def finish(self):
        """
        This function should be called when the response has been completed,
        allowing the associated :class:`HTTPConnection` to either close the
        connection to the client or begin listening for a new request.

        Failing to call this function will drastically reduce the performance
        of the HTTP server.
        """
        self._finish = time()
        self.connection.finish()

    def send(self, data):
        """
        Write data to the client.

        =========  ============
        Argument   Description
        =========  ============
        data       A string of data to be sent to the client.
        =========  ============
        """
        self.connection.write(data)

    def send_cookies(self, keys=None, end_headers=False):
        """
        Write any cookies associated with the request to the client. If any
        keys are specified, only the cookies with the specified keys will be
        transmitted. Otherwise, all cookies will be written to the client.

        This function is usually called automatically by send_headers.

        ============  ========  ============
        Argument      Default   Description
        ============  ========  ============
        keys          None      *Optional.* A list of cookie names to send.
        end_headers   False     *Optional.* If this is set to True, a double CRLF sequence will be written at the end of the cookie headers, signifying the end of the HTTP headers segment and the beginning of the response.
        ============  ========  ============
        """
        if keys is None:
            out = self.cookies.output()
        else:
            out = []
            for k in keys:
                if not k in self.cookies:
                    continue
                out.append(self.cookies[k].output())
            out = CRLF.join(out)

        if not out.endswith(CRLF):
            out += CRLF

        if end_headers:
            self.connection.write('%s%s' % (out, CRLF))
        else:
            self.connection.write(out)

    def send_headers(self, headers, end_headers=True, cookies=True):
        """
        Write a dictionary of HTTP headers to the client.

        ============  ========  ============
        Argument      Default   Description
        ============  ========  ============
        headers                 A dictionary of HTTP headers.
        end_headers   True      *Optional.* If this is set to True, a double CRLF sequence will be written at the end of the cookie headers, signifying the end of the HTTP headers segment and the beginning of the response.
        cookies       True      *Optional.* If this is set to True, HTTP cookies will be sent along with the headers.
        ============  ========  ============
        """
        out = []
        append = out.append
        for key in headers:
            val = headers[key]
            if type(val) is list:
                for v in val:
                    append('%s: %s' % (key, v))
            else:
                append('%s: %s' % (key, val))

        if not 'Date' in headers and self.version == 'HTTP/1.1':
            append('Date: %s' % _date(datetime.utcnow()))

        if not 'Server' in headers:
            append('Server: %s' % SERVER)

        if cookies and hasattr(self, '_cookies'):
            self.send_cookies(end_headers=False)

        if end_headers:
            append(CRLF)
        else:
            append('')

        self.connection.write(CRLF.join(out))

    def send_status(self, code=200):
        """
        Write an HTTP status line (the very first line of any response) to the
        client, using the same HTTP protocol version as the request. If one is
        available, a human readable status message will be appended after the
        provided code.

        For example, ``request.send_status(404)`` would result in
        ``HTTP/1.1 404 Not Found`` being sent to the client, assuming of course
        that the request used HTTP protocol version ``HTTP/1.1``.

        =========  ========  ============
        Argument   Default   Description
        =========  ========  ============
        code       200       *Optional.* The HTTP status code to send to the client.
        =========  ========  ============
        """
        try:
            HTTP[code]
            self.connection.write('%s %d %s%s' % (
                self.version, code, HTTP[code], CRLF))
        except KeyError:
            self.connection.write('%s %s%s' % (
                self.version, code, CRLF))

    write = send

    ##### Internal Event Handlers #############################################

    def _parse_uri(self):
        path, query = urlparse.urlsplit(self.uri)[2:4]
        self.path   = path
        self.query  = query

        self.get = get = {}
        if query:
            for key, val in urlparse.parse_qs(query, False).iteritems():
                if len(val) == 1:
                    val = val[0]
                get[key] = val

###############################################################################
# HTTPServer Class
###############################################################################

class HTTPServer(SSLServer):
    """
    An `HTTP <http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol>`_ server,
    extending the default Server class.

    This class automatically uses the :class:`HTTPConnection` connection class.
    Rather than through specifying a connection class, its behavior is
    customized by providing a request handler function that is called whenever
    a valid request is received.

    A server's behavior is defined almost entirely by its request handler, and
    will not send any response by itself unless the received HTTP request is
    not valid or larger than the specified limit (which defaults to 10 MiB).

    The following is an example that will display a very simple Hello World to
    any connecting clients::

        from pants.contrib.http import HTTPServer
        from pants import engine

        def on_request(request):
            response = ''.join([
                '<!DOCTYPE html>',
                '<title>Hello, World!</title>',
                '<h1>Hello, World!</h1>',
                '<p>Your request was for <code>%s</code>.</p>' % request.uri
            ])

            request.send('HTTP/1.1 200 OK\\r\\n')
            request.send('Content-Type: text/html\\r\\n')
            request.send('Content-Length: %d\\r\\n\\r\\n' % len(response))
            request.send(response)
            request.finish()

        server = HTTPServer(on_request)
        server.listen(80)

        engine.start()

    ================  ========  ============
    Argument          Default   Description
    ================  ========  ============
    request_handler             A callable that accepts a single argument. That argument is an instance of the :class:`HTTPRequest` class representing the current request.
    max_request       10 MiB    *Optional.* The maximum allowed length, in bytes, of an HTTP request body.
    keep_alive        True      *Optional.* Whether or not multiple requests are allowed over a single connection.
    ssl_options       None      *Optional.* A dictionary of options for establishing SSL connections. If this is set, the server will serve requests via HTTPS. The keys and values provided by the dictionary should mimic the arguments taken by :func:`ssl.wrap_socket`.
    cookie_secret     None      *Optional.* A string to use when signing secure cookies.
    xheaders          False     *Optional.* Whether or not to use X-Forwarded-For and X-Forwared-Proto headers.
    ================  ========  ============
    """
    ConnectionClass = HTTPConnection

    def __init__(self, request_handler, max_request=10485760, keep_alive=True,
                    ssl_options=None, cookie_secret=None, xheaders=False):
        SSLServer.__init__(self, ssl_options=ssl_options)

        # Storage
        self.request_handler    = request_handler
        self.max_request        = max_request
        self.keep_alive         = keep_alive
        self.xheaders           = xheaders

        self._cookie_secret     = cookie_secret

    @property
    def cookie_secret(self):
        if self._cookie_secret is None:
            self._cookie_secret = os.urandom(30)

        return self._cookie_secret

    @cookie_secret.setter
    def cookie_secret(self, val):
        self._cookie_secret = val

    def listen(self, port=None, host='', backlog=1024):
        """
        Begins listening on the given host and port.

        =========  ============
        Argument   Description
        =========  ============
        port       *Optional.* The port for the server to listen on. If this isn't specified, it will be set to either 80, or 443 if SSL options have been provided.
        host       *Optional.* The host interface to listen on. By default, listen on all interfaces (``''``).
        backlog    *Optional.* The maximum number of connection attempts to queue. Defaults to 1,024.
        =========  ============
        """
        if not port:
            if self.ssl_options:
                port = 443
            else:
                port = 80

        SSLServer.listen(self, port, host, backlog)

###############################################################################
# Support Functions
###############################################################################

def generate_signature(key, *parts):
    hash = hmac.new(key, digestmod=hashlib.sha1)
    for p in parts:
        hash.update(str(p))
    return hash.hexdigest()

def content_type(filename):
    return mimetypes.guess_type(filename)[0] or 'application/octet-stream'

def encode_multipart(vars, files=None, boundary=None):
    """
    Encode a set of variables and/or files into a ``multipart/form-data``
    request body.

    =========  ============
    Argument   Description
    =========  ============
    vars       A dictionary of variables to encode.
    files      *Optional.* A dictionary of tuples of ``(filename, data)`` to encode.
    boundary   *Optional.* The boundary string to use when encoding, if for any reason the default string is unacceptable.
    =========  ============
    """

    if boundary is None:
        boundary = '-----pants-----PANTS-----pants$'

    out = []

    for k, v in vars.iteritems():
        out.append('--%s' % boundary)
        out.append(CRLF.join([
            'Content-Disposition: form-data; name="%s"' % k,
            '', str(v)]))
    if files:
        for k, (fn, v) in files.iteritems():
            out.append('--%s' % boundary)
            out.append(CRLF.join([
                'Content-Disposition: form-data; name="%s"; filename="%s"' % (
                    k, fn),
                'Content-Type: %s' % content_type(fn),
                '',
                str(v)]))

    out.append('--%s--' % boundary)
    out.append('')

    return boundary, CRLF.join(out)

def parse_multipart(request, boundary, data):
    """
    Parse a ``multipart/form-data`` request body and modify the request's
    ``post`` and ``files`` dictionaries as is appropriate.

    =========  ============
    Argument   Description
    =========  ============
    request    An :class:`HTTPRequest` instance that should be modified to include the parsed data.
    boundary   The ``multipart/form-data`` boundary to be used for splitting the data into parts.
    data       The data to be parsed.
    =========  ============
    """

    if boundary.startswith('"') and boundary.endswith('"'):
        boundary = boundary[1:-1]

    footer_length = len(boundary) + 4
    if data.endswith(CRLF):
        footer_length += 2

    parts = data[:-footer_length].split('--%s%s' % (boundary, CRLF))
    for part in parts:
        if not part:
            continue

        eoh = part.find(DOUBLE_CRLF)
        if eoh == -1:
            log.warning(
                'Missing part headers in multipart/form-data. Skipping.')
            continue

        headers = read_headers(part[:eoh])
        name_header = headers.get('Content-Disposition', '')
        if not name_header.startswith('form-data;') or not part.endswith(CRLF):
            log.warning('Invalid multipart/form-data part.')
            continue

        value = part[eoh+4:-2]
        name_values = {}
        for name_part in name_header[10:].split(';'):
            name, name_value = name_part.strip().split('=', 1)
            name_values[name] = name_value.strip('"').decode('utf-8')

        if not 'name' in name_values:
            log.warning('Missing name value in multipart/form-data part.')
            continue

        name = name_values['name']
        if 'filename' in name_values:
            content_type = headers.get('Content-Type', 'application/unknown')
            request.files.setdefault(name, []).append(dict(
                filename=name_values['filename'], body=value,
                content_type=content_type))
        else:
            request.post.setdefault(name, []).append(value)

def read_headers(data, target=None):
    """
    Read HTTP headers from the supplied data string and return a dictionary
    of those headers. If bad data is supplied, a :class:`BadRequest` exception
    will be raised.

    =========  ============
    Argument   Description
    =========  ============
    data       A data string containing HTTP headers.
    target     *Optional.* A dictionary in which to place the processed headers.
    =========  ============
    """
    if target is None:
        target = {}

    data = data.rstrip(CRLF)
    key = None

    for line in data.splitlines():
        if not line:
            raise BadRequest('Illegal header line: %r' % line)
        if line[0] in ' \t':
            val = line.strip()
        else:
            try:
                key, sep, val = line.partition(':')
            except ValueError:
                raise BadRequest('Illegal header line: %r' % line)

            key = key.rstrip()
            val = val.strip()

        if key in target:
            if key in COMMA_HEADERS:
                target[key] = '%s, %s' % (target[key], val)
            elif isinstance(target[key], list):
                target[key].append(val)
            else:
                target[key] = [target[key], val]
            continue
        target[key] = val

    return target

def _date(dt):
    return dt.strftime("%a, %d %b %Y %H:%M:%S GMT")