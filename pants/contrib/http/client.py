###############################################################################
#
# Copyright 2011 Pants Developers (see AUTHORS.txt)
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

import Cookie
import urllib
import urlparse
import zlib

from pants.contrib.http.utils import *

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
    max_redirects      ``5``     *Optional.* The number of times to follow a redirect issued by the server.
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
        timeout    ``30``    *Optional.* The time, in seconds, to wait for a response before erroring.
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
        timeout    ``30``    *Optional.* The time, in seconds, to wait for a response before erroring.
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
            Engine.instance().defer(request[5], self._request_timeout, request))

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
                raise Exception("SSL has not yet been implemented in this version of Pants.")
                self._stream.startTLS()

            self._stream.connect((request[2].hostname, port))
            return

        # If we got here, we're connected, and to the right server. Do stuff.
        self._stream.write('%s %s HTTP/1.1%s' % (request[0], request[8], CRLF))
        for k, v in request[3].iteritems():
            self._stream.write('%s: %s%s' % (k, v, CRLF))

        if request[4]:
            self._stream.write('%s%s' % (CRLF, request[4]))
        else:
            self._stream.write(CRLF)

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
                Engine.instance().defer(left, self._request_timeout, new_req))

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

