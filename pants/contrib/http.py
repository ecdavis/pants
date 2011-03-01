###############################################################################
#
# Copyright 2011 Stendec <stendec365@gmail.com>
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
import logging
import mimetypes
import pprint
import urllib
import urlparse
import zlib

from time import time
from pants import callback, Connection, __version__ as pants_version
from pants.channel import Channel

from pants.contrib.ssl import SSLServer

###############################################################################
# Logging
###############################################################################

log = logging.getLogger('http')

###############################################################################
# Constants
###############################################################################

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
    using an incomplete implementation of HTTP/1.1.
    
    The HTTPClient's behavior is defined, mainly, through the handle_response
    function that's expected as the first argument when constructing a new
    HTTPClient.
    
    Alternatively, you may subclass HTTPClient to modify the response handler.
    """
    def __init__(self, response_handler=None, max_redirects=5, keep_alive=True,
                unicode=True):
        """
        Initialize a new HTTPClient instance.
        
        Args:
            response_handler: Optionally, a function to use for handling
                received responses from the server. If None is provided, the
                default will be used instead.
            max_redirects: The number of times to follow a redirect from the
                server. Defaults to 5.
            keep_alive: If True, the connection will be reused as much as
                possible. Defaults to True.
            unicode: If True, the Content-Type header will be checked for a
                character set. If one is present, the body will be converted
                to unicode, using that character set. Defauls to True.
        """
        if response_handler is not None:
            if not callable(response_handler):
                raise ValueError("response handler must be callable.")
            self.handle_response = response_handler
        
        # Internal State
        self._channel = None
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
        parameters may be specified as keyword arguments. For example:
            
            client.get('http://www.google.com/search', q='test')
        
        Is equivilent to:
            
            client.get('http://www.google.com/search?q=test')
        
        Args:
            url: The URL to fetch.
            timeout: The time, in seconds, to wait for a response before
                erroring out. Defaults to 30.
            headers: An optional dict of headers to send with the request.
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
        
        Args:
            url: The URL to fetch.
            timeout: The time, in seconds, to wait for a response before
                erroring out. Defaults to 30.
            headers: An optional dict of headers to send with the request.
            files: An optional dict of files to submit to the server.
        
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
        Block until the queued requests finish.
        """
        if not self._requests:
            return
        
        self._processing = True
        from pants.engine import Engine
        Engine.instance().start()
    
    ##### Public Event Handlers ###############################################
    
    def handle_response(self, response):
        """
        Placeholder. Called when an HTTP response is received.
        
        Args:
            response: The HTTP response that was received.
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
            if self._channel:
                self._channel.close_immediately()
                self._channel = None
            if self._processing:
                self._processing = False
                from pants.engine import Engine
                Engine.instance().stop()
            return
        
        request = self._requests[0]
        
        port = request[2].port
        if not port:
            if request[2].scheme.lower() == 'https':
                port = 443
            else:
                port = 80
        
        host = "%s:%d" % (request[2].hostname, port)
        
        if self._channel:
            if not self._server == host.lower() or not \
                    self._is_secure == (request[2].scheme.lower() == 'https'):
                self._channel.close()
                return
        
        if not self._channel:
            # Store the current server.
            self._server = host.lower()
            
            # Create a Channel, hook into it, and connect.
            self._channel = Channel()
            
            self._channel.handle_close = self._handle_close
            self._channel.handle_connect = self._handle_connect
            
            self._is_secure = request[2].scheme.lower() == 'https'
            if self._is_secure:
                self._channel.startTLS()
            
            self._channel.connect(request[2].hostname, port)
            return
        
        # If we got here, we're connected, and to the right server. Do stuff.
        self._send('%s %s HTTP/1.1%s' % (request[0], request[8], CRLF))
        for k, v in request[3].iteritems():
            self._send('%s: %s%s' % (k, v, CRLF))
        
        if request[4]:
            self._send('%s%s' % (CRLF, request[4]))
        else:
            self._send(CRLF)
        
        # Now, wait for a response.
        self._channel.handle_read = self._read_headers
        self._channel.read_delimiter = DOUBLE_CRLF
    
    def _send(self, data):
        self._channel.write(data)
    
    ##### Internal Event Handlers #############################################
    
    def _handle_connect(self):
        #if self._is_secure and not self._channel.is_secure():
        #    self._channel.startTLS()
        #    return
        
        if self._requests:
            self._process_request()
        else:
            self._channel.close()
    
    def _handle_close(self):
        """
        In the event that the connection is closed, see if there's another
        request to process. If so, reconnect to the given host.
        """
        self._channel = None
        self._is_secure = False
        self._process_request()
    
    def _handle_response(self):
        """
        Call the response handler.
        """
        request = self._requests.pop(0)
        response = self.current_response
        
        close_after = response.headers.get('Connection', '') == 'close'
        close_after &= self.keep_alive
        
        # Is this a 100 Continue?
        if response.status == 100:
            self.current_response = None
            del response
            
            # Process the request.
            if close_after:
                if self._channel:
                    self._channel.close_immediately()
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
                                        request[4], request[5], False)
            new_req[6] = request[6]
            new_req[7] = request[7]
            new_req[9] = request[9] + 1
            
            self._requests.insert(0, new_req)
            self.current_response = None
            del response
            
            # Process the request.
            if close_after:
                if self._channel:
                    self._channel.close_immediately()
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
            func = self.handle_response
        
        # Call the handler function.
        try:
            func(response)
        except Exception:
            log.exception('Error handling HTTP response.')
        
        # Process the next request.
        self.current_response = None
        
        if close_after:
            if self._channel:
                self._channel.close_immediately()
                return
        
        self._process_request()
    
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
        self._handle_response()
        
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
        self._handle_response()
        
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
            
            self._channel.handle_read = self._read_additional_headers
            resp._additional_headers = ''
            self._channel.read_delimiter = CRLF
        
        else:
            self._channel.handle_read = self._read_chunk_body
            self._channel.read_delimiter = length + 2
    
    def _read_chunk_body(self, data):
        """
        Read a chunk body.
        """
        resp = self.current_response
    
        if resp._decompressor:
            resp.body += resp._decompressor.decompress(data[:-2])
        else:
            resp.body += data[:-2]
        
        self._channel.handle_read = self._read_chunk_head
        self._channel.read_delimiter = CRLF
        
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
            
            # Construct a HTTPResponse object.
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
                self._channel.handle_read = self._read_body
                self._channel.read_delimiter = int(headers['Content-Length'])
            
            elif 'Transfer-Encoding' in headers:
                if headers['Transfer-Encoding'] == 'chunked':
                    self._channel.handle_read = self._read_chunk_head
                    self._channel.read_delimiter = CRLF
                else:
                    raise BadRequest("Unsupported Transfer-Encoding: %s" % headers['Transfer-Encoding'])
            
            # Is this a HEAD request? If so, then handle the request NOW.
            if response.method == 'HEAD':
                self._handle_response()
        
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
            if self._channel:
                self._channel.close_immediately()
                self._channel = None

class ClientHelper(object):
    """
    This is returned by calls to HTTPClient.get and HTTPClient.post to allow
    you to decorate functions to be used as response handlers for specific
    requests.
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
    
    def _collect(self, response):
        self._responses.append(response)
    
    def fetch(self):
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
    Represents a single HTTP response.
    
    This class contains all the information received in a given HTTP response.
    """
    
    def __init__(self, client, request, http_version, status, status_text,
                    headers):
        """
        Initialize a HTTPResponse object.
        
        Args:
            client: The HTTPClient that received this response.
            request: The request list containing all the information passed
                to the call that generated the request.
            http_version: The HTTP protocol version used for this request.
            status: The HTTP status code of the response.
            status_text: A human readable status code.
            headers: The headers received with the response.
        """
        
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
        The cookies provided to the response.
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
        return "%s://%s%s" % (self.protocol, self.host, self.uri)
    
###############################################################################
# HTTPConnection Class
###############################################################################

class HTTPConnection(Connection):
    """
    Handles the connection between the HTTP server and the remove client,
    parsing headers and response bodies, and executing any received requests
    with the associated server's registered request handler.
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
        To be called when the current request is finished. Prepares the
        connection to take appropriate action when writing to the remote
        client has finished.
        """
        self._finished = True
        if not self.writable():
            self._request_finished()
    
    ##### Public Event Handlers ###############################################
    
    def handle_write(self, bytes_written=None):
        """
        If writing is finished, and the request is also finished, either closes
        the connection or, if keep-alive is supported, attempts to read another
        request.
        """
        if self._finished and not self.writable():
            self._request_finished()
    
    ##### Internal Event Handlers #############################################
    
    def _await_request(self):
        """
        Sets the read handler and read delimiter to prepare to read an HTTP
        request from the socket.
        """
        self.handle_read = self._read_header
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
            self.handle_read = None
            self.close()
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
            
            # Construct a HTTPRequest object.
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
                self.handle_read = self._read_request_body
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
            self.close()
        
        except Exception:
            log.exception('Error handling HTTP request.')
            self.write('HTTP/1.1 500 Internal Server Error%s' % DOUBLE_CRLF)
            self.close()
    
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
            self.close()
        
        except Exception:
            log.exception('Error handling HTTP request.')
            self.write('HTTP/1.1 500 Internal Server Error%s' % DOUBLE_CRLF)
            self.close()

###############################################################################
# HTTPRequest Class
###############################################################################

class HTTPRequest(object):
    """
    Represents a single HTTP request.
    
    This class contains all the information needed to respond to a valid HTTP
    request, as well as containing functions to assist in actually responding.
    """
    
    def __init__(self, connection, method, uri, http_version, headers=None,
                 protocol='http'):
        """
        Initialize an HTTPRequest object.
        
        Args:
            connection: The HTTPConnection that received this request.
            method: The HTTP method of the request.
            uri: The requested URI.
            http_version: The HTTP protocol version used for this request.
            headers: A dictionary of HTTP headers received for this connection.
                Optional.
            protocol: Either 'http' or 'https', depending on whether or not the
                connection that received this request is secure.
        """
        
        self.body       = ''
        self.connection = connection
        self.headers    = headers or {}
        self.method     = method
        self.protocol   = protocol
        self.uri        = uri
        self.version    = http_version
        
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
        attr = ('version','method','protocol','host','uri','path','time')
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
        The cookies provided to the request.
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
        Returns the time elapsed since the request was received, or the total
        processing time if the request has been finished.
        """
        if self._finish is None:
            return time() - self._start
        return self._finish - self._start
    
    ##### I/O Methods #########################################################
    
    def finish(self):
        """
        Close the response, allowing the underlying connection to either close
        the socket or begin listening for a new request.
        """
        self._finish = time()
        self.connection.finish()
    
    def send(self, data):
        """
        Write data to the client.
        
        Args:
            data: The data to be sent.
        """
        self.connection.write(data)
    
    def send_cookies(self, keys=None, end_headers=False):
        """
        Write the request's cookies to the client. If keys is specified, then
        only the listed cookies will be sent out. Otherwise, all cookies will
        be written to the client.
        
        Args:
            keys: The cookies to send.
            end_headers: If True, a double CRLF will be written at the end of
                the cookie headers to end them and tell the client to begin
                reading the response. If False, only a single CRLF will be
                used to end the headers.
        """
        if keys is None:
            out = self.cookie.output()
        else:
            out = []
            for k in keys:
                if not k in self.cookie:
                    continue
                out.append(self.cookie[k].output())
            out = CRLF.join(out)
        
        if end_headers:
            self.connection.write('%s%s' % (out, CRLF))
        else:
            self.connection.write(out)
    
    def send_headers(self, headers, end_headers=True):
        """
        Write a dict of HTTP headers to the client.
        
        Args:
            headers: A dict of HTTP headers to be sent to the client.
            end_headers: If True, a double CRLF will be written after the
                headers to end them and tell the client to expect a response.
                If False, only the provided headers will be written.
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
        
        if end_headers:
            append(CRLF)
        else:
            append('')
        
        self.connection.write(CRLF.join(out))
    
    def send_status(self, code=200):
        """
        Write an HTTP status line (the first line of the response) to the
        client, using the proper HTTP protocol version and a human readable
        message if one is known for the provided code.
        
        Args:
            code: The HTTP status code to write. Optional. Defaults to 200,
                which is OK.
        """
        try:
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
    An HTTP server, extending the default Server class.
    
    This class automatically uses an HTTPConnection connection class. Instead,
    its behavior is customized by providing a request handler function that is
    called whenever a connection is received and after all HTTP headers have
    been processed and validated.
    
    A server's behavior is defined almost entirely by its request_handler, and
    will not send any response unless the received HTTP headers are not valid.
    
    The following is an example that will display a very simple Hello World to
    any connecting clients:
    
        from pants.contrib.http import HTTPServer
        from pants import engine
        
        def handle_request(request):
            response = ''.join([
                '<!DOCTYPE html>',
                '<title>Hello, World!</title>',
                '<h1>Hello, World!</h1>',
                '<p>Your request was for <code>%s</code>.</p>' % request.uri
            ])
            
            request.write('HTTP/1.1 200 OK\r\n')
            request.write('Content-Type: text/html\r\n')
            request.write('Content-Length: %d\r\n\r\n' % len(response))
            request.write(response)
            request.finish()
        
        server = HTTPServer(handle_request)
        server.listen(80)
        
        engine.start()
    """
    ConnectionClass = HTTPConnection
    
    def __init__(self, request_handler, max_request=104857600, keep_alive=True,
                    ssl_options=None):
        """
        Initializes an HTTP server object.
        
        Args:
            request_handler: A callable that should accept a single parameter,
                that being an instance of the HTTPRequest class representing
                the current request.
            max_request: The maximum allowed length of an incoming HTTP request
                body, which is used for receiving HTTP POST data and uploaded
                files. Optional. Defaults to 10MB.
            keep_alive: If set to False, only one request will be allowed per
                connection. Optional.
            ssl_options: A dict of options for establishing SSL connections. If
                this is set, the server will be able to serve pages via HTTPS
                and not just HTTP. The keys and values provided should mimic
                the arguments taken by ssl.wrap_socket.
        """
        SSLServer.__init__(self, ssl_options=ssl_options)
        
        # Storage
        self.request_handler    = request_handler
        self.max_request        = max_request
        self.keep_alive         = keep_alive
    
    def listen(self, port=None, host='', backlog=1024):
        """
        Begins listening on the given host and port.
        
        Args:
            port: The port to listen on. Optional. If not specified, will be
                set to 80 for regular HTTP, or 443 if SSL options have been
                set.
            host: The hostname to listen on. Defaults to ''.
            backlog: The maximum number of queued connections. Defaults
                to 1024.
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

def content_type(filename):
    return mimetypes.guess_type(filename)[0] or 'application/octet-stream'

def encode_multipart(vars, files=None, boundary=None):
    """
    Encode a set of variables and/or files into a multipart/form-data request
    body.
    
    Args:
        vars: A dictionary of variables to encode.
        files: A dictionary of tuples of (filename, data) to encode. Optional.
        boundary: The boundary to use while encoding. Defaults to a crazy
            string that would probably never show up. If it does show up,
            however, you can set it here.
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
    Parse a multipart/form-data request body and modify the request's post
    and files dictionaries as is appropriate.
    
    Args:
        request: An HTTPRequest instance to receive any parsed data.
        boundary: The multipart/form-data boundary for splitting up parts.
        data: The data to parse.
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

def read_headers(data, d=None):
    """
    Read headers from the given data into the given header dictionary.
    
    Args:
        data: The data to parse headers from.
        d: The dictionary to store parsed headers into. A new dictionary is
            created if none is provided.
    
    Returns:
        A dictionary of parsed HTTP headers. Raises a BadRequest exception
        if the provided headers are invalid.
    """
    if d is None:
        d = {}
    
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
        
        if key in d:
            if key in COMMA_HEADERS:
                d[key] = '%s, %s' % (d[key], val)
            elif isinstance(d[key], list):
                d[key].append(val)
            else:
                d[key] = [d[key], val]
            continue
        d[key] = val
    
    return d
