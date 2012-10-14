###############################################################################
#
# Copyright 2011-2012 Pants Developers (see AUTHORS.txt)
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
import pprint

from urlparse import parse_qsl

from pants.http.utils import *

###############################################################################
# HTTPConnection Class
###############################################################################

class HTTPConnection(Stream):
    """
    Instances of this class represent connections received by an
    :class:`HTTPServer`, and perform all the actual logic of receiving and
    responding to an HTTP request.

    In order, this class is in charge of: reading HTTP request lines, reading
    the associated headers, reading any request body, and executing the
    appropriate request handler if the request is valid.

    You will almost never access this class directly.
    """
    def __init__(self, *args, **kwargs):
        Stream.__init__(self, *args, **kwargs)

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

        This function is called for you when you call
        :func:`HTTPRequest.finish() <pants.contrib.http.server.HTTPRequest.finish>`.
        """
        self.flush()
        self._finished = True
        if not self._send_buffer:
            self._request_finished()

    ##### Public Event Handlers ###############################################

    def on_write(self):
        if self._finished:
            self._request_finished()

    def on_close(self):
        # Clear the on_read method to ensure that the connection is collected
        # immediately.
        del self.on_read

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
            initial_line, _, data = data.partition(CRLF)

            try:
                method, uri, http_version = WHITESPACE.split(initial_line) #.split(' ')
            except ValueError:
                raise BadRequest('Invalid HTTP request line.')

            if not http_version.startswith('HTTP/'):
                raise BadRequest('Invalid HTTP protocol version.',
                                 code='505 HTTP Version Not Supported')

            # Parse the headers.
            if data:
                headers = read_headers(data)
            else:
                headers = {}

            # If we're secure, we're HTTPs.
            if self.ssl_enabled:
                protocol = 'https'
            else:
                protocol = 'http'

            # Construct an HTTPRequest object.
            self.current_request = request = HTTPRequest(self,
                method, uri, http_version, headers, protocol)

            # If we have a Content-Length header, read the request body.
            length = headers.get('Content-Length')
            if length:
                if not isinstance(length, int):
                    raise BadRequest(
                        'Provided Content-Length (%r) is invalid.' % length
                        )
                elif length > self.server.max_request:
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

        except BadRequest as err:
            log.info('Bad request from %r: %s',
                self.remote_address, err)
            
            self.write('HTTP/1.1 %s%s' % (err.code, CRLF))
            if err.message:
                self.write('Content-Type: text/html%s' % CRLF)
                self.write('Content-Length: %d%s' % (len(err.message),
                                                     DOUBLE_CRLF))
                self.write(err.message)
            else:
                self.write(CRLF)
            self.close()
            return

        except Exception as err:
            log.info('Exception handling request from %r: %s',
                self.remote_address, err)

            self.write('HTTP/1.1 500 Internal Server Error%s' % CRLF)
            self.write('Content-Length: 0%s' % DOUBLE_CRLF)
            self.close()

        try:
            # Call the request handler.
            self.server.request_handler(request)
        except Exception:
            log.exception('Error handling HTTP request.')
            if request._started:
                self.close(False)
            else:
                request.send_response("500 Internal Server Error", 500)
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
                    post = request.post
                    for key, val in parse_qsl(data, False):
                        if key in post:
                            if isinstance(post[key], list):
                                post[key].append(val)
                            else:
                                post[key] = [post[key], val]
                        else:
                            post[key] = val

                elif content_type.startswith('multipart/form-data'):
                    for field in content_type.split(';'):
                        key, _, value = field.strip().partition('=')
                        if key == 'boundary' and value:
                            parse_multipart(request, value, data)
                            break
                    else:
                        log.warning('Invalid multipart/form-data.')

        except BadRequest as err:
            log.info('Bad request from %r: %s',
                self.remote_address, err)

            request.send_response(err.message, err.code)
            self.close()
            return

        try:
            self.server.request_handler(request)
        except Exception:
            log.exception('Error handling HTTP request.')
            if request._started:
                self.close(False)
            else:
                request.send_response("500 Internal Server Error", 500)
                self.close()

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
        self.method     = method
        self.uri        = uri
        self.version    = http_version
        self._started   = False

        if headers is None:
            self.headers = {}
        else:
            self.headers = headers

        # X-Headers
        if connection.server.xheaders:
            remote_ip = self.headers.get('X-Real-IP')
            if not remote_ip:
                remote_ip = self.headers.get('X-Forwarded-For')
                if not remote_ip:
                    remote_ip = connection.remote_address
                    if not isinstance(remote_ip, basestring):
                        remote_ip = remote_ip[0]
                else:
                    remote_ip = remote_ip.partition(',')[0].strip()

            self.remote_ip = remote_ip
            self.protocol = self.headers.get('X-Forwarded-Proto', protocol)
        else:
            self.remote_ip = connection.remote_address
            if not isinstance(self.remote_ip, basestring):
                self.remote_ip = self.remote_ip[0]
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
                    i, pprint.pformat(getattr(self, i), 8)[1:-1])
            else:
                out += u'    %-8s = {}\n\n' % i

        if hasattr(self, '_cookies') and self.cookies:
            out += u'    cookies  = {\n'
            for k in self.cookies:
                out += u'        %r: %r\n' % (k, self.cookies[k].value)
            out += u'        }\n\n'
        else:
            out += u'    cookies  = {}\n\n'

        out += u'    files    = %s\n)</pre>' % \
            pprint.pformat(self.files.keys(), 0)
        return out

    ##### Properties ##########################################################

    @property
    def cookies(self):
        """
        An instance of :class:`Cookie.SimpleCookie` representing the cookies
        received with this request. Cookies being sent to the client with the
        response are stored in :attr:`cookies_out`.
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
    def cookies_out(self):
        """
        An instance of :class:`Cookie.SimpleCookie` to populate with cookies
        that should be sent with the response.
        """
        try:
            return self._cookies_out
        except AttributeError:
            self._cookies_out = cookies = Cookie.SimpleCookie()
            return cookies

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
        altered by the client. To use this, the :class:`~pants.contrib.http.HTTPServer`
        *must* have a ``cookie_secret`` set.

        Cookies set with this function may be read with
        :func:`~pants.contrib.http.HTTPServer.get_secure_cookie`.

        =========  ===========  ============
        Argument   Default      Description
        =========  ===========  ============
        name                    The name of the cookie to set.
        value                   The value of the cookie.
        expires    ``2592000``  *Optional.* How long, in seconds, the cookie should last before expiring. The default value is equivalent to 30 days.
        =========  ===========  ============

        Additional arguments, such as ``path`` and ``httponly`` may be set by
        providing them as keyword arguments.
        """
        ts = str(int(time()))
        v = base64.b64encode(str(value))
        signature = generate_signature(
                        self.connection.server.cookie_secret, expires, ts, v)

        value = "%s|%d|%s|%s" % (value, expires, ts, signature)

        self.cookies_out[name] = value
        m = self.cookies_out[name]

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
        except (AttributeError, ValueError):
            return None

        v = base64.b64encode(str(value))
        sig = generate_signature(self.connection.server.cookie_secret, expires, ts, v)

        if signature != sig or ts < time() - expires or ts > time() + expires:
            return None

        return value

    ##### I/O Methods #########################################################

    def finish(self):
        """
        This function should be called when the response has been completed,
        allowing the associated :class:`~pants.contrib.http.HTTPConnection` to
        either close the connection to the client or begin listening for a new
        request.

        Failing to call this function will drastically reduce the performance
        of the HTTP server, if it will work at all.
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
        self._started = True
        self.connection.write(data)

    def send_cookies(self, keys=None, end_headers=False):
        """
        Write any cookies associated with the request to the client. If any
        keys are specified, only the cookies with the specified keys will be
        transmitted. Otherwise, all cookies in :attr:`cookies_out` will be
        written to the client.

        This function is usually called automatically by send_headers.

        ============  ========  ============
        Argument      Default   Description
        ============  ========  ============
        keys          None      *Optional.* A list of cookie names to send.
        end_headers   False     *Optional.* If this is set to True, a double CRLF sequence will be written at the end of the cookie headers, signifying the end of the HTTP headers segment and the beginning of the response.
        ============  ========  ============
        """
        self._started = True
        if keys is None:
            if hasattr(self, '_cookies_out'):
                out = self.cookies_out.output()
            else:
                out = ''
        else:
            out = []
            for k in keys:
                if not k in self.cookies_out:
                    continue
                out.append(self.cookies_out[k].output())
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
        self._started = True
        out = []
        append = out.append
        if isinstance(headers, (tuple,list)):
            hv = headers
            headers = []
            for key, val in hv:
                headers.append(key.lower())
                append('%s: %s' % (key, val))
        else:
            hv = headers
            headers = []
            for key in hv:
                headers.append(key.lower())
                val = hv[key]
                if type(val) is list:
                    for v in val:
                        append('%s: %s' % (key, v))
                else:
                    append('%s: %s' % (key, val))

        if not 'date' in headers and self.version == 'HTTP/1.1':
            append('Date: %s' % date(datetime.utcnow()))

        if not 'server' in headers:
            append('Server: %s' % SERVER)

        if cookies and hasattr(self, '_cookies_out'):
            self.send_cookies()

        if end_headers:
            append(CRLF)
        else:
            append('')

        self.connection.write(CRLF.join(out))

    def send_response(self, content, code=200, content_type='text/plain'):
        """
        Write a very simple response, in one easy function. This function is
        for convenience, and allows you to send a basic response in one line.

        Basically, rather than::

            def request_handler(request):
                output = "Hello, World!"

                request.send_status(200)
                request.send_headers({
                    'Content-Type': 'text/plain',
                    'Content-Length': len(output)
                    })
                request.send(output)
                request.finish()

        You can simply::

            def request_handler(request):
                request.send_response("Hello, World!")

        =============  ===============  ============
        Argument       Default          Description
        =============  ===============  ============
        content                         A string of content to send to the client.
        code           ``200``          *Optional.* The HTTP status code to send to the client.
        content_type   ``text/plain``   *Optional.* The Content-Type header to send.
        =============  ===============  ============
        """
        self._started = True
        if not isinstance(content, str):
            content = str(content)

        self.send_status(code)
        self.send_headers({
            'Content-Type': content_type,
            'Content-Length': len(content)
            })
        self.send(content)
        self.finish()

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
        code       ``200``   *Optional.* The HTTP status code to send to the client.
        =========  ========  ============
        """
        self._started = True
        try:
            self.connection.write('%s %d %s%s' % (
                self.version, code, HTTP[code], CRLF))
        except KeyError:
            self.connection.write('%s %s%s' % (
                self.version, code, CRLF))

    write = send

    ##### Internal Event Handlers #############################################

    def _parse_uri(self):
        # Do this ourselves because urlparse is too heavy.
        self.path, _, query = self.uri.partition('?')
        self.query, _, self.fragment = query.partition('#')
        netloc = self.host.lower()

        # In-lined the hostname logic
        if '[' in netloc and ']' in netloc:
            self.hostname = netloc.split(']')[0][1:]
        elif ':' in netloc:
            self.hostname = netloc.split(':')[0]
        else:
            self.hostname = netloc

        self.get = get = {}
        if self.query:
            for key, val in parse_qsl(self.query, False):
                if key in get:
                    if isinstance(get[key], list):
                        get[key].append(val)
                    else:
                        get[key] = [get[key], val]
                else:
                    get[key] = val

###############################################################################
# HTTPServer Class
###############################################################################

class HTTPServer(Server):
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

    ================  ========  ============
    Argument          Default   Description
    ================  ========  ============
    request_handler             A callable that accepts a single argument. That argument is an instance of the :class:`HTTPRequest` class representing the current request.
    max_request       10 MiB    *Optional.* The maximum allowed length, in bytes, of an HTTP request body. This should be kept small, as the entire request body will be held in memory.
    keep_alive        True      *Optional.* Whether or not multiple requests are allowed over a single connection.
    cookie_secret     None      *Optional.* A string to use when signing secure cookies.
    xheaders          False     *Optional.* Whether or not to use ``X-Forwarded-For`` and ``X-Forwarded-Proto`` headers.
    ================  ========  ============
    """
    ConnectionClass = HTTPConnection

    def __init__(self, request_handler, max_request=10485760, keep_alive=True,
                    cookie_secret=None, xheaders=False, **kwargs):
        Server.__init__(self, **kwargs)

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

    def listen(self, address=None, backlog=1024, slave=True):
        """
        Begins listening for connections to the HTTP server.

        The given ``address`` is resolved, the server is bound to the address,
        and it then begins listening for connections. If an address isn't
        specified, the server will listen on either port 80 or port 443 by
        default.

        .. seealso::

            See :func:`pants.server.Server.listen` for more information on
            listening servers.

        =========  ============================================================
        Argument   Description
        =========  ============================================================
        address    *Optional.* The local address to listen for connections on.
                   If this isn't specified, it will be set to either port 80
                   or port 443, depending on the SSL state, and listen
                   on INADDR_ANY.
        backlog    *Optional.* The maximum size of the connection queue.
        slave      *Optional.* If True, this will cause a Server listening on
                   IPv6 INADDR_ANY to create a slave Server that listens on
                   the IPv4 INADDR_ANY.
        =========  ============================================================
        """
        if address is None or isinstance(address, (list,tuple)) and \
                              len(address) > 1 and address[1] is None:
            if self.ssl_enabled:
                port = 443
            else:
                port = 80

            if address is None:
                address = port
            else:
                address = tuple(address[0] + (port,) + address[2:])

        return Server.listen(self, address=address, backlog=backlog,
                                slave=slave)
