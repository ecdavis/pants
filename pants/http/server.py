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
"""
``pants.http.server`` implements a lean HTTP server on top of Pants with
support for most of `HTTP/1.1 <http://www.w3.org/Protocols/rfc2616/rfc2616.html>`_,
including persistent connections. The HTTP server supports secure connections,
efficient transfer of files, and proxy headers. Utilizing the power of Pants,
it becomes easy to implement other protocols on top of HTTP such as
:mod:`WebSockets <pants.http.websocket>`.

The Server
==========

:class:`HTTPServer` is a subclass of :class:`pants.server.Server` that
implements the `HTTP/1.1 protocol <http://www.w3.org/Protocols/rfc2616/rfc2616.html>`_
via the class :class:`HTTPConnection`. Rather than specifying a custom
``ConnectionClass``, you implement your behavior with a ``request_handler``.
There will be more on request handlers below. For now, a brief example::

    from pants.http import HTTPServer
    from pants import Engine

    def my_handler(request):
        request.send_response("Hello World.")

    server = HTTPServer(my_handler)
    server.listen()
    Engine.instance().start()

In addition to specifying the request handler, there are a few other ways to
configure ``HTTPServer``.


Using HTTPServer Behind a Proxy
===============================

:class:`HTTPServer` has support for a few special HTTP headers that can be set
by proxy servers (notably ``X-Forwarded-For`` and ``X-Forwarded-Proto``) and it
can use ``X-Sendfile`` headers when sending files to allow the proxy server to
take care of static file transmission.

When creating your :class:`HTTPServer` instance, set ``xheaders`` to ``True``
to allow the server to automatically use the headers ``X-Real-IP``,
``X-Forwarded-For``, and ``X-Forwarded-Proto`` if they exist to set the
:class:`HTTPRequest`'s ``remote_ip`` and ``scheme``.

Sendfile is a bit more complex, with three separate variables for configuration.
To enable the ``X-Sendfile`` header, set ``sendfile`` to ``True`` when creating
your :class:`HTTPServer` instance. Alternatively, you may set it to a string to
have Pants use a string other than ``X-Sendfile`` for the header's name.

HTTPServer's ``sendfile_prefix`` allows you to set a prefix for the path written
to the ``X-Sendfile`` header. This is useful when using Pants behind nginx.

HTTPServer's ``file_root`` allows you to specify a root directory from which
static files should be located. This root path will be stripped from the file
paths before they're written to the ``X-Sendfile`` header. If ``file_root`` is
not set, the current working directory (as of the time :func:`HTTPRequest.send_file`
is called) will be used.

.. code-block:: python

    def my_handler(request):
        request.send_file('/srv/files/example.jpg')

    server = HTTPServer(my_handler, sendfile=True, sendfile_prefix='/_static/',
                        file_root='/srv/files')
    server.listen()

The above code would result in an HTTP response similar to:

.. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: image/jpeg
    Content-Length: 0
    X-Sendfile: /_static/example.jpg

Your proxy server would then be required to detect the ``X-Sendfile`` header
in that response and insert the appropriate content and headers.

.. note::

    The sendfile API is quite rough at this point, and is most likely going to
    be changed in future versions. It is possible to manually set the
    appropriate headers to handle sending files yourself if you require more
    control over the process.


Request Handlers
================

A request handler is a callable Python object, typically either a function or a
class instance with a defined ``__call__`` method. Request handlers are passed
an instance of :class:`HTTPRequest` representing the current request.

HTTPRequest instances contain all of the information that was sent with an
incoming request. The instances also have numerous methods for building
responses.

.. note::

    It is *not* required to finish responding to a request within the
    request handler.

Please see the documentation for the :class:`HTTPRequest` class below for more
information on what you can do.
"""

###############################################################################
# Imports
###############################################################################

import base64
import Cookie
import json
import mimetypes
import os
import pprint
import sys

from datetime import datetime, timedelta
from urlparse import parse_qsl

if sys.platform == "win32":
    from time import clock as time
else:
    from time import time

from pants.stream import Stream
from pants.server import Server

from pants.http.utils import BadRequest, CRLF, date, DOUBLE_CRLF, \
    generate_signature, HTTP, HTTPHeaders, log, parse_multipart, read_headers, \
    SERVER, WHITESPACE, parse_date

###############################################################################
# Exports
###############################################################################

__all__ = (
    "HTTPConnection", "HTTPRequest", "HTTPServer"
)

###############################################################################
# HTTPConnection Class
###############################################################################

class HTTPConnection(Stream):
    """
    This class implements the HTTP protocol on top of Pants. It specifically
    processes incoming HTTP requests and constructs an instance of
    :class:`HTTPRequest` before passing that instance to the associated
    :class:`HTTPServer`'s request handler.

    Direct interaction with this class is typically unnecessary, only becoming
    useful when implementing another protocol on top of HTTP, such as
    :mod:`WebSockets <pants.http.websocket>` or performing some other action
    that requires direct control over the underlying socket.
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
        This method should be called when the response to the current
        request has been completed, in preparation for either closing the
        connection or attempting to read a new request from the connection.

        This method is called automatically when you use the method
        :meth:`HTTPRequest.finish`.
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

            if self.current_request.protocol == 'HTTP/1.1':
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
                method, url, protocol = WHITESPACE.split(initial_line) #.split(' ')
            except ValueError:
                raise BadRequest('Invalid HTTP request line.')

            if not protocol.startswith('HTTP/'):
                raise BadRequest('Invalid HTTP protocol version.',
                                 code='505 HTTP Version Not Supported')

            # Parse the headers.
            if data:
                headers = read_headers(data)
            else:
                headers = {}

            # If we're secure, we're HTTPs.
            if self.ssl_enabled:
                scheme = 'https'
            else:
                scheme = 'http'

            # Construct an HTTPRequest object.
            self.current_request = request = HTTPRequest(self,
                method, url, protocol, headers, scheme)

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
                        protocol, DOUBLE_CRLF))

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
            return

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
    to build the appropriate response.

    HTTPRequest uses :class:`bytes` rather than :class:`str` unless otherwise
    stated, as network communications take place as bytes.
    """

    def __init__(self, connection, method, url, protocol, headers=None,
                 scheme='http'):
        self.body       = ''
        self.connection = connection
        self.method     = method
        self.url        = url
        self.protocol   = protocol
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
            self.scheme = self.headers.get('X-Forwarded-Proto', scheme)
        else:
            self.remote_ip = connection.remote_address
            if not isinstance(self.remote_ip, basestring):
                self.remote_ip = self.remote_ip[0]
            self.scheme   = scheme

        # Calculated Variables
        self.host       = self.headers.get('Host', '127.0.0.1')

        # Timing Information
        self._start     = time()
        self._finish    = None

        # Request Variables
        self.post       = {}
        self.files      = {}

        # Split the URL into usable information.
        self._parse_url()

    def __repr__(self):
        attr = ('protocol','method','scheme','host','url','path','time')
        attr = u', '.join(u'%s=%r' % (k,getattr(self,k)) for k in attr)
        return u'%s(%s, headers=%r)' % (
            self.__class__.__name__, attr, self.headers)

    def __html__(self):
        attr = ('protocol','method','remote_ip','scheme','host','url','path',
                'time')
        attr = u'\n    '.join(u'%-8s = %r' % (k,getattr(self,k)) for k in attr)

        out = u'<pre>%s(\n    %s\n\n' % (self.__class__.__name__, attr)

        for i in ('headers','get','post'):
            thing = getattr(self, i)
            if thing:
                if isinstance(thing, HTTPHeaders):
                    thing = dict(thing.iteritems())
                out += u'    %-8s = {\n %s\n        }\n\n' % (
                    i, pprint.pformat(thing, 8)[1:-1])
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
        The full url for this request. This is created by combining the
        :attr:`scheme`, :attr:`host`, and the :attr:`url`.
        """
        return '%s://%s%s' % (self.scheme, self.host, self.url)

    @property
    def is_secure(self):
        """
        Whether or not the request was received via HTTPS.
        """
        return self.scheme.lower() == 'https'

    @property
    def time(self):
        """
        The amount of time that has elapsed since the request was received. If
        the request has been finished already, this will be the total time that
        elapsed over the duration of the request.
        """
        if self._finish is None:
            return time() - self._start
        return self._finish - self._start

    ##### Secure Cookies ######################################################

    def set_secure_cookie(self, name, value, expires=30*86400, **kwargs):
        """
        Set a timestamp on a cookie and sign it, ensuring that it can't be
        altered by the client. To use this, the :class:`HTTPServer`
        *must* have a :attr:`~HTTPServer.cookie_secret` set.

        Cookies set with this function may be read with
        :meth:`get_secure_cookie`.

        If the provided value is a dictionary, list, or tuple the value will
        be serialized into JSON and encoded as UTF-8. Unicode strings will
        also be encoded as UTF-8. Byte strings will be passed as is. All other
        types will result in a :class:`TypeError`.

        =========  ===========  ============
        Argument   Default      Description
        =========  ===========  ============
        name                    The name of the cookie to set.
        value                   The value of the cookie.
        expires    ``2592000``  *Optional.* How long, in seconds, the cookie should last before expiring. The default value is equivalent to 30 days.
        =========  ===========  ============

        Additional arguments, such as ``path`` and ``secure`` may be set by
        providing them as keyword arguments. The ``HttpOnly`` attribute will
        be set by default on secure cookies..
        """
        if isinstance(value, (dict, list, tuple)):
            value = b"j" + json.dumps(value)
        elif isinstance(value, unicode):
            value = b"u" + value.encode("utf-8")
        elif not isinstance(value, str):
            raise TypeError("Invalid value for secure cookie: %r" % (value,))
        else:
            value = b"s" + value

        ts = str(int(time()))
        v = base64.b64encode(value)
        signature = generate_signature(
                        self.connection.server.cookie_secret, expires, ts, v)

        value = "%s|%d|%s|%s" % (value, expires, ts, signature)

        self.cookies_out[name] = value
        m = self.cookies_out[name]
        m['httponly'] = True

        if kwargs:
            for k, v in kwargs.iteritems():
                if k.lower() == 'httponly' and not v:
                    del m['httponly']
                else:
                    m[k] = v

        m['expires'] = expires

    def get_secure_cookie(self, name):
        """
        Return the signed cookie with the key ``name`` if it exists and has a
        valid signature. Otherwise, return None.
        """
        if not name in self.cookies:
            return None

        try:
            value, expires, ts, signature = self.cookies[name].value.rsplit('|', 3)
            expires = int(expires)
            ts = int(ts)
        except (AttributeError, ValueError):
            return None

        v = base64.b64encode(str(value))
        sig = generate_signature(self.connection.server.cookie_secret, expires, ts, v)

        if signature != sig or ts < time() - expires or ts > time() + expires:
            return None

        # Process value
        vtype = value[:1]
        if vtype == b"j":
            value = json.loads(value[1:])
        elif vtype == b"u":
            value = value[1:].decode("utf-8")
        else:
            value = value[1:]

        return value

    ##### I/O Methods #########################################################

    def finish(self):
        """
        This function should be called when the response has been completed,
        allowing the associated :class:`HTTPConnection` to
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

    def send_file(self, path, filename=None, guess_mime=True, headers=None):
        """
        Send a file to the client, given the path to that file. This method
        makes use of ``X-Sendfile``, if the :class:`~pants.http.server.HTTPServer`
        instance is configured to send X-Sendfile headers.

        If ``X-Sendfile`` is not available, Pants will make full use of caching
        headers, Ranges, and the `sendfile <http://www.kernel.org/doc/man-pages/online/pages/man2/sendfile.2.html>`_
        system call to improve file transfer performance. Additionally, if the
        client had made a ``HEAD`` request, the contents of the file will not
        be transferred.

        .. note::

            The request is finished automatically by this method.

        ===========  ========  ============
        Argument     Default   Description
        ===========  ========  ============
        path                   The path to the file to send. If this is a relative path, and the :class:`~pants.http.server.HTTPServer` instance has no root path for Sendfile set, the path will be assumed relative to the current working directory.
        filename     None      *Optional.* If this is set, the file will be sent as a download with the given filename as the default name to save it with.
        guess_mime   True      *Optional.* If this is set to True, Pants will attempt to set the ``Content-Type`` header based on the file extension.
        headers      None      *Optional.* A dictionary of HTTP headers to send with the file.
        ===========  ========  ============

        .. note::

            If you set a ``Content-Type`` header with the ``headers`` parameter,
            the mime type will not be used, even if ``guess_mime`` is True. The
            ``headers`` will also override any ``Content-Disposition`` header
            generated by the ``filename`` parameter.

        """
        self._started = True

        # The base path
        base = self.connection.server.file_root
        if not base:
            base = os.getcwd()

        # Now, the headers.
        if not headers:
            headers = {}

        # The Content-Disposition headers.
        if filename and not 'Content-Disposition' in headers:
            if not isinstance(filename, basestring):
                filename = str(filename)
            elif isinstance(filename, unicode):
                filename = filename.encode('utf8')

            headers['Content-Disposition'] = 'attachment; filename="%s"' % filename

        # The Content-Type header.
        if not 'Content-Type' in headers:
            if guess_mime:
                if not mimetypes.inited:
                    mimetypes.init()

                content_type = mimetypes.guess_type(path)[0]
                if not content_type:
                    content_type = 'application/octet-stream'

                headers['Content-Type'] = content_type

            else:
                headers['Content-Type'] = 'application/octet-stream'

        # If X-Sendfile is enabled, this becomes much easier.
        if self.connection.server.sendfile:
            # We don't want absolute paths, if we can help it.
            if os.path.isabs(path):
                rel = os.path.relpath(path, base)
                if not rel.startswith('..'):
                    path = rel

            # If we don't have an absolute path, append the prefix.
            if self.connection.server.sendfile_prefix and not os.path.isabs(path):
                path = os.path.join(self.connection.server.sendfile_prefix, path)

            if isinstance(self.connection.server.sendfile, basestring):
                headers[self.connection.server.sendfile] = path
            else:
                headers['X-Sendfile'] = path

            headers['Content-Length'] = 0

            # Now, pass it through and be done.
            self.send_status()
            self.send_headers(headers)
            self.finish()
            return

        # If we get here, then we have to handle sending the file ourself. This
        # gets a bit trickier. First, let's find the proper path.
        if not os.path.isabs(path):
            path = os.path.join(base, path)

        # Let's start with some information on the file.
        stat = os.stat(path)

        modified = datetime.fromtimestamp(stat.st_mtime)
        expires = datetime.utcnow() + timedelta(days=7)
        etag = '"%x-%x"' % (stat.st_size, int(stat.st_mtime))

        if not 'Last-Modified' in headers:
            headers['Last-Modified'] = date(modified)

        if not 'Expires' in headers:
            headers['Expires'] = date(expires)

        if not 'Cache-Control' in headers:
            headers['Cache-Control'] = 'max-age=604800'

        if not 'Accept-Ranges' in headers:
            headers['Accept-Ranges'] = 'bytes'

        if not 'ETag' in headers:
            headers['ETag'] = etag

        # Check request headers.
        not_modified = False

        if 'If-Modified-Since' in self.headers:
            try:
                since = parse_date(self.headers['If-Modified-Since'])
            except ValueError:
                since = None

            if since and since >= modified:
                not_modified = True

        if 'If-None-Match' in self.headers:
            values = self.headers['If-None-Match'].split(',')
            for val in values:
                val = val.strip()
                if val == '*' or etag == val:
                    not_modified = True
                    break

        # Send a 304 Not Modified, if possible.
        if not_modified:
            self.send_status(304)

            if 'Content-Length' in headers:
                del headers['Content-Length']

            if 'Content-Type' in headers:
                del headers['Content-Type']

            self.send_headers(headers)
            self.finish()
            return


        # Check for an If-Range header.
        if 'If-Range' in self.headers and 'Range' in self.headers:
            head = self.headers['If-Range']
            if head != etag:
                try:
                    match = parse_date(head) == modified
                except ValueError:
                    match = False

                if not match:
                    del self.headers['Range']

        # Open the file.
        if not os.access(path, os.R_OK):
            self.send_response('You do not have permission to access that file.', 403)
            return

        try:
            f = open(path, 'rb')
        except IOError:
            self.send_response('You do not have permission to access that file.', 403)
            return

        # If we have no Range header, just do things the easy way.
        if not 'Range' in self.headers:
            headers['Content-Length'] = stat.st_size

            self.send_status()
            self.send_headers(headers)

            if self.method != 'HEAD':
                self.connection.write_file(f)

            self.finish()
            return

        # Start parsing the Range header.
        length = stat.st_size
        start = length - 1
        end = 0

        try:
            if not self.headers['Range'].startswith('bytes='):
                raise ValueError

            for pair in self.headers['Range'][6:].split(','):
                pair = pair.strip()

                if pair.startswith('-'):
                    # Final x bytes.
                    val = int(pair[1:])
                    if val > length:
                        raise ValueError

                    end = length - 1

                    s = length - val
                    if s < start:
                        start = s

                elif pair.endswith('-'):
                    # Everything past x.
                    val = int(pair[:-1])
                    if val > length - 1:
                        raise ValueError

                    end = length - 1
                    if val < start:
                        start = val

                else:
                    s, e = map(int, pair.split('-'))
                    if start < 0 or start > end or end > length - 1:
                        raise ValueError

                    if s < start:
                        start = s

                    if e > end:
                        end = e

        except ValueError:
            # Any ValueErrors need to send a 416 error response.
            self.send_response('416 Requested Range Not Satisfiable', 416)
            return

        # Set the Content-Range header, and the Content-Length.
        total = 1 + (end - start)
        headers['Content-Range'] = 'bytes %d-%d/%d' % (start, end, length)
        headers['Content-Length'] = total

        # Now, send the response.
        self.send_status(206)
        self.send_headers(headers)

        if self.method != 'HEAD':
            if end == length - 1:
                total = 0

            self.connection.write_file(f, nbytes=total, offset=start)

        self.finish()


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

        if not 'date' in headers and self.protocol == 'HTTP/1.1':
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
                self.protocol, code, HTTP[code], CRLF))
        except KeyError:
            self.connection.write('%s %s%s' % (
                self.protocol, code, CRLF))

    write = send

    ##### Internal Event Handlers #############################################

    def _parse_url(self):
        # Do this ourselves because urlparse is too heavy.
        self.path, _, query = self.url.partition('?')
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
    extending the default :class:`~pants.server.Server` class.

    This class automatically uses the :class:`HTTPConnection` connection class.
    Rather than through specifying a connection class, its behavior is
    customized by providing a request handler function that is called whenever
    a valid request is received.

    A server's behavior is defined almost entirely by its request handler, and
    will not send any response by itself unless the received HTTP request is
    not valid or larger than the specified limit (which defaults to 10 MiB, or
    10,485,760 bytes).

    ================  ========  ============
    Argument          Default   Description
    ================  ========  ============
    request_handler             A callable that accepts a single argument. That argument is an instance of the :class:`HTTPRequest` class representing the current request.
    max_request       10 MiB    *Optional.* The maximum allowed length, in bytes, of an HTTP request body. This should be kept small, as the entire request body will be held in memory.
    keep_alive        True      *Optional.* Whether or not multiple requests are allowed over a single connection.
    cookie_secret     None      *Optional.* A string to use when signing secure cookies.
    xheaders          False     *Optional.* Whether or not to use ``X-Forwarded-For`` and ``X-Forwarded-Proto`` headers.
    sendfile          False     *Optional.* Whether or not to use ``X-Sendfile`` headers. If this is set to a string, that string will be used as the header name.
    sendfile_prefix   None      *Optional.* A string to prefix paths with for use in the ``X-Sendfile`` headers. Useful for nginx.
    file_root         None      *Optional.* The root path to send files from using :meth:`~pants.http.server.HTTPRequest.send_file`.
    ================  ========  ============
    """
    ConnectionClass = HTTPConnection

    def __init__(self, request_handler, max_request=10485760, keep_alive=True,
                    cookie_secret=None, xheaders=False, sendfile=False,
                    sendfile_prefix=None, file_root=None, **kwargs):
        Server.__init__(self, **kwargs)

        # Storage
        self.request_handler    = request_handler
        self.max_request        = max_request
        self.keep_alive         = keep_alive
        self.xheaders           = xheaders
        self.sendfile           = sendfile
        self.sendfile_prefix    = sendfile_prefix
        self.file_root          = os.path.abspath(file_root) if file_root else None

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
        default. Port 443 is selected if SSL has been enabled prior to the
        call to listen, otherwise port 80 will be used.

        .. seealso::

            See :func:`pants.server.Server.listen` for more information on
            listening servers.
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
