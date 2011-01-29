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

import logging
import time
import urlparse

from pants import Connection, Server

###############################################################################
# Logging
###############################################################################
log = logging.getLogger('http')

###############################################################################
# Constants
###############################################################################

COMMA_HEADERS = ('Accept', 'Accept-Charset','Accept-Encoding','Accept-Language',
    'Accept-Ranges', 'Allow', 'Cache-Control', 'Connection', 'Content-Encoding',
    'Content-Language', 'Expect', 'If-Match', 'If-None-Match', 'Pragma',
    'Proxy-Authenticate', 'TE', 'Trailer', 'Transfer-Encoding','Upgrade','Vary',
    'Via', 'Warning', 'WWW-Authenticate')

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
    
    def handle_write(self):
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
            
            # Construct a HTTPRequest object.
            self.current_request = request = HTTPRequest(self,
                method, uri, http_version, headers)
            
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
            headers: A dictionary of HTTP headers recieved for this connection.
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
        self._start     = time.time()
        self._finish    = None
        
        # Request Variables
        self.post       = {}
        self.files      = {}
        
        # Split the URI into usable information.
        self._parse_uri()
    
    ##### Properties ##########################################################
    
    @property
    def full_url(self):
        """
        The full URL used to generate the request.
        """
        return '%s://%s%s' % (self.protocol, self.host, self.uri)
    
    @property
    def time(self):
        """
        Returns the time elapsed since the request was recieved, or the total
        processing time if the request has been finished.
        """
        if self._finish is None:
            return time.time() - self._start
        return self._finish - self._start
    
    ##### I/O Methods #########################################################
    
    def finish(self):
        """
        Close the response, allowing the underlying connection to either close
        the socket or begin listening for a new request.
        """
        self._finish = time.time()
        self.connection.finish()
    
    def send(self, data):
        """
        Write data to the client.
        
        Args:
            data: The data to be sent.
        """
        self.connection.write(data)
    
    def send_headers(self, headers, end_headers=True):
        """
        Write a dict of HTTP headers to the client.
        
        Args:
            headers: A dict of HTTP headers to be sent to the client.
            end_headers: If True, a double CRLF will be written after the
                headers to end them and tell the client to expect a response.
                If False, only the provided headers will be written.
        """
        assert isinstance(headers, dict)
        
        for key, value in headers.iteritems():
            if isinstance(value, list) or isinstance(value, tuple):
                if key in COMMA_HEADERS:
                    self.connection.write('%s: %s%s' % (key,
                        ', '.join(str(v) for v in value), CRLF))
                else:
                    for val in value:
                        self.connection.write('%s: %s%s' % (key, val, CRLF))
            else:
                self.connection.write('%s: %s%s' % (key, value, CRLF))
        
        if end_headers:
            self.connection.write(CRLF)
    
    def send_status(self, code=200):
        """
        Write an HTTP status line (the first line of the response) to the
        client, using the proper HTTP protocol version and a human readable
        message if one is known for the provided code.
        
        Args:
            code: The HTTP status code to write. Optional. Defaults to 200,
                which is OK.
        """
        if code in HTTP:
            self.connection.write('%s %d %s%s' % (
                self.version, code, HTTP[code], CRLF))
            return
        
        self.connection.write('%s %s%s' % (self.version, code, CRLF))
    
    write = send
    
    ##### Internal Event Handlers #############################################
    
    def _parse_uri(self):
        scheme, loc, path, query, fragment = urlparse.urlsplit(self.uri)
        self.path       = path
        self.query      = query
        
        self.get = {}
        for key, values in urlparse.parse_qs(query, False).iteritems():
            self.get[key] = values
        
        for key in self.get:
            if len(self.get[key]) == 1:
                self.get[key] = self.get[key][0]
    
###############################################################################
# HTTPServer Class
###############################################################################

class HTTPServer(Server):
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
    
    def __init__(self, request_handler, max_request=104857600, keep_alive=True):
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
        """
        Server.__init__(self)
        
        # Storage
        self.request_handler    = request_handler
        self.max_request        = max_request
        self.keep_alive         = keep_alive
    
    def listen(self, port=80, host='', backlog=1024):
        """
        Begins listening on the given host and port.
        
        Args:
            port: The port to listen on. Defaults to 80 for regular HTTP.
            host: The hostname to listen on. Defaults to ''.
            backlog: The maximum number of queued connections. Defaults
                to 1024.
        """
        Server.listen(self, port, host, backlog)
    
###############################################################################
# Support Functions
###############################################################################

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
    
    # Clear off the nonsense. One CRLF only.
    data = data.rstrip(CRLF) + CRLF
    
    key = None
    for line in data.splitlines(True):
        if not line or not line.endswith(CRLF):
            raise BadRequest('HTTP header lines must end in CRLF.')
        
        # Check for multi-line nonsense.
        if line[0] in ' \t':
            # Continuation
            val = line.strip()
        else:
            try:
                key, val = line.split(':', 1)
            except ValueError:
                raise BadRequest('Illegal header line: %r' % line)
            
            key = key.strip()
            val = val.strip()
        
        if key in COMMA_HEADERS:
            if key in d:
                d[key] = '%s, %s' % (d[key], val)
                continue
        d[key] = val
    
    return d
