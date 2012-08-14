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

import cStringIO
import re
import sys
import traceback

from pants.web.application import error
from pants.web.utils import log

###############################################################################
# WSGIConnector Class
###############################################################################

class WSGIConnector(object):
    """
    This class acts as a request handler for :class:`pants.http.HTTPServer`
    and provides a simple interface for hosting `WSGI <http://en.wikipedia.org/wiki/WSGI>`_
    compatible applications.

    When called, it constructs a proper environment for the WSGI call, and
    calls it within a try block to catch errors. A ``500 Internal Server Error``
    page is displayed if an exception bubbles up from the WSGI application.

    ============  ============
    Argument      Description
    ============  ============
    application   The WSGI application that will handle incoming requests.
    debug         *Optional.* Whether or not to display tracebacks and additional information about a request within the output 500 Internal Server Error pages.
    ============  ============
    """
    def __init__(self, application, debug=False):
        self.app = application
        self.debug = debug

    def attach(self, application, rule, methods=('HEAD','GET','POST','PUT')):
        """
        Attach the WSGIConnector to an instance of
        :class:`pants.web.Application` at the given route.

        ============  ============
        Argument      Description
        ============  ============
        application   The :class:`~pants.web.Application` to attach to.
        rule          The path to serve requests from.
        methods       *Optional.* The HTTP methods to accept.
        ============  ============
        """
        if not rule.endswith('/'):
            rule += '/'

        application.basic_route(rule + '<regex("(.*)"):path>', methods=methods, func=self)

    def __call__(self, request):
        """
        Handle the given request.
        """
        # Make sure this plays nice with Web.
        request.auto_finish = False

        request._headers = None
        request._head_status = None
        request._chunk_it = False

        def write(data):
            if not request._started:
                # Before the first output, send the headers.
                # But before that, figure out if we've got a set length.
                for k,v in request._headers:
                    if k.lower() == 'content-length' or k.lower() == 'transfer-encoding':
                        break
                else:
                    request._headers.append(('Transfer-Encoding', 'chunked'))
                    request._chunk_it = True

                request.send_status(request._head_status)
                request.send_headers(request._headers)

            if request._chunk_it:
                request.write("%x\r\n%s\r\n" % (len(data), data))
            else:
                request.write(data)

        def start_response(status, head, exc_info=None):
            if exc_info:
                try:
                    if request._started:
                        raise exc_info[0], exc_info[1], exc_info[2]
                finally:
                    exc_info = None

            elif request._head_status is not None:
                raise RuntimeError("Headers already set.")

            if not isinstance(status, (int, str)):
                raise ValueError("status must be a string or int")
            if not isinstance(head, list):
                if isinstance(head, dict):
                    head = [(k,v) for k,v in head.iteritems()]
                else:
                    try:
                        head = list(head)
                    except ValueError:
                        raise ValueError("headers must be a list")

            request._head_status = status
            request._headers = head
            return write

        # Build an environment for the WSGI application.
        environ = {
            'REQUEST_METHOD'    : request.method,
            'SCRIPT_NAME'       : '',
            'PATH_INFO'         : request.path,
            'QUERY_STRING'      : request.query,
            'SERVER_NAME'       : request.headers.get('Host','127.0.0.1'),
            'SERVER_PROTOCOL'   : request.version,
            'REMOTE_ADDR'       : request.remote_ip,
            'GATEWAY_INTERFACE' : 'WSGI/1.0',
            'wsgi.version'      : (1,0),
            'wsgi.url_scheme'   : request.protocol,
            'wsgi.input'        : cStringIO.StringIO(request.body),
            'wsgi.errors'       : sys.stderr,
            'wsgi.multithread'  : False,
            'wsgi.multiprocess' : False,
            'wsgi.run_once'     : False
        }

        if isinstance(request.connection.server.local_address, tuple):
            environ['SERVER_PORT'] = request.connection.server.local_address[1]

        if hasattr(request, 'arguments'):
            environ['wsgiorg.routing_args'] = (request.arguments, {})
        elif hasattr(request, 'match'):
            environ['wsgiorg.routing_args'] = (request.match.groups(), {})

        if 'Content-Type' in request.headers:
            environ['CONTENT_TYPE'] = request.headers['Content-Type']
        if 'Content-Length' in request.headers:
            environ['CONTENT_LENGTH'] = request.headers['Content-Length']

        for k,v in request.headers.iteritems():
            environ['HTTP_%s' % k.replace('-','_').upper()] = v

        # Run the WSGI Application.
        try:
            result = self.app(environ, start_response)

            if result:
                try:
                    if isinstance(result, str):
                        write(result)
                    else:
                        for data in result:
                            if data:
                                write(data)
                finally:
                    try:
                        if hasattr(result, 'close'):
                            result.close()
                    except Exception:
                        log.warning("Exception running result.close() for: "
                                    "%s %s", request.method, request.path,
                            exc_info=True)
                    result = None

        except Exception:
            log.exception('Exception running WSGI application for: %s %s',
                request.method, request.path)

            # If we've started, bad stuff.
            if request._started:
                # We can't recover, so close the connection.
                if request._chunk_it:
                    request.write("0\r\n\r\n\r\n")
                request.connection.close(True)
                return

            # Use the default behavior if we're not debugging.
            if not self.debug:
                raise

            resp = u''.join([
                u"<h2>Traceback</h2>\n",
                u"<pre>%s</pre>\n" % traceback.format_exc(),
                u"<h2>HTTP Request</h2>\n",
                request.__html__(),
                ])
            body, status, headers = error(resp, 500, request=request,
                debug=True)

            request.send_status(500)

            if not 'Content-Length' in headers:
                headers['Content-Length'] = len(body)

            request.send_headers(headers)
            request.write(body)
            request.finish()
            return

        # Finish up here.
        if not request._started:
            write('')
        if request._chunk_it:
            request.write("0\r\n\r\n\r\n")

        request.finish()
