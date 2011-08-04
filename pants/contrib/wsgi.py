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

import cStringIO
import re
import sys
import traceback

from http import log
from web import error

###############################################################################
# WSGIConnector Class
###############################################################################

class WSGIConnector(object):
    """
    This class acts as a request handler for :class:`pants.contrib.http.HTTPServer`
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

    def attach(self, application, path, domain=None):
        """
        Attach the WSGIConnector to an instance of
        :class:`pants.contrib.web.Application` at the given route.

        ============  ========  ============
        Argument      Default   Description
        ============  ========  ============
        application             The :class:`~pants.contrib.web.Application` to attach to.
        path                    The path to serve requests from.
        domain        None      *Optional.* The domain to serve requests upon.
        ============  ========  ============
        """
        path = re.compile("^%s(.*)$" % re.escape(path))
        application._insert_route(
            path, self, domain, "WSGIConnector", ['HEAD','GET','POST','PUT'],
            None, None)

    def __call__(self, request):
        """
        Handle the given request.
        """
        # Make sure this plays nice with Web.
        request.auto_finish = False

        def start_response(status, head):
            request.send_status(status)
            if isinstance(head, list):
                head = dict(head)
            request.send_headers(head)

            return request.write

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

        if isinstance(request.connection.server.local_addr, tuple):
            environ['SERVER_PORT'] = request.connection.server.local_addr[1]

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
        except Exception, e:
            log.exception('Exception running WSGI application for: %s %s',
                request.method, request.path)

            if not self.debug:
                body, status, headers = error(500, request=request, debug=False)
            else:
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

        # Finish up anything in result.
        if result:
            try:
                for thing in result:
                    request.write(thing)
            finally:
                if hasattr(result, 'close'):
                    result.close()
                del result

        request.finish()
