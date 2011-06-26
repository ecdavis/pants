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
    This class provides a simple interface for hosting WSGI compatible
    applications with the pants.contrib.http :class:`HTTPServer` by functioning
    as a valid request handler.

    When called, it constructs a proper environment for the WSGI call, and
    calls it within a try block to catch errors. A 500 Internal Server Error
    page is displayed if the WSGI application raises an error.

    ============  ============
    Argument      Description
    ============  ============
    application   The WSGI application that will handle incoming requests.
    debug         *Optional.* Whether or not to display tracebacks and additional information about a request within the output 500 Internal Server Error pages.
    ============  ============

    Example Usage::

        def application(environ, start_response):
            status = '200 OK'
            output = 'Pong!'

            response_headers = [('Content-type', 'text/plain'),
                                ('Content-Length', str(len(output)))]
            start_response(status, response_headers)
            return [output]

        from pants.contrib.http import HTTPServer
        from pants.contrib.wsgi import WSGIConnector
        from pants import engine

        HTTPServer(WSGIConnector(application)).listen()
        engine.start()
    """
    def __init__(self, application, debug=False):
        self.app = application
        self.debug = debug

    def attach(self, application, route):
        """
        Attach the WSGIConnector to an instance of
        :class:`pants.contrib.web.Application` at the given route.

        ============  ============
        Argument      Description
        ============  ============
        application   The :class:`Application` to attach to.
        route         The route for access to this WSGIConnector.
        ============  ============
        """
        route = re.compile("^%s(.*)$" % re.escape(route))
        application._insert_route(
            route, self, "WSGIConnector", ['HEAD','GET','POST','PUT'], None,
            None)

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
            'SERVER_PORT'       : request.connection.server.local_addr[1],
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

if __name__ == '__main__':
    from optparse import OptionParser
    from http import HTTPServer
    import logging
    import sys

    parser = OptionParser(usage="python -m pants.contrib.wsgi [options] module:callable")
    parser.add_option("-b", "--bind", dest="bind", default=":80",
        help="Bind the server to the given interface:port, or UNIX socket.")
    parser.add_option("-d", "--debug", dest="debug", action="store_true", default=False)

    options, args = parser.parse_args()

    # Zeroth, do debug stuff.
    if options.debug:
        logging.getLogger('').setLevel(logging.DEBUG)
    else:
        logging.getLogger('').setLevel(logging.INFO)

    # First, determine where to listen.
    bind = options.bind
    if ':' in bind:
        interface, _, port = bind.rpartition(':')
        try:
            port = int(port)
        except ValueError:
            print 'Invalid port.'
            sys.exit(1)
    else:
        port = bind
        interface = None

    if interface is None:
        print "UNIX sockets aren't supported yet."
        sys.exit(1)

    if not args or not ':' in args[0]:
        print "Must specify a module and callable to host as a WSGI application."
        sys.exit(1)

    module, _, call = args[0].partition(':')

    try:
        mod = __import__(module)
    except ImportError:
        print "Unable to import module %r." % module
        sys.exit(1)

    if not hasattr(mod, call):
        print "No such callable %r in module %r." % (call, module)
        sys.exit(1)

    # Start it up.
    conn = WSGIConnector(getattr(mod, call), options.debug)
    server = HTTPServer(conn).listen(port, interface)

    logging.info('Serving %s:%s to: %s' % (module, call, bind))

    from pants import engine
    engine.start()
