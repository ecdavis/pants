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

import cStringIO
import sys

from http import log

###############################################################################
# WSGIConnector Class
###############################################################################

class WSGIConnector(object):
    """
    Provides an interface for hosting WSGI apps with pants.contrib.http.
    
    The WSGIConnector class is a valid request_handler for the HTTPServer
    provided by http.contrib.http that calls a WSGI application to generate
    a response.
    """
    
    def __init__(self, application):
        """
        Initialize the WSGI connector.
        
        Args:
            application: The WSGI application that should be called to handle
                incoming requests.
        """
        self.app = application
    
    def __call__(self, request):
        """
        Handle the given request.
        """
        response = []
        status = '200 OK'
        headers = {}
        
        def start_response(status, head):
            status = status
            headers.update(head)
            return response.append
        
        # Build an environment for the WSGI application.
        environ = {
            'REQUEST_METHOD'    : request.method,
            'SCRIPT_NAME'       : '',
            'PATH_INFO'         : request.path,
            'QUERY_STRING'      : request.query,
            'SERVER_NAME'       : request.headers.get('Host','127.0.0.1'),
            'SERVER_PORT'       : request.connection.server.local_addr[1],
            'SERVER_PROTOCOL'   : request.version,
            'wsgi.version'      : (1,0),
            'wsgi.url_scheme'   : request.protocol,
            'wsgi.input'        : cStringIO.StringIO(request.body),
            'wsgi.errors'       : sys.stderr,
            'wsgi.multithread'  : False,
            'wsgi.multiprocess' : False,
            'wsgi.run_once'     : False
        }
        
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
            
            status = '500 Internal Server Error'
            result = []
            response = [
                '<!DOCTYPE html>',
                '<title>%s</title>' % status,
                '<h1>%s</h1>' % status,
                '<p>Your request cannot be completed.</p>'
                ]
            headers = {'Content-Type':'text/html'}
        
        # Finish up anything in result.
        try:
            response.extend(result)
        finally:
            if hasattr(result, 'close'):
                result.close()
            del result
        
        # Write the response.
        response = ''.join(response)
        if not 'Content-Length' in headers:
            headers['Content-Length'] = len(response)
        
        request.send_status(status)
        request.send_headers(headers)
        request.send(response)
        request.finish()
