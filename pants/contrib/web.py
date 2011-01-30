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
import os
import re
import traceback
import urllib

from datetime import datetime
from pants import __version__ as pants_version
from http import HTTP, HTTPServer, HTTPRequest

try:
    import simplejson as json
except ImportError:
    import json

try:
    import magic
    m = magic.Magic(mime=True)
    def guess_type(filename):
        return m.from_file(filename)
except ImportError:
    import mimetypes
    def guess_type(filename):
        return mimetypes.guess_type(filename)[0]

__all__ = ('Application','HTTPException','HTTPTransparentRedirect','abort',
    'all_or_404','error','json_response','jsonify','redirect','url_for',
    'HTTPServer','FileServer')

###############################################################################
# Logging
###############################################################################
log = logging.getLogger('web')

###############################################################################
# Constants
###############################################################################

SERVER      = 'HTTPants (pants/%s)' % pants_version
SERVER_URL  = 'http://www.pantsweb.org/'

HAIKUS = {
    400: u'Something you entered<br>'
         u'transcended parameters.<br>'
         u'So much is unknown.',
    
    401: u'To access this page,<br>'
         u'one must know oneself; but then:<br>'
         u'inform the server.',
    
    403: u'Unfortunately,<br>'
         u'permissions insufficient.<br>'
         u'This, you cannot see.',
    
    404: u'You step in the stream,<br>'
         u'But the water has moved on.<br>'
         u'This page is not here.',
    
    410: u'A file that big?<br>'
         u'It might be very useful.<br>'
         u'But now it is Gone.',
    
    413: u'Out of memory.<br>'
         u'We wish to hold the whole sky,<br>'
         u'But we never will.',
    
    418: u'You requested coffee,<br>'
         u'it is neither short nor stout.<br>'
         u'I am a teapot.',
    
    500: u'Chaos reigns within.<br>'
         u'Reflect, repent, and reboot.<br>'
         u'Order shall return.'
}

if os.name == 'nt':
    HAIKUS[500] = (u'Yesterday it worked.<br>'
        u'Today, it is not working.<br>'
        u'Windows is like that.')

HTTP_MESSAGES = {
    401: u'You must sign in to access this page.',
    403: u'You do not have permission to view this page.',
    404: u'The page at <code>%(uri)s</code> cannot be found.',
    500: u'The server encountered an internal error and cannot display '
         u'this page.'
}

PAGE_CSS = u"""html, body {
    margin: 0; padding: 0;
    min-height: 100%%;
}

body {
    font-family: Calibri,"Trebuchet MS",sans-serif;
    background: #EEE;
    background-image: -webkit-gradient(
        linear, left bottom, left top,
        color-stop(0, rgb(204,204,204)),
        color-stop(0.5, rgb(238,238,238))
    );
}

a { color: #666; text-decoration: none; }
a:hover { color: #444; text-decoration: underline; }

h1 { margin: 0; color: #444; }
p { margin-bottom: 0; }
pre {
    display: block;
    text-align: left;
    background: #ddd;
    border-radius: 5px;
    padding: 5px;
    /*overflow-x: scroll;*/
}

table { width: 100%%; border-spacing: 0; }
td,th { margin: 0; padding: 2px 5px; text-align: right; }
tr td {
    color: #666;
    border-top: 1px solid transparent;
    border-bottom: 1px solid transparent;
}
tr:first-child td { border-top: none; }
tr:hover td { border-color: #ccc; }
th { border-bottom: 1px solid #ccc; }
th:first-child,td:first-child { text-align: left; }

.faint { color: #aaa; }

.haiku { margin-top: 20px; }
.haiku + p { color: #777; }

.left { text-align: left; }
.right { text-align: right; }
.center { text-align: center; }
.spacer { padding-top: 50px; }
.column { max-width: 1000px; min-width: 600px; margin: 0px auto; }
.footer {
    padding-top: 10px; color: #aaa;
    text-align: center;
}
.thingy {
    background: #FFF;
    background-image: -webkit-gradient(
        linear, left bottom, left top,
        color-stop(0, rgb(239, 239, 239)),
        color-stop(0.5, rgb(255,255,255))
    );
    
    color: #000;
    border: 5px #DDD solid;
    -moz-border-radius: 25px;
    border-radius: 25px;
    padding: 50px;
    margin: 0 50px;
    text-align: center;
}"""

DIRECTORY_PAGE = u"""<!DOCTYPE html>
<html><head><title>Index of %%s</title><style>%s</style></head><body>
<div class="column"><div class="spacer"></div><div class="thingy">
<h1>Index of %%s</h1>
%%s
<table><thead>
<tr><th style="width:50%%%%">Name</th>
<th>Size</th><th class="center" colspan="2">Last Modified</th></tr></thead>
%%s
</table>
</div><div class="footer"><i><a href="%s">%s</a><br>%%s</i></div>
<div class="spacer"></div>
</div></body></html>""" % (PAGE_CSS, SERVER_URL, SERVER)

ERROR_PAGE = u"""<!DOCTYPE html>
<html><head><title>%%d %%s</title><style>%s</style></head><body>
<div class="column"><div class="spacer"></div><div class="thingy">
<h1>%%d<br>%%s</h1>
%%s%%s
</div><div class="footer"><i><a href="%s">%s</a><br>%%s</i></div>
<div class="spacer"></div>
</div></body></html>""" % (PAGE_CSS, SERVER_URL, SERVER)

# Regular expressions used for various types.
REGEXES = {
    int     : '(-?\d+)',
    float   : '(-?\d+(?:\.\d+)?)',
}

###############################################################################
# Special Exceptions
###############################################################################

class HTTPException(Exception):
    """
    This exception will force the webserver to display an error page to the
    client of your choice.
    
    To invoke this, use the abort() helper.
    """
    def __init__(self, status=404, message=None, headers=None):
        self.status = status
        self.message = message
        self.headers = headers

class HTTPTransparentRedirect(Exception):
    """
    This exception will redirect the current request to the given URI in a way
    that's transparent to the client.
    """
    def __init__(self, uri):
        self.uri = uri

###############################################################################
# Application Class
###############################################################################

class Application(object):
    """
    An application is a HTTP server with routing logic, allowing you to easilly
    use more than one request handler.
    
    More than that, it makes it easy to send responses to the client by just
    returning values from your functions, rather than messing around with the
    write and finish functions of the request object.
    
    Instances of this class are callable and can be used as an HTTPServer's
    request handler. Example:
        
        from pants.contrib.http import HTTPServer
        from pants.contrib.web import Application
        from pants import engine
        
        app = Application()
        
        @app.route('/')
        def hello_world():
            return 'Hiya!'
        
        HTTPServer(app).listen()
        engine.start()
    """
    current_app = None
    
    def __init__(self, debug=False):
        """
        Initialize an Application instance.
        
        Args:
            debug: If debug is set to True, HTTP responses will include
                tracebacks when errors are encountered running routes. If it's
                False, then generic pages will be displayed and tracebacks
                will merely be logged. Defaults to False.
        """
        
        # Internal Stuff
        self._routes    = {}
        self._names     = {}
        
        # External Stuff
        self.debug = debug
    
    def run(self, port=80, host=''):
        """
        For testing, setup pants and go nuts. Example:
            
            from pants.contrib.web import *
            app = Application()
            
            @app.route("/")
            def hello():
                return "Hello, world!"
            
            app.run()
        
        Args:
            port: The port to listen on. Defaults to 80.
            host: The host to listen on. Optional.
        """
        from pants import engine
        HTTPServer(self).listen(port, host)
        engine.start()
    
    ##### Route Management Methods ############################################
    
    def basic_route(self, rule, methods=['GET','HEAD']):
        """
        This method is a decorator that registers a route without holding your
        hand about it.
        
        Using this decorator, rule must be a regular expression. And, when your
        view is called, it receives a single argument: the HTTPRequest that
        triggered the route.
        
        Example Usage:
            
            @app.basic_route("^/char/([^/]+)/$")
            def my_route(request):
                char, = request.match.groups()
                return 'The character is %s!' % char
        
        That's essentially equivilent to:
            
            @app.route("/char/<char>/")
            def my_route(char):
                return 'The character is %s!' % char
        
        In addition, url_for doesn't really know how to deal with these basic
        routes, so you should avoid using it with any basic routes that you
        create.
        """
        def decorator(func):
            self._insert_route(rule, func,
                "%s.%s" % (func.__module__,func.__name__), methods, None, None)
            return func
        return decorator
    
    def route(self, rule, name=None, methods=['GET','HEAD'], auto404=False):
        """
        This method is a decorator that's used to register a new request handler
        for a given URI rule. Example:
            
            @app.route("/")
            def index():
                return "Hello, World!"
        
        Variable parts in the route can be specified with inequality signs (for
        example: <variable_name>). By default, a variable part accepts any
        characters except a slash (/) and returns a string. However, you can
        specify a specific type to be returned by using <type:name>.
        
        Converters are simply callables that accept a string and return
        something. Built-in types, such as int and float, work well for this.
        So, for example, in:
            
            @app.route("/user/<int:id>/")
            def user(id):
                # Code Here
        
        The id is automatically converted to a number for you, and the view
        function is never even called if id isn't a valid number.
        
        View functions are easy to write, and are expected to return either a
        single value (a string or unicode value), or a tuple to the form of:
        body, status, headers. Status is an integer HTTP status code, and
        headers are a dictionary of optional HTTP headers to send with the
        response. You may also specify a status code and no headers.
        
        The following example returns a page with the 404 status code:
            
            @app.route("/nowhere")
            def nowhere():
                return 'This does not exist.', 404
        
        Args:
            rule: The URI rule to trigger this route. It's internally
                converted to regex for fast processing.
            name: A name to use for this route. If not specified, the name of
                the decorated function is used. Optional.
            methods: The HTTP methods valid for this route. Defaults to GET
                and HEAD.
            auto404: If this is True, all arguments to the view will be checked
                for truthiness, and if any fail, a 404 page will be displayed
                rather than your view function.
        """
        if callable(name):
            self._add_route(rule, name, None, methods, auto404)
            return
        
        def decorator(func):
            self._add_route(rule, func, name, methods, auto404)
            return func
        return decorator
    
    ##### Error Handlers ######################################################
    
    def handle_404(self, request, exception):
        if isinstance(exception, HTTPException):
            return error(exception.message, 404)
        return error(404)
    
    def handle_500(self, request, exception):
        log.error('Error handling HTTP request: %s %s\r\n%s',
            request.method, request.uri, traceback.format_exc())
        if not self.debug:
            return error(500)
        
        resp = (
            u"<h2>Traceback</h2>\n" +
            u"<pre>%s</pre>\n" % traceback.format_exc() +
            u"<h2>Route</h2>\n<pre>" +
            u"route name   = %r\n" % self._routes[request.route][1] +
            u"match groups = %r" % (request.match.groups(),) + 
            u"</pre>\n" + 
            u"<h2>HTTP Request</h2>\n" +
            request.__html__()
            )
        
        return error(resp, 500)
    
    ##### The Request Handler #################################################
    
    def __call__(self, request):
        """
        This function is responsible for determining what view to call, via
        regex matching of the uri, then calling that view, and processing the
        result into a suitable HTTP response.
        """
        Application.current_app = self
        self.request = request
        
        try:
            uri = request.uri
            ind = uri.find('?')
            if ind != -1:
                uri = uri[:ind]
            
            result = None
            for route in self._routes:
                match = route.match(uri)
                if match is None:
                    continue
                
                request.route = route
                request.match = match
                
                func, name, methods = self._routes[route][:3]
                if request.method not in methods:
                    result = error('The method %r is not allowed for %r.' % (
                        request.method, uri), 405, {'Allow': ', '.join(methods)}
                        )
                else:
                    try:
                        result = func(request)
                    except HTTPException, e:
                        if hasattr(self, 'handle_%d' % e.status):
                            result = getattr(self, 'handle_%d' % e.status)(
                                request, e)
                        else:
                            result = error(e.message, e.status, e.headers)
                    except HTTPTransparentRedirect, e:
                        request.uri = e.uri
                        request._parse_uri()
                        
                        del request.route
                        del request.match
                        
                        return self.__call__(request)
                    except Exception, e:
                        result = self.handle_500(request, e)
                break
            
            else:
                # No route found.
                if not uri.endswith('/'):
                    u = uri + '/'
                    for route in self._routes:
                        if route.match(u):
                            if ind != -1:
                                u += request.uri[ind:]
                            result = redirect(u)
                            break
                if result is None:
                    result = self.handle_404(request, None)
            
            if result is None or request._finish is not None:
                if request._finish is None:
                    request.finish()
                return
            
            # Parse the result.
            status = 200
            if isinstance(result, tuple):
                if len(result) == 3:
                    body, status, headers = result
                else:
                    body, status = result
                    headers = {}
            else:
                body = result
                headers = {}
            
            # Set a Content-Type header if there isn't one already.
            if not 'Content-Type' in headers:
                if (isinstance(body, basestring) and
                        body[:5].lower() in ('<html','<!doc')) or \
                        (hasattr(body, '__html__') and callable(body.__html__)):
                    headers['Content-Type'] = 'text/html'
                else:
                    headers['Content-Type'] = 'text/plain'
            
            # Convert the body to something we can send.
            if hasattr(body, '__html__'):
                body = body.__html__()
            
            if isinstance(body, unicode):
                encoding = headers['Content-Type']
                if encoding.find('charset=') != -1:
                    before, enc = encoding.split('charset=',1)
                else:
                    before = encoding.strip()
                    if before.endswith(';'):
                        before += ' '
                    else:
                        before += '; '
                    enc = 'UTF-8'
                
                body = body.encode(enc)
                headers['Content-Type'] = '%scharset=%s' % (before, enc)
            
            elif not isinstance(body, str):
                body = str(body)
            
            # Set some additional headers.
            headers['Content-Length'] = len(body)
            if not 'Date' in headers:
                headers['Date'] = datetime.utcnow().strftime(
                    "%a, %d %b %Y %H:%M:%S GMT")
            if not 'Server' in headers:
                headers['Server'] = SERVER
            
            # Send the response.
            request.send_status(status)
            request.send_headers(headers, False)
            
            if hasattr(request, '_rcookies'):
                request.send(request._rcookies.output())
            
            request.send('\r\n')
            
            if request.method != 'HEAD':
                request.write(body)
            
            request.finish()
        
        finally:
            request.route = None
            request.match = None
            
            self.request = None
            Application.current_app = None
    
    ##### Internal Methods and Event Handlers #################################
    
    def _insert_route(self, route, handler, name, methods, nms, namegen):
        if isinstance(route, basestring):
            route = re.compile(route)
        self._routes[route] = (handler, name, methods, nms, namegen)
        self._names[name] = route
    
    def _add_route(self, route, view, name=None, methods=['GET','HEAD'],
            auto404=False):
        """ See: Application.route """
        if name is None:
            if view is None:
                raise Exception('No name or view specified!')
            if hasattr(view, '__name__'):
                name = view.__name__
            elif hasattr(view, '__class__'):
                name = view.__class__.__name__
            else:
                raise NameError("Cannot find name for this route.")
        
        if not callable(view):
            raise Exception('View must be callable.')
        
        # Parse the route.
        regex, arguments, names, namegen = _route_to_regex(route)
        _regex = re.compile(regex)
        
        if not arguments:
            arguments = False
        
        def view_runner(request):
            request.__viewmodule__ = view.__module__
            match = request.match
            try:
                try:
                    view.func_globals['request'] = request
                except AttributeError:
                    view.__call__.func_globals['request'] = request
                if arguments is False:
                    return view()
                
                out = []
                for val,type in zip(match.groups(), arguments):
                    if type is not None:
                        try:
                            val = type(val)
                        except Exception:
                            return error('Unable to parse data %r.' % val, 400)
                    out.append(val)
                
                if auto404 is True:
                    all_or_404(*out)
                
                return view(*out)
            finally:
                try:
                    view.func_globals['request'] = None
                except AttributeError:
                    view.__call__.func_globals['request'] = None
        
        view_runner.__name__ = name
        self._insert_route(_regex, view_runner, "%s.%s" %(view.__module__,name),
            methods, names, namegen)

###############################################################################
# FileServer Class
###############################################################################

class FileServer(object):
    """
    The FileServer is a request handling class that, as it sounds, serves files
    to the client. It also supports the Content-Range header, HEAD requests,
    ETags, and last modified dates.
    
    It attempts to serve the files as efficiently as possible.
    
    Using it is simple. It only requires a single argument: the path to serve
    files from. You can also supply a list of default files to check to serve
    rather than a file listing.
    
    When used with an Application, the FileServer is not created in the usual
    way with the route decorator, but rather with a method of the FileServer
    itself. Example:
        
        FileServer("/tmp/path").attach(app)
    
    If you wish to listen on a path other than /static/, you can also use that
    when attaching:
        
        FileServer("/tmp/path").attach(app, "/files/")
    """
    def __init__(self, path, defaults=['index.html','index.html']):
        """
        Initialize the FileServer.
        
        Args:
            path: The path to serve.
            defaults: A list of default files, such as index.html.
        """
        self.path = os.path.normpath(os.path.realpath(path))
        self.defaults = defaults
    
    def attach(self, app, route='/static/'):
        """
        Attach this fileserver to an application, bypassing the usual route
        decorator to ensure things are done right.
        
        Args:
            app: The application to attach to.
            route: The path to listen on. Defaults to '/static/'.
        """
        route = re.compile("^%s(.*)$" % re.escape(route))
        app._insert_route(route, self, "FileServer", ['HEAD','GET'], None, None)
    
    def __call__(self, request):
        """
        Serve a request.
        """
        
        # Get the proper path.
        try:
            path = request.match.group(1)
        except (AttributeError,IndexError):
            path = request.path
        
        # Update the path.
        path = urllib.unquote(path)
        path = os.path.normpath(os.path.join(self.path, path))
        
        # Make sure we can access it.
        if not path.startswith(self.path):
            abort(403)
        if not os.path.exists(path):
            abort(404)
        
        # Is there a default?
        for f in self.defaults:
            full = os.path.join(path, f)
            if os.path.exists(full):
                request.path = full
                if hasattr(request, 'match'):
                    del request.match
                return self.__call__(request)
        
        # Is this a directory?
        if os.path.isdir(path):
            return self.list_directory(request, path)
        
        with open(path,'rb') as f:
            content = f.read()
        
        # Guess the Content-Type
        if path.endswith('.css'):
            type = 'text/css'
        elif path.endswith('.js'):
            type = 'application/javascript'
        else:
            type = guess_type(path)
        
        return content, 200, {'Content-Type':type}
    
    def list_directory(self, request, path):
        """
        Generate a directory listing and return it.
        """
        uri = request.path
        if not uri.startswith('/'):
            uri = '/%s' % uri
        if not uri.endswith('/'):
            return redirect('%s/' % uri)
        
        go_up = u''
        url = uri.strip('/')
        if url:
            url = url.rpartition('/')[0]
            go_up = u'<p><a href="..">Up to Higher Directory</a></p>' #% url
        
        files = []
        
        for p in sorted(os.listdir(path), key=str.lower):
            if p.startswith('.'):
                continue
            full = os.path.join(path, p)
            stat = os.stat(full)
            mtime = datetime.fromtimestamp(stat.st_mtime).strftime(
                '<td class="right">%Y-%m-%d</td><td class="left">%I:%M:%S %p</td>')
            
            if os.path.isdir(full):
                files.append('<tr><td><a href="%s%s/">%s</a></td>' % (
                    uri, p, p))
                files.append('<td class="faint">Directory</td>')
                files.append('%s</tr>' % mtime)
            else:
                size = _human_readable_size(stat.st_size)
                files.append('<tr><td><a href="%s%s">%s</a></td>' % (
                    uri, p, p))
                files.append('<td>%s</td>' % size)
                files.append('%s</tr>' % mtime)
        
        files = u''.join(files)
        
        return DIRECTORY_PAGE % (uri, uri, go_up, files, request.host), 200, {
            'Content-Type':'text/html; charset=utf-8'
        }
        
###############################################################################
# Private Helper Functions
###############################################################################

def path(st):
    return st
path.regex = "(.+?)"

def _get_thing(thing):
    if thing in globals():
        return globals()[thing]
    elif type(__builtins__) is dict and thing in __builtins__:
        return __builtins__[thing]
    elif hasattr(__builtins__, thing):
        return getattr(__builtins__, thing)
    return None

_route_parser = re.compile("<([^>]+)>([^<]*)")
def _route_to_regex(route):
    """ Parse a Flask-style route and return a regular expression, as well as
        a tuple of things for conversion. """
    regex, values, names, namegen = "", [], [], ""
    if not route.startswith("^/"):
        if route.startswith("/"):
            route = "^%s$" % route
        else:
            route = "^/%s$" % route
    
    # Find up to the first < and add it to regex.
    ind = route.find('<')
    if ind is -1:
        return route, tuple(), tuple(), route[1:-1]
    elif ind > 0:
        regex += route[:ind]
        namegen += route[:ind]
        route = route[ind:]
    
    # If the parser doesn't match, return.
    if not _route_parser.match(route):
        return regex+route, tuple(), tuple(), (regex+route)[1:-1]
    
    for match in _route_parser.finditer(route):
        group = match.group(1)
        if ':' in group:
            type, var = group.split(':', 1)
            thing = _get_thing(type)
            if not thing:
                raise Exception, "Invalid type declaration, %s" % type
            if hasattr(thing, 'regex'):
                regex += thing.regex
            elif thing in REGEXES:
                regex += REGEXES[thing]
            else:
                regex += "([^/]+)"
            values.append(thing)
            names.append(var)
        else:
            regex += "([^/]+)"
            values.append(None)
            names.append(group)
        namegen += "%s" + match.group(2)
        regex += match.group(2)
    
    return regex, tuple(values), tuple(names), namegen[1:-1]

_abbreviations = (
    (1<<50L, ' PB'),
    (1<<40L, ' TB'),
    (1<<30L, ' GB'),
    (1<<20L, ' MB'),
    (1<<10L, ' KB'),
    (1, ' B')
)
def _human_readable_size(size, precision=2):
    """ Convert a size to a human readable filesize. """
    if size == 0:
        return '0 B'
    
    for f,s in _abbreviations:
        if size >= f:
            break
    
    ip, dp = `size/float(f)`.split('.')
    if int(dp[:precision]):
        return  '%s.%s%s' % (ip,dp[:precision],s)
    return '%s%s' % (ip,s)

###############################################################################
# Public Helper Functions
###############################################################################

def abort(status=404, message=None, headers=None):
    """
    Raise an HTTPException to display an error page.
    """
    raise HTTPException(status, message, headers)

def all_or_404(*args):
    """
    If any of the provided arguments aren't truthy, raise a 404 exception.
    This is automatically called for you if you set auto404=True when using the
    route decorator.
    """
    all(args) or abort()

def error(message=None, status=None, headers=None):
    """
    Return a very simple error page, defaulting to a 404 Not Found error if
    no status code is supplied. Usually, you'll want to call abort() in your
    code, rather than error, to streamline the process of abandoning your code.
    Usage:
        
        return error(404)
        return error("Some message.", 404)
        return error("Blah blah blah.", 403, {'Some-Header':'Fish'})
    """
    request = Application.current_app.request
    
    if status is None:
        if type(message) is int:
            status = message
            message = None
        else:
            status = 404
    
    if not status in HTTP:
        status = 404
    title = HTTP[status]
    if not headers:
        headers = {}
    
    if message is None:
        if status in HTTP_MESSAGES:
            message = HTTP_MESSAGES[status] % request.__dict__
        else:
            message = u"An unspecified error has occured."
    
    haiku = u''
    if status in HAIKUS:
        haiku = u'<div class="haiku">%s</div>' % HAIKUS[status]
    
    if not message.startswith(u'<'):
        message = u'<p>%s</p>' % message
    
    result = u"".join([
        u"<html><head>",
        u"<title>%d %s</title>" % (status, title),
        u"<style>%s</style>" % PAGE_CSS,
        u"</head><body>",
        u'<div class="column">',
        u'<div class="spacer"></div><div class="thingy">',
        u"<h1>%d<br>%s</h1>" % (status, title.replace(' ','&nbsp;')),
        haiku, message,
        u"</div>",
        u'<div class="footer"><i><a href="%s">%s</a><br>%s</i></div>' % (
            SERVER_URL, SERVER, request.host),
        u'<div class="spacer"></div>',
        u'</div></body></html>'
        ])
    
    return result, status, headers

def json_response(object, status=200, headers=None):
    """
    Constructs a JSON response from a given object. You can also specify a
    HTTP status code and additional headers. Example:
        
        return json_response(["my","object","here"])
    
    Args:
        object: The object to return.
        status: The HTTP status code to send. Defaults to 200.
        headers: A dictionary of headers to send. Optional.
    """
    if not headers:
        headers = {}
    if not 'Content-Type' in headers:
        headers['Content-Type'] = 'application/json'
    
    return json.dumps(object), status, headers

def jsonify(*args, **kwargs):
    """
    Construct a JSON response using the provided arguments or keyword
    arguments. Somewhat less powerful than json_response, but providing a
    simple interface. Example:
        
        return jsonify(username="Stacy",
                       email="stacy@examples.com",
                       id=2)
    """
    if args:
        if kwargs:
            args = list(args) + [kwargs]
        kwargs = args
    return json.dumps(kwargs), 200, {'Content-Type':'application/json'}

def redirect(uri, status=302):
    """
    Construct a 302 Found response to instruct the client's browser to redirect
    its request to a different URL. Other codes may be returned by specifying a
    status.
    """
    return error(
        'The document you have requested is located at <a href="%s">%s</a>.' % (
            uri, uri), status, {'Location':uri})

def url_for(name, **values):
    """
    Generates a URL to the route with the given name. The name is relative to
    the module of the route function. Examples:
    
    View's Module | Target Endpoint | Target Function
    'test'        | 'index'         | 'index' function of 'test' module
    'test'        | '.who'          | First 'who' function of any module
    'test'        | 'admin.login'   | 'login' function of 'admin' module
    
    Provided values with unknown keys are added to the URL as query arugments.
    """
    app = Application.current_app
    request = app.request
    
    if name.startswith('.'):
        # Find it in the first possible place.
        name = name[1:]
        for n in app._names:
            module, nm = n.split('.',1)
            if nm == name:
                name = n
                break
    elif not '.' in name:
        # Find it in this module.
        name = "%s.%s" % (request.__viewmodule__, name)
    
    if not name in app._names:
        raise NameError("Cannot find route %r." % name)
    
    route = app._names[name]
    names, namegen = app._routes[route][-2:]
    
    out = []
    for n in names:
        out.append(str(values[n]))
        del values[n]
    out = tuple(out)
    
    if len(out) == 1:
        out = namegen % out[0]
    else:
        out = namegen % out
    out = urllib.quote(out)
    
    if '_external' in values:
        if values['_external']:
            out = '%s://%s%s' % (request.protocol, request.host, out)
        del values['_external']
    
    if values:
        out += '?%s' % urllib.urlencode(values)
    
    return out
