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

import inspect
import traceback

from pants.http import HTTPServer
from pants.web.utils import *

try:
    import simplejson as json
except ImportError:
    import json

###############################################################################
# Application Class
###############################################################################

class Application(object):
    """
    The Application class builds upon :class:`pants.contrib.http.HTTPServer`,
    adding support for request routing, additional error handling, and a
    degree of convenience that makes writing dynamic pages easier.

    Instances of Application are callable, and may be used as a HTTPServer's
    request handler.

    ===============  ============
    Argument         Description
    ===============  ============
    default_domain   *Optional.* The default domain to search for a route for if the request's Host does not exist.
    debug            *Optional.* If this is set to True, automatically generated ``500 Internal Server Error`` response pages will include information about the failed request, including a traceback of the exception that caused the page to be generated.
    ===============  ============
    """
    current_app = None

    def __init__(self, default_domain=None, debug=False):
        # Internal Stuff
        self._routes    = {}
        self._names     = {}

        self._routes[None] = {}

        # External Stuff
        self.default_domain = default_domain
        self.debug = debug

    def run(self, addr=None, ssl_options=None):
        """
        This function exists for convenience, and when called creates a
        :class:`~pants.contrib.http.HTTPServer` instance with its request
        handler set to this application instance, calls
        :func:`~pants.contrib.http.HTTPServer.listen` on that HTTPServer, and
        finally, starts the Pants engine to process requests.

        ============  ============
        Argument      Description
        ============  ============
        port          *Optional.* The port to listen on. If this isn't specified, it will be either 80 or 443, depending on whether or not SSL options for the server have been provided.
        host          *Optional.* The host interface to listen on. If this isn't specified, listen on all interfaces.
        ssl_options   *Optional.* A dict of SSL options for the server. See :class:`pants.contrib.ssl.SSLServer` for more information.
        ============  ============
        """
        from pants import engine
        HTTPServer(self, ssl_options=ssl_options).listen(addr)
        engine.start()

    ##### Route Management Methods ############################################

    def basic_route(self, rule, name=None, methods=('GET','HEAD')):
        """
        The basic_route decorator registers a route with the Application without
        holding your hand over it.

        It functions almost the same as the :func:`Application.route` decorator,
        but doesn't wrap the provided function with any argument handling code.
        Instead, you're provided with the request object and the the regex
        match object.

        Example Usage::

            @app.basic_route("/char/<char>")
            def my_route(request):
                char, = request.match.groups()
                return 'The character is %s!' % char

        That is, essentially, equivilent to::

            @app.route("/char/<char>/")
            def my_route(char):
                return 'The character is %s!' % char

        =========  ============
        Argument   Description
        =========  ============
        rule       The route rule to match for a request to go to the decorated function. See :func:`Application.route` for more information.
        name       *Optional.* The name of the decorated function, for use with the :func:`url_for` helper function.
        methods    *Optional.* A list of HTTP methods to allow for this request handler. By default, only ``GET`` and ``HEAD`` requests are allowed, and all others will result in a ``405 Method Not Allowed`` error.
        =========  ============
        """
        def decorator(func):
            if rule[0] != '/':
                domain, _, _rule = rule.partition('/')
                _rule = '/' + rule
            else:
                domain = None
                _rule = rule

            regex, arguments, names, namegen = _route_to_regex(_rule)
            _regex = re.compile(regex)

            _name = name
            if _name is None:
                _name = "%s.%s" % (func.__module__, func.__name__)

            if not hasattr(func, 'content_type'):
                func.content_type = None

            self._insert_route(_regex, func, domain, _name, methods, names, namegen)
            return func
        return decorator

    def route(self, rule, name=None, methods=('GET','HEAD'), auto404=False,
              content_type=None):
        """
        The route decorator is used to register a new request handler with the
        Application instance. Example::

            @app.route("/")
            def hello_world():
                return "Hiya, Everyone!"

        Variables may be specified in the route *rule* by wrapping them with
        inequality signs (for example: ``<variable_name>``). By default, a
        variable part accepts any character except a slash (``/``) and returns
        a string value. However, you may specify a specific type to be returned
        by using the format ``<type:name>``, where type is the name of a
        callable in the pants.contrib.web namespace that accepts a single
        string as its argument, and returns a value. Built-in types, such as
        int and float, work well for this. Example::

            @app.route("/user/<int:id>/")
            def user(id):
                return "Hi, user %d!" % id

        The ``id`` is automatically converted into an integer for you, and as
        an added bonus, your function is never even called if the provided
        value for ``id`` isn't a valid number.

        Request handlers are easy to write and can send their output to the
        client simply by returning a value, such as a string::

            @app.route("/")
            def hello_world():
                return "Hiya, Everyone!"

        The previous code would result in a `200 OK`` response, with a
        ``Content-Type`` header of ``text/plain``, and a ``Content-Length``
        header of ``15``. With, of course, the body ``Hiya, Everyone!``.

        If the returned string begins with ``<!DOCTYPE`` or ``<html``, it will
        be assumed that the response is of ``Content-Type: text/html``.

        If a unicode object is returned, rather than a simple string, it will
        be automatically encoded and an encoding argument will be added to the
        ``Content-Type`` header.

        If a dictionary is returned, it will be automatically converted to a
        string of `JSON <http://en.wikipedia.org/wiki/JSON>`_ and the
        ``Content-Type`` header will be set to ``application/json``.

        If any other object is returned, it will be converted to a string
        via ``str()`` before any content headers are set. The exception to this
        is that, if the object has a ``__html__`` method, that method will be
        called rather than ``str()``, and the ``Content-Type`` will be
        automatically assumed to be ``text/html``, regardless of the actual
        content of the string.

        A tuple of ``(body, status)`` or ``(body, status, headers)`` may be
        returned, rather than simply a body, to set the HTTP status code of
        the result and additional response headers. If provided, ``status``
        must be an integer, and ``headers`` must be a dict.

        The following example returns a page with the status code ``404 Not Found``::

            @app.route("/nowhere")
            def nowhere():
                return "This does not exist.", 404

        =============  ============
        Argument       Description
        =============  ============
        rule           The route rule to be matched for the decorated function to be used for handling a request.
        name           *Optional.* The name of the decorated function, for use with the :func:`url_for` helper function.
        methods        *Optional.* A list of HTTP methods to allow for this request handler. By default, only ``GET`` and ``HEAD`` requests are allowed, and all others will result in a ``405 Method Not Allowed`` error.
        auto404        *Optional.* If this is set to True, all response handler arguments will be checked for truthiness (True, non-empty strings, etc.) and, if any fail, a ``404 Not Found`` page will be rendered automatically.
        content_type   *Optional.* If set, the ``Content-Type`` header will default to this unless returned as part of a header dict from the view function.
        =============  ============
        """
        if callable(name):
            self._add_route(rule, name, None, methods, auto404, content_type)
            return

        def decorator(func):
            self._add_route(rule, func, name, methods, auto404, content_type)
            return func
        return decorator

    ##### Error Handlers ######################################################

    def handle_404(self, request, exception):
        if isinstance(exception, HTTPException):
            return error(exception.message, 404, request=request)
        return error(404, request=request)

    def handle_500(self, request, exception):
        log.exception('Error handling HTTP request: %s %%s' % request.method,
            request.uri)
        if not self.debug:
            return error(500)

        resp = u''.join([
            u"<h2>Traceback</h2>\n",
            u"<pre>%s</pre>\n" % traceback.format_exc(),
            u"<h2>Route</h2>\n<pre>",
            u"route name   = %r\n" % request.route_name,
            u"match groups = %r" % (request.match.groups(),),
            u"</pre>\n",
            u"<h2>HTTP Request</h2>\n",
            request.__html__(),
            ])

        return error(resp, 500)

    ##### The Request Handler #################################################

    def __call__(self, request):
        """
        This function is called when a new request is received, and calls both
        :func:`Application.handle_request` and :func:`Application.handle_output`
        to process the request.
        """
        Application.current_app = self
        self.request = request

        try:
            request.auto_finish = True
            self.handle_output(*self.handle_request(request))
        finally:
            request.route = None
            request.match = None
            request.route_name = None

            Application.current_app = None
            self.request = None

    def handle_output(self, result, content_type):
        """ Process the output of handle_request. """
        request = self.request

        if not request.auto_finish or result is None or \
                request._finish is not None:
            if request.auto_finish and request._finish is None:
                request.finish()
            return

        status = 200
        if type(result) is tuple:
            if len(result) == 3:
                body, status, headers = result
            else:
                body, status = result
                headers = {}
        else:
            body = result
            headers = {}

        # Set a Content-Type header if there isn't already one.
        if not 'Content-Type' in headers:
            if content_type is not None:
                headers['Content-Type'] = content_type
            elif (isinstance(body, basestring) and
                    body[:5].lower() in ('<html','<!doc')) or \
                    hasattr(body, 'to_html'):
                headers['Content-Type'] = 'text/html'
            elif isinstance(body, dict):
                headers['Content-Type'] = 'application/json'
            else:
                headers['Content-Type'] = 'text/plain'

        # Convert the body to something sendable.
        try:
            body = body.to_html()
        except AttributeError:
            pass

        if isinstance(body, unicode):
            encoding = headers['Content-Type']
            if 'charset=' in encoding:
                before, sep, enc = encoding.partition('charset=')
            else:
                before = encoding
                sep = '; charset='
                enc = 'UTF-8'

            body = body.encode(enc)
            headers['Content-Type'] = '%s%s%s' % (before, sep, enc)

        elif isinstance(body, dict):
            try:
                body = json.dumps(body)
            except Exception, e:
                body, status, headers = self.handle_500(request, e)
                body = body.encode('utf-8')
                headers['Content-Type'] = 'text/html; charset=UTF-8'

        elif not isinstance(body, str):
            body = str(body)

        # More headers!
        headers['Content-Length'] = len(body)
        if not 'Date' in headers:
            headers['Date'] = date(datetime.utcnow())
        if not 'Server' in headers:
            headers['Server'] = SERVER

        # Send the response.
        request.send_status(status)
        request.send_headers(headers)

        if request.method == 'HEAD':
            request.finish()
            return

        request.write(body)
        request.finish()

    def handle_request(self, request):
        path = request.path

        # Domain Matching
        if len(self._routes) == 1:
            domain = None
        else:
            if request.host in self._routes:
                domain = request.host
            else:
                domain = '.' + request.host.partition('.')[2]
                if not domain in self._routes and ':' in request.host:
                    domain = request.host.rpartition(':')[0]
                    if not domain in self._routes:
                        domain = '.' + domain.partition('.')[2]
                if not domain in self._routes:
                    domain = self.default_domain

        for route in self._routes[domain]:
            match = route.match(path)
            if match is None:
                continue

            # Process this route.
            func, name, methods = self._routes[domain][route][:3]

            request.route = route
            request.match = match
            request.route_name = name

            if request.method not in methods:
                if request.method == 'OPTIONS':
                    methods = tuple(methods) + ('OPTIONS',)
                    return ('', 200, {'Allow': ', '.join(methods)}), None
                else:
                    return error(
                        'The method %s is not allowed for %r.' % (
                            request.method, path), 405, {
                                'Allow': ', '.join(methods)
                            }), None
            else:
                try:
                    return func(request), getattr(func, 'content_type', None)
                except HTTPException, e:
                    if hasattr(self, 'handle_%d' % e.status):
                        return getattr(self, 'handle_%d' % e.status)(request, e), None
                    else:
                        return error(e.message, e.status, e.headers), None
                except HTTPTransparentRedirect, e:
                    request.uri = e.uri
                    request._parse_uri()
                    return self.handle_request(request)
                except Exception, e:
                    return self.handle_500(request, e), None
        else:
            # No matching routes.
            if not path.endswith('/'):
                p = '%s/' % path
                for route in self._routes[domain]:
                    if route.match(p):
                        if request.query:
                            return redirect('%s?%s' % (p,request.query)), None
                        else:
                            return redirect(p), None

        return self.handle_404(request, None), None

    ##### Internal Methods and Event Handlers #################################

    def _insert_route(self, route, handler, domain, name, methods, nms, namegen):
        if isinstance(route, basestring):
            route = re.compile(route)
        if not domain in self._routes:
            self._routes[domain] = {}
        self._routes[domain][route] = (handler, name, methods, nms, namegen)
        self._names[name] = route

    def _add_route(self, route, view, name=None, methods=('GET','HEAD'),
            auto404=False, content_type=None):
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
        if route[0] != '/':
            domain, _, route = route.partition('/')
            route = '/' + route
        else:
            domain = None

        regex, arguments, names, namegen = _route_to_regex(route)
        _regex = re.compile(regex)

        if not arguments:
            arguments = False

        try:
            args = inspect.getargspec(view).args
        except TypeError:
            args = inspect.getargspec(view.__call__).args[1:]

        if len(args) == 1 and args[0] == 'request':
            def view_runner(request):
                request.__viewmodule__ = view.__module__
                match = request.match
                try:
                    if arguments is False:
                        return view(request)

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

                    request.arguments = out
                    return view(request)
                finally:
                    request.arguments = None

        else:
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
        view_runner.content_type = content_type
        self._insert_route(_regex, view_runner, domain,
            "%s.%s" %(view.__module__,name), methods, names, namegen)

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

_route_parser = re.compile(r"<([^>]+)>([^<]*)")
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

###############################################################################
# Public Helper Functions
###############################################################################

def abort(status=404, message=None, headers=None):
    """
    Raise a :class:`~pants.contrib.web.HTTPException` to display an error page.
    """
    raise HTTPException(status, message, headers)

def all_or_404(*args):
    """
    If any of the provided arguments aren't truthy, raise a ``404 Not Found``
    exception. This is automatically called for you if you set ``auto404=True``
    when using the route decorator.
    """
    all(args) or abort()

def error(message=None, status=None, headers=None, request=None, debug=None):
    """
    Return a very simple error page, defaulting to a ``404 Not Found`` error if
    no status code is supplied. Usually, you'll want to call :func:`~pants.contrib.web.abort`
    in your code, rather than error(), to streamline the process of abandoning
    your code. Usage::

        return error(404)
        return error("Some message.", 404)
        return error("Blah blah blah.", 403, {'Some-Header':'Fish'})
    """
    if request is None:
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
            dict = request.__dict__.copy()
            dict['uri'] = decode(urllib.unquote(dict['uri']))
            message = HTTP_MESSAGES[status] % dict
        else:
            message = u"An unspecified error has occured."

    haiku = u''
    if status in HAIKUS:
        haiku = u'<div class="haiku">%s</div>' % HAIKUS[status]

    if not message.startswith(u'<'):
        message = u'<p>%s</p>' % message

    if debug is None:
        debug = Application.current_app and Application.current_app.debug

    if debug:
        time = u'%0.3f ms' % (1000 * request.time)
    else:
        time = u''

    result = ERROR_PAGE % (status, title, status, title.replace(u' ',u'&nbsp;'),
        haiku, message, request.host, request.host, time)

    return result, status, headers

def redirect(uri, status=302):
    """
    Construct a ``302 Found`` response to instruct the client's browser to
    redirect its request to a different URL. Other codes may be returned by
    specifying a status.

    =========  ========  ============
    Argument   Default   Description
    =========  ========  ============
    uri                  The URI to redirect the client's browser to.
    status     ``302``   *Optional.* The status code to send with the response.
    =========  ========  ============
    """
    url = uri
    if isinstance(url, unicode):
        url = uri.encode('utf-8')

    return error(
        'The document you have requested is located at <a href="%s">%s</a>.' % (
            uri, uri), status, {'Location':url})

def url_for(name, **values):
    """
    Generates a URL to the route with the given name. The name is relative to
    the module of the route function. Examples:

    ==============  ================  ================
    View's Module   Target Endpoint   Target Function
    ==============  ================  ================
    ``test``        ``index``         ``test.index``
    ``test``        ``.who``          The first ``who`` function in *any* module.
    ``test``        ``admin.login``   ``admin.login``
    ==============  ================  ================

    Any value provided to the function with an unknown key is appended to the
    generated URL as query arguments. For example, take the following route::

        @app.route("/user/<int:id>/")
        def user_page(id):
            pass

    Assuming ``url_for`` is used within the same module, the following examples
    will hold true::

        >>> url_for("user_page", id=12)
        '/user/12/'

        >>> url_for("user_page", id=12, section=3)
        '/user/12/?section=3'

        >>> url_for("user_page", id=12, _external=True)
        'http://www.example.com/user/12/'

    As demonstrated above, the ``_external`` parameter is special, and will
    result in the generation of a full URL, using the scheme and host provided
    by the current request.

    *Note:* This function has not yet been updated to properly make use of
    domains.
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
