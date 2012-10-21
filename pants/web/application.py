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
This is the new and improved Application system for Pants. You'll note that the
design is pretty much `Flask <http://flask.pocoo.org/>`_, but without WSGI so
it should in theory perform faster.
"""

###############################################################################
# Imports
###############################################################################

import inspect
import re
import traceback
import weakref

from pants.http.server import HTTPServer
from pants.web.utils import *

try:
    import simplejson as json
except ImportError:
    import json

###############################################################################
# Constants
###############################################################################

RULE_PARSER = re.compile(r"<(?:([a-zA-Z_][a-zA-Z0-9_]+)(?:\(((?:\"[^\"]+\"|[^:>)]*)+)\))?:)?([a-zA-Z_][a-zA-Z0-9_]+)(?:=([^>]*))?>([^<]*)")
OPTIONS_PARSER = re.compile(r"""(?:(\w+)=)?(None|True|False|\d+\.\d+|\d+\.|\d+|"[^"]*?"|'[^']*?'|\w+)""", re.IGNORECASE)

###############################################################################
# JSONEncoder Class
###############################################################################

class JSONEncoder(json.JSONEncoder):
    """
    This subclass of JSONEncoder adds support for serializing datetime objects.
    """
    def default(self, o):
        if hasattr(o, 'isoformat'):
            return o.isoformat()
        return json.JSONEncoder.default(self, o)

###############################################################################
# Converter Class
###############################################################################

class Converter(object):
    """
    The Converter class is the base class for all the different value
    converters usable in routing rules.
    """
    def __init__(self, options, default):
        # Handle the options.
        self.default = default
        args, kwargs = [], {}
        if options:
            for key, val in OPTIONS_PARSER.findall(options):
                if val.lower() == 'none':
                    val = None
                elif val.lower() == 'true':
                    val = True
                elif val.lower() == 'false':
                    val = False
                else:
                    try:
                        val = int(val)
                    except ValueError:
                        try:
                            val = float(val)
                        except ValueError:
                            pass

                if isinstance(val, basestring):
                    val = val
                    if (val.startswith('"') and val.endswith('"')) or\
                       (val.startswith("'") and val.endswith("'")):
                        val = val[1:-1]

                if key:
                    kwargs[key] = val
                else:
                    args.append(val)

        # Now, configure it with those settings.
        self.configure(*args, **kwargs)

    def __repr__(self):
        out = ""
        if self.default:
            out += " default=" + repr(self.default)
        if hasattr(self, 'regex'):
            out += ' regex=' + repr(self.regex)
        if hasattr(self, 'namegen'):
            out += ' namegen=' + repr(self.namegen)
        return "<Converter[%s]%s>" % (self.__class__.__name__, out)

    def __call__(self, value):
        if not value:
            value = self.default
        return self.convert(value)

    def configure(self):
        """
        Placeholder. Override this function to configure the converter.
        """
        pass

    def convert(self, value):
        """
        Placeholder. Override this function to configure how the converter
        does its actual conversion.
        """
        return value


###############################################################################
# Built-In Converters
###############################################################################

CONVERTER_TYPES = {}

def register_converter(name=None, klass=None):
    """
    Register a converter with the given name. If a name is not provided, the
    class name will be converted to lowercase and used instead.
    """
    try:
        if issubclass(name, Converter):
            name, klass = None, name
    except TypeError:
        pass

    def decorator(klass):
        _name = name if name else klass.__name__.lower()
        CONVERTER_TYPES[_name] = klass
        return klass

    if klass:
        return decorator(klass)
    return decorator


@register_converter
class Regex(Converter):
    def configure(self, match, namegen=None):
        self.regex = match
        if namegen is not None:
            self.namegen = namegen


@register_converter
class Any(Converter):
    def configure(self, *choices):
        self.regex = "(%s)" % '|'.join(re.escape(x) for x in choices)

        if self.default is not None:
            dl = self.default.lower()
            for choice in choices:
                if choice.lower() == dl:
                    self.default = choice
                    break
            else:
                raise ValueError("Default value %r is not a valid "
                                 "choice." % self.default)


@register_converter
class DomainPart(Converter):
    def configure(self, min=None, max=None, length=None):
        if length is not None:
            min, max = length, length

        if min is None and max is None:
            self.regex = "([^/.]+)"
        elif min == max:
            self.regex = "([^/.]{%d})" % min
        elif max is None:
            self.regex = "([^/.]{%d,})" % min
        else:
            self.regex = "([^/.]{%d,%d})" % (min, max)


@register_converter
class Float(Converter):
    def configure(self, min=None, max=None):
        # Build the correct regex and namegens for our length.
        if min is None or min < 0:
            self.regex = "(-?\d+(?:\.\d+)?)"
        else:
            self.regex = "(\d+(?:\.\d+)?)"
        self.namegen = "%g"

        self.min = min
        self.max = max

    def convert(self, value):
        value = float(value)
        if (self.min is not None and value < self.min) or\
           (self.max is not None and value > self.max):
            raise ValueError("Value %d is out of range." % value)
        return value


@register_converter('int')
@register_converter
class Integer(Converter):
    def configure(self, digits=None, min=None, max=None):
        # Build the correct regex and namegen for our length.
        minus = "-?" if min is None or min < 0 else ""
        if digits:
            self.regex = "(%s\d{%d})" % (minus, digits)
            self.namegen = "%%.%dd" % digits
        else:
            self.regex = "(%s\d+)" % minus
            self.namegen = "%d"

        self.min = min
        self.max = max

    def convert(self, value):
        value = int(value)
        if (self.min is not None and value < self.min) or\
           (self.max is not None and value > self.max):
            raise ValueError("Value %d is out of range." % value)
        return value


@register_converter
class Path(Converter):
    regex = "(.+?)"


@register_converter
class String(Converter):
    def configure(self, min=None, max=None, length=None):
        if length is not None:
            min, max = length, length

        if min is None and max is None:
            self.regex = "([^/]+)"
        elif min == max:
            self.regex = "([^/]{%d})" % min
        elif max is None:
            self.regex = "([^/]{%d,})" % min
        else:
            self.regex = "([^/]{%d,%d})" % (min, max)


###############################################################################
# Module Class
###############################################################################

class Module(object):
    """
    TODO: Document this.
    """

    def __init__(self, name):
        # Internal Stuff
        self._routes = {}
        self._parents = set()

        # External Stuff
        self.name = name

    ##### Module Connection ###################################################

    def add(self, rule, module):
        if isinstance(module, Application):
            raise TypeError("Applications cannot be added as modules.")

        # TODO: Check for cyclic stuff.

        # Register this module with the child module.
        module._parents.add(self)

        if not '/' in rule:
            rule = '/' + rule
        self._routes[rule] = module

        # Now, recalculate.
        self._recalculate_routes()

    def _recalculate_routes(self):
        for parent in self._parents:
            parent._recalculate_routes()

    ##### Route Management Decorators #########################################

    def basic_route(self, rule, name=None, methods=('GET', 'HEAD'), func=None):
        """
        The basic_route decorator registers a route with the Module without
        holding your hand about it.

        It functions similarly to the :func:`Module.route` decorator, but it
        doesn't wrap the function with any argument processing code. Instead,
        the function is given the request object, and through it access to the
        regular expression match.

        Example Usage::

            @app.basic_route("/char/<char>")
            def my_route(request):
                char, = request.match.groups()
                return "The character is %s!" % char

        That is essentially equivalent to::

            @app.route("/char/<char>")
            def my_route(char):
                return "The character is %s!" % char

        .. note::

            Output is still handled the way it is with a normal route, so you
            can return strings and dictionaries as usual.

        =========  ============
        Argument   Description
        =========  ============
        rule       The route rule to match for a request to go to the decorated function. See :func:`Module.route` for more information.
        name       *Optional.* The name of the decorated function, for use with the :func:`url_for` helper function.
        methods    *Optional.* A list of HTTP methods to allow for this request handler. By default, only ``GET`` and ``HEAD`` requests are allowed, and all others will result in a ``405 Method Not Allowed`` error.
        func       *Optional.* The function for this view. Specifying the function bypasses the usual decorator-like behavior of this function.
        =========  ============
        """
        if not '/' in rule:
            rule = '/' + rule

        def decorator(func):
            if not callable(func):
                raise ValueError("Request handler must be callable.")

            if name is None:
                if hasattr(func, "__name__"):
                    _name = func.__name__
                elif hasattr(func, "__class__"):
                    _name = func.__class__.__name__
                else:
                    raise ValueError("Cannot find name for rule. Please "
                                     "specify name manually.")
            else:
                _name = name

            # Get the rule table for this rule.
            rule_table = self._routes.setdefault(rule, {})
            if isinstance(rule_table, Module):
                raise ValueError("The rule %r is claimed by a Module." % rule)

            # Now, for each method, store the data.
            for method in methods:
                rule_table[method] = (func, _name, False, None)

            # Recalculate routes and return.
            self._recalculate_routes()
            return func

        if func:
            return decorator(func)
        return decorator

    def route(self, rule, name=None, methods=('GET','HEAD'), auto404=False,
              func=None):
        """
        The route decorator is used to register a new route with the Module
        instance. Example::

            @app.route("/")
            def hello_world():
                return "Hiya, Everyone!"

        Variables may be specified in the route *rule* by wrapping them in
        inequality signs (for example: ``<variable_name>``). By default, a
        variable segment accepts any character except a slash (``/``) and
        returns the entire captured string. However, you may specify a
        converter function for processing the value before your view is called
        by using the format ``<converter:name>``, where *converter* is the name
        of the converter to use. As an example::

            @app.route("/user/<int:id>")
            def user(id):
                return "Hello, user %d." % id

        The ``id`` is automatically converted to an integer for you. This also
        serves to limit the URLs that will match a view. The rule
        ``"/user/<int:id>"`` will, for example, fail to match the URL
        ``"/user/stendec"`` as it only matches integer numbers.

        .. seealso::

            :func:`pants.web.application.register_converter`

        Request handlers are easy to write and can send their output to the
        client simply by returning a value, such as a string::

            @app.route("/")
            def example():
                return "Hello World!"

        The previous code would result in a ``200 OK`` response, with a
        ``Content-Type`` header of ``text/plain`` and a ``Content-Length``
        header of ``12``.

        If the returned string begins with ``<!DOCTYPE`` or ``<html`` it will
        be assumed that the ``Content-Type`` is ``text/html`` if one is not
        provided.

        If a unicode string is returned rather than a byte string, it will be
        automatically encoded, using the encoding specified in the
        ``Content-Type`` header. If there is no ``Content-Type`` header, or
        the ``Content-Type`` header has no encoding, the document will be
        encoded in ``UTF-8`` and the ``Content-Type`` header will be updated to
        reflect the encoding.

        Dictionaries, lists, and boolean values will be automatically converted
        to `JSON <http://en.wikipedia.org/wiki/JSON>`_ strings and the
        ``Content-Type`` header will be set to ``application/json``.

        If any other object is returned, the Application instance will attempt
        to cast it into a byte string using ``str(object)``. To provide custom
        behavior, an object may be given a ``to_html`` method, which will be
        called rather than ``str(object)``. If ``to_html`` is present, the
        ``Content-Type`` will be automatically assumed to be ``text/html``
        regardless of the actual content.

        A tuple of ``(body, status)`` or ``(body, status, headers)`` may be
        provided, rather than simply a body, to set the HTTP status code and
        additional headers to be sent with a response. If provided, ``status``
        may be an integer or byte string, and ``headers`` may be either a
        dictionary, or a list of ``[(heading, value), ...]``.

        The following example returns a page with the status code
        ``404 Not Found``::

            @app.route("/nowhere/")
            def nowhere():
                return "This does not exist.", 404

        =============  ============
        Argument       Description
        =============  ============
        rule           The route rule to be matched for the decorated function to be used for handling a request.
        name           *Optional.* The name of the decorated function, for use with the :func:`url_for` helper function.
        methods        *Optional.* A list of HTTP methods to allow for this request handler. By default, only ``GET`` and ``HEAD`` requests are allowed, and all others will result in a ``405 Method Not Allowed`` error.
        auto404        *Optional.* If this is set to True, all response handler arguments will be checked for truthiness (True, non-empty strings, etc.) and, if any fail, a ``404 Not Found`` page will be rendered automatically.
        func           *Optional.* The function for this view. Specifying the function bypasses the usual decorator-like behavior of this function.
        =============  ============
        """
        if not '/' in rule:
            rule = '/' + rule

        def decorator(func):
            if not callable(func):
                raise ValueError("Request handler must be callable.")

            if name is None:
                if hasattr(func, "__name__"):
                    _name = func.__name__
                elif hasattr(func, "__class__"):
                    _name = func.__class__.__name__
                else:
                    raise ValueError("Cannot find name for rule. Please "
                                     "specify name manually.")
            else:
                _name = name

            # Get the rule table for this rule.
            rule_table = self._routes.setdefault(rule, {})
            if isinstance(rule_table, Module):
                raise ValueError("The rule %r is claimed by a Module." % rule)

            # Now, for each method, store the data.
            for method in methods:
                rule_table[method] = (func, _name, True, auto404)

            # Recalculate and return.
            self._recalculate_routes()
            return func

        if func:
            return decorator(func)
        return decorator


###############################################################################
# Application Class
###############################################################################

class Application(Module):
    """
    The Application class builds upon the :class:`Module` class and acts as a
    request handler for the :class:`~pants.http.HTTPServer`, with request
    routing, error handling, and a degree of convenience that makes sending
    output easier.

    Instances of Application are callable, and should be used as a HTTPServer's
    request handler.

    =========  ================================================================
    Argument   Description
    =========  ================================================================
    debug      *Optional.* If this is set to True, the automatically generated
               ``500 Internal Server Error`` pages will display additional
               debugging information.
    =========  ================================================================
    """
    current_app = None

    def __init__(self, name=None, debug=False):
        super(Application, self).__init__(name)

        # Internal Stuff
        self._route_table = {}
        self._domains = []
        self._name_table = {}
        self._started = False

        # External Stuff
        self.json_encoder = JSONEncoder
        self.debug = debug
        self.fix_end_slash = False

    def run(self, address=None, ssl_options=None, engine=None):
        """
        This function exists for convenience, and when called creates a
        :class:`~pants.contrib.http.HTTPServer` instance with its request
        handler set to this application instance, calls
        :func:`~pants.contrib.http.HTTPServer.listen` on that HTTPServer, and
        finally, starts the Pants engine to process requests.

        ============  ============
        Argument      Description
        ============  ============
        address       *Optional.* The address to listen on. If this isn't specified, it will default to ``(INADDR_ANY, 80)``.
        ssl_options   *Optional.* A dict of SSL options for the server. See :class:`pants.contrib.ssl.SSLServer` for more information.
        engine        *Optional.* The :class:`pants.engine.Engine` instance to use.
        ============  ============
        """
        # Force routes to recalculate early.
        self._started = True
        self._recalculate_routes()

        if not engine:
            from pants.engine import Engine
            engine = Engine.instance()

        HTTPServer(self, ssl_options=ssl_options).listen(address)
        engine.start()

    ##### Error Handlers ######################################################

    def handle_404(self, request, err):
        if isinstance(err, HTTPException):
            return error(err.message, 404, request=request)
        return error(404, request=request)

    def handle_500(self, request, err):
        log.exception("Error handling HTTP request: %s %s" %
                      (request.method, request.uri))
        if not self.debug:
            return err(500, request=request)

        response = u"\n".join([
            u"<h2>Traceback</h2>",
            u"<pre>%s</pre>" % traceback.format_exc(),
            #u'<div id="console"><h2>Console</h2>',
            #u'<pre id="output"></pre>',
            #u'<script type="text/javascript">%s</script></div>' % CONSOLE_JS,
            u"<h2>Route</h2>",
            u"<pre>route name   = %r" % request.route_name,
            u"match groups = %r</pre>" % (request.match.groups(),),
            u"<h2>HTTP Request</h2>",
            request.__html__()
        ])

        return error(response, 500, request=request)

    ##### Routing Table Builder ###############################################

    def _recalculate_routes(self, path=None, module=None, nameprefix=None):
        """
        This function does the heavy lifting of building the routing table,
        and it's called every time a route is updated. Fortunately, that
        pretty much never happens after application startup.
        """
        if not self._started:
            return

        if path is None:
            self._route_table = {}
            self._name_table = {}
            self._domains = []

        # Get the proper route table.
        routes = module._routes if module else self._routes

        # Do name stuff.
        if not nameprefix:
            if module:
                nameprefix = module.name
            else:
                nameprefix = self.name
        else:
            if module:
                nameprefix += '.' + module.name
            else:
                nameprefix += '.' + self.name

        # Now, iterate through it.
        for rule, table in routes.iteritems():
            if isinstance(table, Module):
                self._recalculate_routes(rule, table, nameprefix)
                continue

            # If there is a path, and this rule doesn't have a domain, merge
            # them.
            if path and (not '/' in rule or rule[0] == '/'):
                if path.endswith('/'):
                    if rule[0] == '/':
                        rule = path + rule[1:]
                    else:
                        rule = path + rule
                else:
                    if rule[0] == '/':
                        rule = path + rule
                    else:
                        rule = path + '/' + rule

            # Process the rule.
            regex, converters, names, namegen, domain, rpath = _rule_to_regex(rule)
            domain = domain.lower()

            # If this is a new domain, add it to the domain table.
            if not domain in self._domains:
                self._domains.append(domain)

            # If this is a new path, add it to the path table for that domain.
            rt = self._route_table.setdefault(domain, {})
            pt = rt.setdefault(None, [])
            if not rpath in pt:
                pt.append(rpath)

            # Now, get the rule table.
            if not rpath in rt:
                rt[rpath] = [re.compile(regex), None, {}, names, namegen, converters]
            rule_table = rt[rpath][2]

            # Iterate through all the methods.
            for method, (func, name, advanced, auto404) in table.iteritems():
                method = method.upper()
                if method == 'GET' or rt[rpath][1] is None:
                    if nameprefix:
                        name = nameprefix + '.' + name
                    rt[rpath][1] = name
                if advanced:
                    for mthd in rule_table:
                        if table[mthd][0] is func:
                            rule_table[method] = rule_table[mthd]
                            break
                    else:
                        rule_table[method] = _get_runner(func, converters, auto404)
                else:
                    rule_table[method] = func

            # Update the name table.
            self._name_table[rt[rpath][1]] = domain, rpath

        if path is None:
            # Sort everything.
            self._domains.sort(key=len, reverse=True)

            for v in self._route_table.itervalues():
                v[None].sort(key=len, reverse=True)

    ##### The Request Handler #################################################

    def __call__(self, request):
        """
        This function is called when a new request is received, and uses the
        method :meth:`Application.route_request` to select and execute the
        proper request handler, and then the method
        :meth:`Application.parse_output` to process the handler's output.
        """
        if not self._started:
            self._started = True
            self._recalculate_routes()

        Application.current_app = self
        self.request = request

        try:
            request.auto_finish = True
            self.parse_output(self.route_request(request))
        finally:
            request.route = None
            request.match = None
            request.route_name = None

            Application.current_app = None
            self.request = None

    def route_request(self, request):
        """
        Determine which request handler to use for the given request, execute
        that handler, and return its output.
        """
        domain = request.hostname
        path = request.path
        matcher = domain + path
        available_methods = set()

        for dmn in self._domains:
            if ':' in dmn:
                if not request.host.lower().endswith(dmn):
                    continue
            elif not domain.endswith(dmn):
                continue

            dmn = self._route_table[dmn]
            for pth in dmn[None]:
                if not path.startswith(pth):
                    continue

                regex, name, methods = dmn[pth][:3]
                match = regex.match(matcher)
                if match is None:
                    continue

                method = request.method.upper()
                if not method in methods:
                    available_methods.update(methods)
                    continue

                request.route_name = name
                request.match = match

                try:
                    return methods[method](request)
                except HTTPException as err:
                    if hasattr(self, "handle_%d" % err.status):
                        return getattr(self, "handle_%d" % err.status)(request, err)
                    else:
                        return error(err.message, err.status, err.headers, request=request)
                except HTTPTransparentRedirect as err:
                    request.uri = err.uri
                    request._parse_uri()
                    return self.route_request(request)
                except Exception as err:
                    return self.handle_500(request, err)

        if available_methods:
            if request.method == 'OPTIONS':
                return '', 200, {'Allow': ', '.join(available_methods)}
            else:
                return error(
                    "The method %s is not allowed for %r." %
                    (request.method, path), 405,
                    {'Allow': ', '.join(available_methods)}
                )
        elif self.fix_end_slash:
            # No matching routes.
            if not path.endswith('/'):
                path += '/'
                matcher += '/'
                for dmn in self._domains:
                    if not domain.endswith(dmn):
                        continue

                    dmn = self._route_table[dmn]
                    for pth in dmn[None]:
                        if not path.startswith(pth):
                            continue

                        if dmn[path][0].match(matcher):
                            if request.query:
                                return redirect("%s?%s" % (path, request.query))
                            else:
                                return redirect(path)

        return self.handle_404(request, None)

    def parse_output(self, result):
        """ Process the output of :meth:`Application.route_request`. """
        request = self.request

        if not request.auto_finish or result is None or \
                request._finish is not None:
            if request.auto_finish and request._finish is None:
                request.finish()
            return

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
            if isinstance(body, basestring) and body[:5].lower() in ('<html', '<!doc') or hasattr(body, 'to_html'):
                headers['Content-Type'] = 'text/html'
            elif isinstance(body, (list, dict)):
                headers['Content-Type'] = 'application/json'
            else:
                headers['Content-Type'] = 'text/plain'

        # Convert the body to something that we can send.
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
            headers['Content-Type'] = before + sep + enc

        elif isinstance(body, (list,dict)):
            try:
                body = json.dumps(body, cls=self.json_encoder)
            except Exception as err:
                body, status, headers = self.handle_500(request, err)
                body = body.encode('utf-8')
                headers['Content-Type'] = 'text/html; charset=UTF-8'

        elif not isinstance(body, str):
            body = str(body)

        # More headers!
        headers['Content-Length'] = len(body)

        # Send the response.
        request.send_status(status)
        request.send_headers(headers)

        if request.method.upper() == 'HEAD':
            request.finish()
            return

        request.write(body)
        request.finish()


###############################################################################
# Private Helper Functions
###############################################################################

def _get_runner(func, converters, auto404):
    try:
        args = inspect.getargspec(func).args
    except TypeError:
        args = inspect.getargspec(func.__call__).args

    if len(args) == 1 and args[0] == 'request':
        def view_runner(request):
            request.__func_module = func.__module__
            match = request.match

            if not converters:
                return func(request)

            out = []
            for val, converter in zip(match.groups(), converters):
                if type is not None:
                    try:
                        val = converter(val)
                    except Exception:
                        return error("Unable to parse data %r." % val, 400)
                out.append(val)

            if auto404:
                all_or_404(*out)

            try:
                request.arguments = out
                return func(request)
            finally:
                request.arguments = None
    else:
        def view_runner(request):
            request.__func_module = func.__module__
            match = request.match

            try:
                try:
                    func.func_globals['request'] = request
                except AttributeError:
                    func.__call__.func_globals['request'] = request

                if not converters:
                    return func()

                out = []
                for val, converter in zip(match.groups(), converters):
                    if type is not None:
                        try:
                            val = converter(val)
                        except Exception:
                            return error("Unable to parse data %r." % val, 400)
                    out.append(val)

                if auto404:
                    all_or_404(*out)

                return func(*out)

            finally:
                try:
                    func.func_globals['request'] = None
                except AttributeError:
                    func.__call__.func_globals['request'] = None

    return view_runner

def _rule_to_regex(rule):
    """
    Parse a rule and return a regular expression, as well as converters for
    value conversion and default values.
    """
    regex, converters, names, namegen, domain, path = "", [], [], "", "", ""

    # Make sure we have at least one /.
    if not '/' in rule:
        rule = '/' + rule

    in_domain = True

    # Handle the beginning of the string.
    if rule[0] == '.':
        regex += '[^./]+?'
    elif rule[0] == '/':
        regex += '[^/]+?'

    # Find the first <.
    ind = rule.find("<")
    if ind == -1:
        if '/' in rule:
            domain, _, path = rule.partition('/')
            path = '/' + path
            regex += re.escape(domain) + "(?::\d+)?" + re.escape(path) + "$"
        else:
            regex += re.escape(rule) + "$"

        # There are no variables to match. Tough luck.
        return "^" + regex, tuple(), tuple(), rule, domain, path
    elif ind > 0:
        text = rule[:ind]
        rule = rule[ind:]

        if '/' in text:
            in_domain = False
            domain, _, path = text.partition('/')
            path = '/' + path
            regex += re.escape(domain) + "(?::\d+)?" + re.escape(path)
        else:
            regex += re.escape(text)
        namegen += text.replace('%','%%')

    has_default = 0

    # Iterate through the matches.
    for match in RULE_PARSER.finditer(rule):
        converter, options, name, default, text = match.groups()
        names.append(name)

        if default is not None:
            has_default += 1
            if not in_domain:
                regex += "(?:"

        # If we're still in the domain, use a special converter that doesn't
        # match the period.
        if converter == 'str':
            converter = 'string'
        if in_domain and (not converter or converter == 'string'):
            converter = 'domainpart'
        elif not in_domain and (not converter or converter == 'domainpart'):
            converter = 'string'

        if converter:
            converter = converter.strip()
            if not converter in CONVERTER_TYPES:
                raise ValueError("No such converter %r." % converter)

            # Make the converter.
            converter = CONVERTER_TYPES[converter](options, default)
            converters.append(converter)

            if hasattr(converter, 'regex'):
                regex += converter.regex
            else:
                regex += "([^/]+)"

            if hasattr(converter, 'namegen'):
                namegen += converter.namegen
            else:
                namegen += "%s"

        else:
            converters.append(None)
            regex += "([^/]+)"
            namegen += "%s"

        namegen += text.replace('%','%%')

        if in_domain and '/' in text:
            in_domain = False
            domain, _, path = text.partition('/')
            path = '/' + path
            regex += re.escape(domain) + "(?::\d+)?" + re.escape(path)

            if default:
                regex += ")?"

            while has_default > 0:
                regex = "(?:" + regex
                has_default -= 1
        else:
            regex += re.escape(text)
            if default and in_domain:
                regex += ")?"

    while has_default > 0:
        regex += ")?"
        has_default -= 1

    return "^" + regex + "$", tuple(converters), tuple(names), namegen, domain, path


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
    no status code is supplied. Usually, you'll want to call :func:`abort` in
    your code, rather than error(). Usage::

        return error(404)
        return error("Some message.", 404)
        return error("Blah blah blah.", 403, {'Some-Header': 'Fish'})
    """
    if request is None:
        request = Application.current_app.request

    if status is None:
        if isinstance(message, (int, long)):
            status, message = message, None
        else:
            status = 404

    status_text = None
    if isinstance(status, basestring):
        status, _, status_text = status.partition(' ')
        status = int(status)
    if not status_text:
        status_text = HTTP.get(status, "Unknown Error")

    if not headers:
        headers = {}

    if message is None:
        message = HTTP_MESSAGES.get(status, u"An unknown error has occurred.")
        values = request.__dict__.copy()
        values['uri'] = decode(urllib.unquote(values['uri']))
        message = message.format(**values)

    if status in HAIKUS:
        haiku = u'<div class="haiku">%s</div>' % HAIKUS[status]
    else:
        haiku = u""

    if not message.startswith(u"<"):
        message = u"<p>%s</p>" % message

    if debug is None:
        debug = Application.current_app and Application.current_app.debug

    if debug:
        debug = u"%0.3f ms" % (1000 * request.time)
    else:
        debug = u""

    result = ERROR_PAGE.safe_substitute(
        status=status,
        status_text=status_text,
        status_text_nbsp=status_text.replace(u" ", u"&nbsp;"),
        haiku=haiku,
        content=message,
        schema=request.protocol,
        host=request.host,
        debug=debug
    )

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
    Generates a URL to the request handler with the given name. The name is
    relative to that of the current request handler.
    """
    app = Application.current_app
    request = app.request

    if not name in app._name_table:
        if name.startswith("."):
            # Find the name in the first possible location, scanning up from
            # this module.
            module = request.route_name
            while module:
                module = module.rpartition('.')[0]
                nm = "%s.%s" % (module, name) if module else name
                if nm in app._name_table:
                    name = nm
                    break
            else:
                for n in app._name_table:
                    if n.endswith(name) or n == name[1:]:
                        # We've found it.
                        name = n
                        break

        elif not '.' in name:
            # Find it in this module.
            module = request.route_name.rpartition('.')[0]
            name = "%s.%s" % (module, name)

    if not name in app._name_table:
        raise KeyError("Cannot find request handler with name %r." % name)

    domain, path = app._name_table[name]
    rule_table = app._route_table[domain][path]
    names, namegen, converters = rule_table[-3:]

    data = []
    values = values.copy()

    for i in xrange(len(names)):
        name = names[i]
        if not name in values and converters[i].default is None:
            raise ValueError("Missing required value %r." % name)
        if not name in values:
            data.append(converters[i](converters[i].default))
        else:
            data.append(values[name])
            del values[name]

    out = namegen % tuple(data)
    out = urllib.quote(out)

    if '_external' in values:
        if values['_external'] and out.startswith('/'):
            out = request.host + out
        elif not values['_external'] and not out.startswith('/'):
            _, _, out = out.partition('/')
            out = '/' + out
        del values['_external']
    else:
        if out.lower().startswith(request.host.lower()):
            out = out[len(request.host):]

    if not out.startswith('/'):
        out = '%s://%s' % (request.protocol, out)

    # Build the query
    if values:
        out += '?%s' % urllib.urlencode(values)

    return out
